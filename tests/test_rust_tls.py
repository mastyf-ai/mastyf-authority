"""Mutual TLS transport for the Rust key service."""

import datetime as dt
import json
import socket
import ssl
import subprocess
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import NameOID

from authority.crypto import Signer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")


def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def make_ca(cn="test-ca"):
    k = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
         .not_valid_after(now + dt.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
         .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True, content_commitment=False,
                                      key_encipherment=False, data_encipherment=False, key_agreement=False,
                                      encipher_only=False, decipher_only=False), critical=True)
         .sign(k, hashes.SHA256()))
    return k, c


def issue(ca_k, ca_c, cn, server=False):
    k = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    b = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(ca_c.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
         .not_valid_after(now + dt.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([x509.oid.ExtendedKeyUsageOID.SERVER_AUTH if server
                                               else x509.oid.ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False))
    if server:
        b = b.add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
    return k, b.sign(ca_k, hashes.SHA256())


def write(p, k=None, c=None):
    data = b""
    if c is not None:
        data += c.public_bytes(serialization.Encoding.PEM)
    if k is not None:
        data += k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())
    p.write_bytes(data)
    return str(p)


@pytest.fixture
def server(tmp_path):
    ca_k, ca_c = make_ca()
    sk, sc = issue(ca_k, ca_c, "keyservice", server=True)
    ck, cc = issue(ca_k, ca_c, "authority-node-1")
    (tmp_path / "auth.pem").write_text(Signer.generate().public_pem())
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    p = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key", str(tmp_path / "auth.pem"),
                          "--tls-listen", f"127.0.0.1:{port}", "--tls-cert", write(tmp_path / "s.crt", c=sc),
                          "--tls-key", write(tmp_path / "s.key", k=sk), "--tls-client-ca", write(tmp_path / "ca.crt", c=ca_c)],
                         stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.05)
    yield port, tmp_path, (ca_k, ca_c), (write(tmp_path / "c.crt", c=cc), write(tmp_path / "c.key", k=ck))
    p.terminate()
    p.wait(timeout=5)


def ctx(ca_file, client=None, tls12=False):
    c = ssl.create_default_context(cafile=ca_file)
    if tls12:
        c.maximum_version = ssl.TLSVersion.TLSv1_2
    if client:
        c.load_cert_chain(*client)
    return c


def ask(port, c, req):
    with socket.create_connection(("127.0.0.1", port), timeout=5) as raw:
        with c.wrap_socket(raw, server_hostname="localhost") as s:
            s.sendall((json.dumps(req) + "\n").encode())
            data = b""
            while not data.endswith(b"\n"):
                chunk = s.recv(65536)
                if not chunk:
                    break
                data += chunk
            return json.loads(data)


def test_valid_client_certificate_gets_answers(server):
    port, tmp, _, client = server
    r = ask(port, ctx(str(tmp / "ca.crt"), client), {"op": "check_script", "candidate": "var a = 1;"})
    assert r["verdict"] == "review"


def test_no_certificate_or_foreign_ca_is_refused(server):
    port, tmp, _, _ = server
    with pytest.raises((ssl.SSLError, ConnectionError, OSError, json.JSONDecodeError)):
        ask(port, ctx(str(tmp / "ca.crt")), {"op": "check_script", "candidate": "x"})
    other_k, other_c = make_ca("other-ca")
    k, c = issue(other_k, other_c, "intruder")
    foreign = (write(tmp / "f.crt", c=c), write(tmp / "f.key", k=k))
    with pytest.raises((ssl.SSLError, ConnectionError, OSError, json.JSONDecodeError)):
        ask(port, ctx(str(tmp / "ca.crt"), foreign), {"op": "check_script", "candidate": "x"})


def test_tls12_refused(server):
    port, tmp, _, client = server
    with pytest.raises((ssl.SSLError, ConnectionError, OSError)):
        ask(port, ctx(str(tmp / "ca.crt"), client, tls12=True), {"op": "check_script", "candidate": "x"})
