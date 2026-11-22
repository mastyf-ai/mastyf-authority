"""Rust front door (mastyf-gateway) in front of the Python decision engine."""

import hashlib
import json
import socket
import ssl
import subprocess
import threading
import time
from pathlib import Path

import pytest

from authority.audit import AuditLog
from authority.crypto import Signer
from authority.engine import Authority
from authority.grants import GrantIssuer, GrantVerifier
from authority.policy import Policy
from authority.server import BoundedServer, make_handler
from test_rust_ha import _certs, _free_port

ROOT = Path(__file__).resolve().parents[1]
GW = ROOT / "rust/keyservice/target/release/mastyf-gateway"
pytestmark = pytest.mark.skipif(not GW.exists(), reason="build rust/keyservice first")
KEYS = {"k-alice": "human:alice", "k-bob": "human:bob"}


@pytest.fixture
def stack(tmp_path):
    pol = Policy.load(ROOT / "policies/default.json")
    signer = Signer.generate()
    auth = Authority(pol, GrantIssuer(signer, 60), AuditLog(tmp_path / "a.log", signer))
    callers = {hashlib.sha256(k.encode()).hexdigest(): v for k, v in KEYS.items()}
    (tmp_path / "callers.json").write_text(json.dumps(callers))
    httpd = BoundedServer(("127.0.0.1", 0), make_handler(auth, callers, GrantVerifier(signer.public_key)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    tls = _certs(tmp_path)
    port = _free_port()
    gw = subprocess.Popen([str(GW), "--listen", f"127.0.0.1:{port}", "--tls-cert", tls[1], "--tls-key", tls[3],
                           "--callers", str(tmp_path / "callers.json"), "--upstream", f"127.0.0.1:{httpd.server_address[1]}",
                           "--rate", "20", "--burst", "25"], stderr=subprocess.PIPE, text=True)
    ctx = ssl.create_default_context(cafile=tls[5])
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)

    def raw(data: bytes) -> bytes:
        # 1 s: an incomplete request is (correctly) held open by the gateway until more bytes arrive or its
        # own 15 s client timeout; the test only needs to see that it never answers with anything but HTTP
        s = ctx.wrap_socket(socket.create_connection(("127.0.0.1", port), timeout=1), server_hostname="localhost")
        s.sendall(data)
        out = b""
        try:
            while True:
                c = s.recv(65536)
                if not c:
                    break
                out += c
                if b"\r\n\r\n" in out:
                    head, _, body = out.partition(b"\r\n\r\n")
                    n = [int(x.split(b":")[1]) for x in head.split(b"\r\n") if x.lower().startswith(b"content-length")]
                    if n and len(body) >= n[0]:
                        break
        except (TimeoutError, ssl.SSLError):
            pass
        s.close()
        return out

    def req(method, path, body=None, key="k-alice"):
        b = json.dumps(body).encode() if body is not None else b""
        h = f"{method} {path} HTTP/1.1\r\nHost: x\r\nConnection: close\r\nContent-Length: {len(b)}\r\n"
        if key:
            h += f"Authorization: Bearer {key}\r\n"
        out = raw(h.encode() + b"\r\n" + b)
        head, _, rest = out.partition(b"\r\n\r\n")
        status = int(head.split(b" ")[1])
        return status, head.decode(), (json.loads(rest) if rest.strip().startswith(b"{") else rest)
    yield req, raw, httpd, port, ctx
    gw.kill()
    gw.wait(timeout=5)
    httpd.shutdown()


def test_normal_traffic_passes_and_identity_is_enforced(stack):
    req, raw, *_ = stack
    st, head, body = req("GET", "/enroll", key=None)
    assert st == 200 and "script-src 'self'" in head and "Strict-Transport-Security" in head
    st, _, d = req("POST", "/v1/decide", {"action": {"identity": "human:alice", "action_type": "data.read",
                                                    "resource": "db://crm/customers/query", "count": 5}})
    assert st == 200 and d["verdict"] in ("ALLOW", "ESCALATE", "DENY")
    st, _, d = req("POST", "/v1/decide", {"action": {"identity": "human:bob", "action_type": "data.read",
                                                    "resource": "db://crm/customers/query", "count": 5}})
    assert st == 403 and d["verdict"] == "DENY"  # alice's key cannot act as bob


def test_hostile_requests_are_refused_before_the_engine(stack):
    req, raw, *_ = stack
    assert req("GET", "/v1/pending", key="wrong")[0] == 401
    assert req("GET", "/etc/passwd", key="k-alice")[0] == 404
    assert req("GET", "/v1/devices?x=1")[0] == 400
    assert req("PUT", "/v1/decide", {})[0] == 405
    st, _, d = req("POST", "/v1/decide", ["not", "an", "object"])
    assert st == 400 and d["verdict"] == "DENY"
    smug = raw(b"POST /v1/decide HTTP/1.1\r\nHost: x\r\nTransfer-Encoding: chunked\r\nAuthorization: Bearer k-alice\r\n\r\n0\r\n\r\n")
    assert smug.startswith(b"HTTP/1.1 411")
    dup = raw(b"POST /v1/decide HTTP/1.1\r\nHost: x\r\nContent-Length: 2\r\nContent-Length: 40\r\n\r\n{}")
    assert dup.startswith(b"HTTP/1.1 400")
    big = raw(b"GET /healthz HTTP/1.1\r\nHost: x\r\nX-Junk: " + b"a" * 20000 + b"\r\n\r\n")
    assert big.startswith(b"HTTP/1.1 431")
    huge = raw(b"POST /v1/decide HTTP/1.1\r\nHost: x\r\nContent-Length: 99999999\r\n\r\n")
    assert huge.startswith(b"HTTP/1.1 413")
    assert raw(b"GET /healthz HTTP/1.0\r\n\r\n").startswith(b"HTTP/1.1 505")


def test_rate_limit_and_fail_closed(stack):
    req, raw, httpd, *_ = stack
    codes = [req("GET", "/v1/devices", key="k-bob")[0] for _ in range(40)]
    assert 429 in codes and codes[0] != 429
    httpd.shutdown()
    httpd.server_close()  # engine down
    st, _, d = req("POST", "/v1/decide", {"action": {"identity": "human:alice", "action_type": "data.read",
                                                    "resource": "db://crm/customers/query", "count": 5}})
    assert st == 503 and d["verdict"] == "DENY"


def test_garbage_never_crashes_the_gateway(stack):
    import random
    req, raw, *_ = stack
    rng = random.Random(5)
    base = [b"GET /healthz HTTP/1.1\r\nHost: x\r\n\r\n",
            b"POST /v1/decide HTTP/1.1\r\nHost: x\r\nAuthorization: Bearer k-alice\r\nContent-Length: 30\r\n\r\n{\"action\":{\"identity\":\"x\"}}xx"]
    for _ in range(300):
        b = bytearray(rng.choice(base))
        for _ in range(rng.randint(1, 12)):
            op = rng.random()
            i = rng.randrange(len(b))
            if op < 0.4:
                b[i] = rng.randrange(256)
            elif op < 0.7:
                b[i:i] = bytes(rng.randrange(256) for _ in range(rng.randint(1, 40)))
            else:
                del b[i:i + rng.randint(1, 10)]
        if rng.random() < 0.2:
            b = bytearray(rng.randbytes(rng.randint(1, 3000)))
        out = raw(bytes(b))
        assert out == b"" or out.startswith(b"HTTP/1.1 ")
    assert req("GET", "/healthz", key=None)[0] == 200  # still up
