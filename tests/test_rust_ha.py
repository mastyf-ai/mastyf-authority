"""High availability of the Rust key service: primary + standby + witness.

Failover must lose nothing (budgets, spent grants, record keys), there must never be two primaries,
and a standby that may be missing writes must never take over on its own."""

import datetime as dt
import json
import os
import signal
import socket
import subprocess
import tempfile
import time
from pathlib import Path

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

from authority.actions import Action
from authority.crypto import Signer
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")


def _free_port():
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def _certs(d: Path):
    def name(cn):
        return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])
    now = dt.datetime.now(dt.timezone.utc)
    ca_k = ec.generate_private_key(ec.SECP256R1())
    ca = (x509.CertificateBuilder().subject_name(name("ha-ca")).issuer_name(name("ha-ca")).public_key(ca_k.public_key())
          .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
          .not_valid_after(now + dt.timedelta(days=1))
          .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True).sign(ca_k, hashes.SHA256()))
    k = ec.generate_private_key(ec.SECP256R1())
    c = (x509.CertificateBuilder().subject_name(name("ha-node")).issuer_name(ca.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=1))
         .not_valid_after(now + dt.timedelta(days=1))
         .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), critical=False)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
         .sign(ca_k, hashes.SHA256()))
    (d / "ca.pem").write_bytes(ca.public_bytes(serialization.Encoding.PEM))
    (d / "node.pem").write_bytes(c.public_bytes(serialization.Encoding.PEM))
    (d / "node.key").write_bytes(k.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                                                 serialization.NoEncryption()))
    return ["--ha-cert", str(d / "node.pem"), "--ha-key", str(d / "node.key"), "--ha-ca", str(d / "ca.pem")]


class Cluster:
    def __init__(self, tmp: Path, witnesses: int = 1):
        self.tmp = tmp
        self.wnames = ["w"] if witnesses == 1 else [f"w{i}" for i in range(witnesses)]
        self.auth = Signer.generate()
        (tmp / "auth.pem").write_text(self.auth.public_pem())
        kek = tmp / "kek.b64"  # same KEK on both nodes (in production: the same KMS key)
        kek.write_text("QUJDREVGR0hJSktMTU5PUFFSU1RVVldYWVphYmNkZWY=")
        os.chmod(kek, 0o600)
        self.tls = _certs(tmp)
        self.ports = {n: _free_port() for n in [*self.wnames, "a", "b"]}
        self.procs = {}
        self.sockdir = Path(tempfile.mkdtemp(prefix="ha"))  # Unix socket paths must be short

    def start_witness(self, only=None):
        for w in ([only] if only else self.wnames):
            self.procs[w] = subprocess.Popen(
                [str(BIN), "witness", "--listen", f"localhost:{self.ports[w]}", "--state", str(self.tmp / f"{w}.json"), *self.tls],
                stderr=open(self.tmp / f"{w}.log", "a"))

    def start(self, n):
        other = "b" if n == "a" else "a"
        sock = self.sockdir / f"sock-{n}" / "ks.sock"
        if sock.exists():
            sock.unlink()
        self.procs[n] = subprocess.Popen(
            [str(BIN), "--policy", str(getattr(self, "policy", ROOT / "policies/default.json")), "--authority-key", str(self.tmp / "auth.pem"),
             "--fake-clock", "--state-dir", str(self.tmp / f"state-{n}"), "--kek-file", str(self.tmp / "kek.b64"),
             "--socket", str(sock), "--ha-node", n, "--ha-listen", f"localhost:{self.ports[n]}",
             "--ha-peer", f"localhost:{self.ports[other]}", "--ha-peer-node", other,
             *[x for w in self.wnames for x in ("--ha-witness", f"localhost:{self.ports[w]}")], *self.tls],
            stderr=open(self.tmp / f"{n}.log", "a"))

    def kill(self, n):
        self.procs[n].send_signal(signal.SIGKILL)
        self.procs[n].wait(timeout=5)

    def log(self, n):
        return (self.tmp / f"{n}.log").read_text()

    def ask(self, n, req, timeout=5.0):
        s = socket.socket(socket.AF_UNIX)
        s.settimeout(timeout)
        s.connect(str(self.sockdir / f"sock-{n}" / "ks.sock"))
        s.sendall((json.dumps(req) + "\n").encode())
        buf = b""
        while not buf.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            buf += chunk
        s.close()
        return json.loads(buf)

    def wait_primary(self, candidates, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            for n in candidates:
                if "promoted to primary" in self.log(n) and (self.sockdir / f"sock-{n}" / "ks.sock").exists():
                    try:
                        if self.ask(n, {"op": "health"})["ok"]:
                            return n
                    except OSError:
                        pass
            time.sleep(0.2)
        raise AssertionError("no primary: " + " | ".join(self.log(n)[-400:] for n in candidates))

    def wait_log(self, n, text, count=1, timeout=20):
        end = time.time() + timeout
        while time.time() < end:
            if self.log(n).count(text) >= count:
                return
            time.sleep(0.2)
        raise AssertionError(f"{n}: waited for {text!r}: {self.log(n)[-600:]}")

    def stop(self):
        for p in self.procs.values():
            if p.poll() is None:
                p.kill()
                p.wait(timeout=5)


@pytest.fixture
def cluster3(tmp_path):
    c = Cluster(tmp_path, witnesses=3)
    yield c
    c.stop()


@pytest.fixture
def cluster(tmp_path):
    c = Cluster(tmp_path)
    yield c
    c.stop()


def read(n, ids=None, now=None):
    return Action("human:alice", "data.read", "db://crm/customers/query", n, ts=now or time.time(),
                  metadata={"record_ids": ids} if ids else {})


def test_failover_loses_nothing_and_old_primary_rejoins_as_standby(cluster):
    c = cluster
    now = time.time()
    iss = GrantIssuer(c.auth, 600, now=lambda: now)
    c.start_witness()
    c.start("a")
    c.start("b")
    p = c.wait_primary(["a", "b"])
    s = "b" if p == "a" else "a"
    c.wait_log(p, "HA standby in sync")
    assert c.ask(p, {"op": "new_record_key", "record_id": "c1", "class": "crm.customer"})["ok"]
    used = None
    for i in range(5):  # alice: 5,000 records per 24 h
        a = read(1000, now=now)
        g = iss.issue(a, "x")
        assert c.ask(p, {"op": "release", "grant": g, "action": a.to_dict(), "now": now + i})["ok"]
        used = (g, a)
    # the standby serves nobody
    assert not (c.sockdir / f"sock-{s}" / "ks.sock").exists()

    c.kill(p)  # primary host dies
    t0 = time.time()
    p2 = c.wait_primary([s])
    failover = time.time() - t0
    assert failover < 12, failover
    a = read(1000, now=now)
    r = c.ask(p2, {"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + 10})
    assert not r["ok"] and r["reason"].startswith("budget"), r  # budget carried over
    r = c.ask(p2, {"op": "release", "grant": used[0], "action": used[1].to_dict(), "now": now + 11})
    assert not r["ok"] and "already used" in r["reason"], r  # spent grant stays spent
    later = GrantIssuer(c.auth, 600, now=lambda: now + 86400 * 2)
    a = read(1, ids=["c1"], now=now + 86400 * 2)
    r = c.ask(p2, {"op": "release", "grant": later.issue(a, "x"), "action": a.to_dict(), "now": now + 86400 * 2})
    assert r["ok"] and "c1" in r["keys"], r  # record key created on the old primary is usable

    c.start(p)  # old primary comes back: it must become the standby, not a second primary
    c.wait_log(p2, "HA standby in sync", count=2 if p2 == p else 1)
    time.sleep(2)
    assert "promoted to primary" not in c.log(p).split("standing by")[-1]
    assert not (c.sockdir / f"sock-{p}" / "ks.sock").exists()


def test_degraded_primary_blocks_unsafe_takeover_and_fails_closed_without_witness(cluster):
    c = cluster
    now = time.time()
    iss = GrantIssuer(c.auth, 600, now=lambda: now)
    c.start_witness()
    c.start("a")
    c.start("b")
    p = c.wait_primary(["a", "b"])
    s = "b" if p == "a" else "a"
    c.wait_log(p, "HA standby in sync")

    c.kill(s)  # standby dies: primary continues only after the witness records it
    a = read(100, now=now)
    assert c.ask(p, {"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now})["ok"]
    assert "asking witnesses to continue without it" in c.log(p) or "stopped answering" in c.log(p)

    # primary dies while running without a synced standby: the standby's copy may be missing writes,
    # so it must NOT take over on its own
    c.kill(p)
    c.start(s)
    time.sleep(9)
    assert "promoted to primary" not in c.log(s).split("standing by")[-1]
    assert "manual recovery" in c.log(s)

    # bring the old primary back: it has everything, holds the lease, resyncs the standby
    c.start(p)
    c.wait_log(p, "promoted to primary", count=2)
    c.wait_log(p, "HA standby in sync", count=2)

    # witness and standby both gone: nothing can be confirmed, so the primary refuses (fails closed)
    c.kill("w")
    c.kill(s)
    a = read(100, now=now)
    r = c.ask(p, {"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + 1}, timeout=15)
    assert not r["ok"], r


def test_three_witnesses_survive_losing_one_and_never_split(cluster3):
    c = cluster3
    now = time.time()
    iss = GrantIssuer(c.auth, 600, now=lambda: now)
    c.start_witness()
    c.start("a")
    c.start("b")
    p = c.wait_primary(["a", "b"])
    s = "b" if p == "a" else "a"
    c.wait_log(p, "HA standby in sync")
    for i in range(5):
        a = read(1000, now=now)
        assert c.ask(p, {"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + i})["ok"]
    c.kill("w0")  # one referee host lost: nothing changes
    a = read(10, ids=None, now=now)
    c.kill(p)  # then the primary too: the standby still gets 2 of 3 and takes over
    p2 = c.wait_primary([s])
    r = c.ask(p2, {"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now + 10})
    assert not r["ok"] and r["reason"].startswith("budget"), r  # nothing lost
    c.start(p)
    c.wait_log(p2, "HA standby in sync")
    c.start_witness("w0")
    # two referees and the standby gone: no majority, no standby ack: the primary refuses
    c.kill("w1")
    c.kill("w2")
    c.kill(p)
    b = Action("svc:backup", "data.read", "fs://prod/data", 5, ts=now)
    r = c.ask(p2, {"op": "release", "grant": iss.issue(b, "x"), "action": b.to_dict(), "now": now + 20}, timeout=20)
    assert not r["ok"], r
