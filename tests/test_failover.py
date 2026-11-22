"""Engine failover end to end: active + hot standby behind one gateway, key service fenced on promotion.

  kill -9 the active engine  ->  gateway promotes the standby within seconds, decisions continue, state
  (freezes, approvals) carried over, grants from the old engine refused by the key service, and the old
  engine, if it comes back, sees the newer peer and stops deciding.
"""

import hashlib
import http.client
import json
import os
import shutil
import signal
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

import pytest

from authority.crypto import Signer
from authority.engine import sign_approval
from test_rust_ha import _certs, _free_port

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release"
pytestmark = pytest.mark.skipif(not (BIN / "mastyf-gateway").exists(), reason="build rust/keyservice first")
PY = sys.executable
KEYS = {"k-alice-000000000000000000": "human:alice", "k-dana-0000000000000000000": "human:dana",
        "k-admin-000000000000000000": "admin", "k-replica-0000000000000000": "replica"}


class Cluster:
    def __init__(self, tmp: Path):
        self.tmp = tmp
        self.sock_dir = Path(tempfile.mkdtemp(prefix="fo", dir="/tmp"))
        self.sock = self.sock_dir / "ks.sock"
        self.procs = {}
        signer = Signer.generate()
        for d in ("a", "b"):
            (tmp / d).mkdir()
        key_a = tmp / "a/signing_key.pem"
        Signer.load_or_create(key_a)  # creates; both engines must hold the same key
        shutil.copy(key_a, tmp / "b/signing_key.pem")
        os.chmod(tmp / "b/signing_key.pem", 0o600)
        self.signer = Signer.load_or_create(key_a)
        (tmp / "authority.pub.pem").write_text(self.signer.public_pem())
        self.dana = Signer.generate()
        (tmp / "approvers.json").write_text(json.dumps({"human:dana": self.dana.public_pem()}))
        (tmp / "callers.json").write_text(json.dumps({hashlib.sha256(k.encode()).hexdigest(): w for k, w in KEYS.items()}))
        (tmp / "promote.key").write_text("k-replica-0000000000000000")
        (tmp / "ks").mkdir()
        tls = _certs(tmp)
        self.cert, self.tkey, self.ca = tls[1], tls[3], tls[5]
        self.pa, self.pb, self.pg = _free_port(), _free_port(), _free_port()
        del signer

    def start_ks(self):
        self.procs["ks"] = subprocess.Popen(
            [str(BIN / "mastyf-keyservice"), "--policy", str(ROOT / "policies/default.json"),
             "--authority-key", str(self.tmp / "authority.pub.pem"), "--state-dir", str(self.tmp / "ks"),
             "--init-kek", "--socket", str(self.sock)], stderr=subprocess.DEVNULL)
        self._wait(lambda: self.ks({"op": "health"}).get("ok"))

    def start_engine(self, name, role, extra=()):
        port = self.pa if name == "a" else self.pb
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUTHORITY_CALLERS": str(self.tmp / "callers.json"),
               "AUTHORITY_APPROVER_KEYS": str(self.tmp / "approvers.json"), "AUTHORITY_KEYSERVICE": f"unix:{self.sock}",
               "AUTHORITY_REPLICA_KEY": "k-replica-0000000000000000", "AUTHORITY_PEER_CA": self.ca}
        cmd = [PY, "-c", "import sys;from authority.cli import main;main(sys.argv[1:])", "serve",
               "--policy", str(ROOT / "policies/default.json"), "--state", str(self.tmp / name), "--port", str(port),
               "--model", str(self.tmp / "no-model.json"), "--role", role, *extra]
        if role == "standby" and "--follow" not in extra:
            cmd += ["--follow", f"https://localhost:{self.pg}"]
        self.procs[name] = subprocess.Popen(cmd, env=env, stdout=open(self.tmp / f"{name}.log", "ab"),
                                            stderr=subprocess.STDOUT)
        try:
            self._wait(lambda: socket.create_connection(("127.0.0.1", port), timeout=0.2).close() or True, limit=40)
        except AssertionError:
            pass  # an engine that exits on purpose (diverged) is handled by the caller

    def start_gateway(self):
        self.procs["gw"] = subprocess.Popen(
            [str(BIN / "mastyf-gateway"), "--listen", f"127.0.0.1:{self.pg}", "--tls-cert", self.cert, "--tls-key", self.tkey,
             "--callers", str(self.tmp / "callers.json"), "--upstream", f"127.0.0.1:{self.pa}",
             "--upstream", f"127.0.0.1:{self.pb}", "--promote-key-file", str(self.tmp / "promote.key"),
             "--failover-after", "2", "--rate", "100000", "--burst", "100000"],
            stderr=open(self.tmp / "gw.log", "ab"))
        self._wait(lambda: socket.create_connection(("127.0.0.1", self.pg), timeout=0.2).close() or True)

    def _wait(self, ok, limit=60):
        end = time.time() + limit
        while time.time() < end:
            try:
                if ok():
                    return
            except (OSError, ValueError):
                pass
            time.sleep(0.1)
        raise AssertionError("not ready")

    def ks(self, req):
        with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
            s.settimeout(5)
            s.connect(str(self.sock))
            f = s.makefile("rw")
            f.write(json.dumps(req) + "\n")
            f.flush()
            return json.loads(f.readline())

    def call(self, method, path, key, body=None, port=None):
        if port is None:
            c = http.client.HTTPSConnection("localhost", self.pg, context=ssl.create_default_context(cafile=self.ca), timeout=15)
        else:
            c = http.client.HTTPConnection("127.0.0.1", port, timeout=15)
        c.request(method, path, json.dumps(body) if body is not None else None,
                  {"Authorization": f"Bearer {key}", "Content-Type": "application/json"} if key else {})
        r = c.getresponse()
        out = (r.status, json.loads(r.read() or b"{}"))
        c.close()
        return out

    def health(self, port):
        return self.call("GET", "/healthz", None, port=port)[1]

    def grant_for_alice(self):
        """A grant for an ordinary read (directly, or after Dana approves if it escalates)."""
        act = {"identity": "human:alice", "action_type": "data.read", "resource": "db://crm/customers/7", "count": 3}
        st, d = self.call("POST", "/v1/decide", "k-alice-000000000000000000", {"action": act})
        assert st == 200, d
        if d["verdict"] == "ALLOW":
            return act, d["grant"]
        assert d["verdict"] == "ESCALATE", d
        sig = sign_approval(self.dana, d["fingerprint"], "human:alice", "ticket OPS-77")
        st, ap = self.call("POST", "/v1/approve", "k-dana-0000000000000000000",
                           {"fingerprint": d["fingerprint"], "requester": "human:alice", "approver": "human:dana",
                            "reason": "ticket OPS-77", "signature": sig})
        assert st == 200, ap
        st, d2 = self.call("POST", "/v1/decide", "k-alice-000000000000000000", {"action": act, "approval_id": ap["approval_id"]})
        assert d2["verdict"] == "ALLOW" and d2.get("grant"), d2
        return act, d2["grant"]

    def stop(self):
        for p in self.procs.values():
            if p.poll() is None:
                p.send_signal(signal.SIGCONT)
                p.kill()
                p.wait()
        shutil.rmtree(self.sock_dir, ignore_errors=True)


def test_failover_promotes_standby_and_fences_old_grants(tmp_path):
    c = Cluster(tmp_path)
    try:
        c.start_ks()
        c.start_engine("a", "active")
        c.start_gateway()
        c.start_engine("b", "standby")
        # traffic and state on the active engine
        for _ in range(20):
            assert c.call("POST", "/v1/decide", "k-alice-000000000000000000",
                          {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "sso://corp"}})[0] == 200
        assert c.call("POST", "/v1/freeze", "k-admin-000000000000000000", {"identity": "human:bob", "reason": "drill"})[0] == 200
        old_act, old_grant = c.grant_for_alice()
        # the standby catches up to the same position
        c._wait(lambda: c.health(c.pb)["seq"] == c.health(c.pa)["seq"])
        assert c.health(c.pb)["role"] == "standby"
        # a standby never decides
        assert c.call("POST", "/v1/decide", "k-alice-000000000000000000",
                      {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "x"}}, port=c.pb)[0] == 503

        c.procs["a"].kill()
        c.procs["a"].wait()
        t0 = time.time()
        c._wait(lambda: c.health(c.pb)["role"] == "active", limit=30)
        took = time.time() - t0
        assert took < 15, took
        assert c.health(c.pb)["epoch"] == 1
        # decisions continue through the same gateway, with the replicated state
        st, d = c.call("POST", "/v1/decide", "k-alice-000000000000000000",
                       {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "sso://corp"}})
        assert st == 200 and d["verdict"] == "ALLOW", d
        assert c.call("GET", "/v1/alerts", "k-admin-000000000000000000")[1]["frozen"].get("human:bob")
        # the old engine's grant is refused by the key service; a new one works
        r = c.ks({"op": "release", "grant": old_grant, "action": {**old_act, "ts": time.time()}})
        assert not r["ok"] and "superseded" in r["reason"], r
        act, grant = c.grant_for_alice()
        r = c.ks({"op": "release", "grant": grant, "action": {**act, "ts": time.time()}})
        assert r["ok"], r
        # the old engine comes back as active (an operator mistake): it sees the newer peer and stops deciding
        c.start_engine("a", "active", ["--peer", f"https://localhost:{c.pg}"])
        c._wait(lambda: c.health(c.pa)["role"] == "fenced", limit=20)
        assert c.call("POST", "/v1/decide", "k-alice-000000000000000000",
                      {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "x"}}, port=c.pa)[0] == 503
        assert c.call("POST", "/v1/decide", "k-alice-000000000000000000",
                      {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "sso://corp"}})[0] == 200
        print(f"failover took {took:.1f} s")
    finally:
        c.stop()


def test_promotion_refused_without_a_reachable_key_service(tmp_path):
    c = Cluster(tmp_path)
    try:
        c.start_ks()
        c.start_engine("a", "active")
        c.start_gateway()
        c.start_engine("b", "standby")
        c._wait(lambda: c.health(c.pb)["seq"] == c.health(c.pa)["seq"])
        c.procs["ks"].kill()
        c.procs["ks"].wait()
        st, r = c.call("POST", "/v1/promote", "k-replica-0000000000000000", {"reason": "test"}, port=c.pb)
        assert st == 409 and "not fenced" in r["error"], r
        assert c.health(c.pb)["role"] == "standby"
    finally:
        c.stop()


def test_critical_records_reach_the_standby_before_the_reply(tmp_path):
    """Semi-synchronous replication: by the time a freeze is acknowledged the standby already has it, so a
    failover right after cannot lose it. The active engine is paused the moment the reply arrives."""
    c = Cluster(tmp_path)
    try:
        c.start_ks()
        c.start_engine("a", "active")
        c.start_gateway()
        c.start_engine("b", "standby")
        c._wait(lambda: c.health(c.pb)["seq"] == c.health(c.pa)["seq"])
        for i in range(5):
            assert c.call("POST", "/v1/freeze", "k-admin-000000000000000000",
                          {"identity": "human:bob", "reason": f"drill {i}"})[0] == 200
            c.procs["a"].send_signal(signal.SIGSTOP)  # from here on nothing more can reach the standby
            try:
                standby_has = c.health(c.pb)["seq"]
            finally:
                c.procs["a"].send_signal(signal.SIGCONT)
            freeze_seq = c.health(c.pa)["seq"]  # nothing else writes in this test: the freeze is the newest
            assert standby_has >= freeze_seq, (standby_has, freeze_seq)
    finally:
        c.stop()


def test_old_engine_rejoins_automatically_as_standby(tmp_path):
    """--role auto: after a failover the old engine, restarted by its supervisor, joins as a standby; if its
    log holds records the new active engine never got, they are moved aside and it resyncs from scratch."""
    c = Cluster(tmp_path)
    try:
        c.start_ks()
        c.start_engine("a", "active")
        c.start_gateway()
        c.start_engine("b", "standby")
        c._wait(lambda: c.health(c.pb)["seq"] == c.health(c.pa)["seq"])
        c.procs["b"].send_signal(signal.SIGSTOP)  # cut the standby off, then A writes records B never sees
        for _ in range(5):
            c.call("POST", "/v1/decide", "k-alice-000000000000000000",
                   {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "sso://corp"}}, port=c.pa)
        c.procs["a"].kill()
        c.procs["a"].wait()
        c.procs["b"].send_signal(signal.SIGCONT)
        c._wait(lambda: c.health(c.pb)["role"] == "active", limit=30)
        # A comes back under a supervisor with --role auto: it must not take over, and must resync
        for _ in range(3):  # the first start exits after moving the diverged state aside; restart like systemd would
            c.start_engine("a", "auto", ["--follow", f"https://localhost:{c.pg}", "--peer", f"https://localhost:{c.pg}"])
            try:
                c._wait(lambda: c.health(c.pa)["seq"] == c.health(c.pb)["seq"], limit=20)
                break
            except (AssertionError, OSError):
                c.procs["a"].wait(timeout=30)
        assert c.health(c.pa)["role"] == "standby"
        assert any(p.name.startswith("diverged-") for p in (tmp_path / "a").iterdir())
    finally:
        c.stop()
