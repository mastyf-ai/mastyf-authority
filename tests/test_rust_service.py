"""The Rust key service as a real service: Unix socket with owner-only permissions, many
clients, and a 2-of-3 authority quorum enforced in Rust."""

import json
import os
import socket
import stat
import subprocess
import tempfile
import time
from pathlib import Path

import pytest

from authority.actions import Action
from authority.crypto import Signer
from authority.grants import GrantIssuer
from authority.quorum import bundle

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")


@pytest.fixture
def svc():
    # AF_UNIX paths are limited to ~104 bytes on macOS, so use a short private directory
    d = Path(tempfile.mkdtemp(prefix="ks", dir="/tmp"))
    nodes = [Signer.generate() for _ in range(3)]
    keys = []
    for i, n in enumerate(nodes):
        p = d / f"n{i}.pem"
        p.write_text(n.public_pem())
        keys += ["--authority-key", str(p)]
    sock = d / "priv" / "ks.sock"
    proc = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"), *keys, "--threshold", "2",
                             "--socket", str(sock)], stderr=subprocess.PIPE, text=True)
    for _ in range(100):
        if sock.exists():
            break
        time.sleep(0.05)
    yield sock, nodes
    proc.terminate()
    proc.wait(timeout=5)
    for p in sorted(d.rglob("*"), reverse=True):
        p.unlink() if not p.is_dir() else p.rmdir()
    d.rmdir()


def ask(sock, req):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as s:
        s.connect(str(sock))
        f = s.makefile("rw")
        f.write(json.dumps(req) + "\n")
        f.flush()
        return json.loads(f.readline())


def test_socket_is_owner_only(svc):
    sock, _ = svc
    assert stat.S_IMODE(os.stat(sock).st_mode) == 0o600
    assert stat.S_IMODE(os.stat(sock.parent).st_mode) == 0o700


def test_quorum_enforced_in_rust(svc):
    sock, nodes = svc
    a = Action("human:alice", "data.read", "db://crm/customers/query", 10, ts=time.time())
    iss = [GrantIssuer(n, 60) for n in nodes]
    one = ask(sock, {"op": "release", "grant": iss[0].issue(a, "x"), "action": a.to_dict()})
    assert not one["ok"] and "quorum" in one["reason"]
    same_node_twice = bundle([iss[1].issue(a, "x"), iss[1].issue(a, "y")])
    assert not ask(sock, {"op": "release", "grant": same_node_twice, "action": a.to_dict()})["ok"]
    two = bundle([iss[0].issue(a, "x"), iss[2].issue(a, "x")])
    assert ask(sock, {"op": "release", "grant": two, "action": a.to_dict()})["ok"]


def test_many_clients_share_one_budget(svc):
    sock, nodes = svc
    iss = [GrantIssuer(n, 60) for n in nodes]
    ok = 0
    for _ in range(12):  # alice's budget is 5000/day; 12 x 1000 must stop at 5
        a = Action("human:alice", "data.read", "db://crm/customers/query", 1000, ts=time.time())
        g = bundle([iss[0].issue(a, "x"), iss[1].issue(a, "x")])
        ok += ask(sock, {"op": "release", "grant": g, "action": a.to_dict()})["ok"]
    assert ok == 5
