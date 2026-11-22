"""Sharded deployment: identities split across engine pairs behind one gateway and one key service.

Each identity always lands on the same shard (rendezvous hashing), its freezes and approvals go where its
state is, lists (alerts) are merged across shards, and each shard fails over on its own: fencing one shard
never refuses another shard's grants."""

import hashlib
import json
import os
import socket
import subprocess
import time

import pytest

from authority.crypto import b64e
from test_failover import BIN, Cluster

pytestmark = pytest.mark.skipif(not (BIN / "mastyf-gateway").exists(), reason="build rust/keyservice first")


def shard_of(identity, names=("s1", "s2")):
    return max(sorted(names), key=lambda n: int.from_bytes(hashlib.sha256(f"{n}|{identity}".encode()).digest()[:8], "big"))


def _sig(signer, msg):
    return b64e(signer.sign(msg.encode()))


def test_two_shards_route_merge_and_fence_independently(tmp_path):
    c = Cluster(tmp_path)
    old = os.environ.get("AUTHORITY_SHARD")
    try:
        c.start_ks()
        for name, sh in (("a", "s1"), ("b", "s2")):
            os.environ["AUTHORITY_SHARD"] = sh
            c.start_engine(name, "active", ["--peer", f"https://localhost:{c.pg}"])
        os.environ.pop("AUTHORITY_SHARD", None)
        c.procs["gw"] = subprocess.Popen(
            [str(BIN / "mastyf-gateway"), "--listen", f"127.0.0.1:{c.pg}", "--tls-cert", c.cert, "--tls-key", c.tkey,
             "--callers", str(c.tmp / "callers.json"), "--shard", f"s1=127.0.0.1:{c.pa}", "--shard", f"s2=127.0.0.1:{c.pb}",
             "--promote-key-file", str(c.tmp / "promote.key"), "--rate", "100000", "--burst", "100000"],
            stderr=open(c.tmp / "gw.log", "ab"))
        c._wait(lambda: socket.create_connection(("127.0.0.1", c.pg), timeout=0.2).close() or True)
        port = {"s1": c.pa, "s2": c.pb}
        assert c.health(c.pa)["shard"] == "s1" and c.health(c.pb)["shard"] == "s2"
        # freezes go to the shard that holds the identity
        victims = {}
        i = 0
        while len(victims) < 2:
            v = f"human:victim{i}"
            victims.setdefault(shard_of(v), v)
            i += 1
        for sh, v in victims.items():
            assert c.call("POST", "/v1/freeze", "k-admin-000000000000000000", {"identity": v, "reason": "drill"})[0] == 200
            assert v in c.call("GET", "/v1/alerts", "k-admin-000000000000000000", port=port[sh])[1]["frozen"]
            other = "s2" if sh == "s1" else "s1"
            assert v not in c.call("GET", "/v1/alerts", "k-admin-000000000000000000", port=port[other])[1]["frozen"]
        # the gateway merges lists from every shard
        merged = c.call("GET", "/v1/alerts", "k-admin-000000000000000000")[1]["frozen"]
        assert set(victims.values()) <= set(merged)
        # alice decides on her shard; her grant names it
        act, grant = c.grant_for_alice()
        payload = json.loads(__import__("authority.crypto", fromlist=["b64d"]).b64d(grant.split(".")[0]))
        mine = shard_of("human:alice")
        assert payload.get("sh") == mine
        other = "s2" if mine == "s1" else "s1"
        # fencing the OTHER shard (its failover) does not touch alice's grants
        s = c.signer
        fo = c.ks({"op": "floor_get", "shard": other})  # each shard keeps its own floor (its freeze above)
        assert fo["seq"] > 0
        f = c.ks({"op": "fence", "shard": other, "epoch": 7, "floor_seq": fo["seq"], "floor_hash": fo["hash"],
                  "sig": _sig(s, f"mastyf-fence@{other}|7|{fo['seq']}|{fo['hash']}")})
        assert f["ok"], f
        r = c.ks({"op": "release", "grant": grant, "action": {**act, "ts": time.time()}})
        assert r["ok"], r
        # fencing HER shard refuses her old grant
        cur = c.ks({"op": "floor_get", "shard": mine})
        ep = cur["min_engine_epoch"] + 5
        f = c.ks({"op": "fence", "shard": mine, "epoch": ep, "floor_seq": cur["seq"], "floor_hash": cur["hash"],
                  "sig": _sig(s, f"mastyf-fence@{mine}|{ep}|{cur['seq']}|{cur['hash']}")})
        assert f["ok"], f
        act2, grant2 = c.grant_for_alice()  # issued before her engine learns it was fenced
        r = c.ks({"op": "release", "grant": grant2, "action": {**act2, "ts": time.time()}})
        assert not r["ok"] and "superseded" in r["reason"], r
        # a shard's replication needs the shard named
        st, _ = c.call("POST", "/v1/replication", "k-replica-0000000000000000", {"after": 0})
        assert st == 400
    finally:
        if old is not None:
            os.environ["AUTHORITY_SHARD"] = old
        c.stop()
