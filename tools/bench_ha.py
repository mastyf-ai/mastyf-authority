"""Durable key releases per second: single node vs primary + synchronous standby.

  PYTHONPATH=src:tests python tools/bench_ha.py [clients] [seconds]
"""

from __future__ import annotations

import json
import socket
import sys
import tempfile
import threading
import time
from pathlib import Path

from authority.actions import Action
from authority.grants import GrantIssuer
from test_rust_ha import Cluster


def bench(c: Cluster, node: str, clients: int, seconds: float) -> float:
    now = time.time()
    iss = GrantIssuer(c.auth, 600, now=lambda: now)
    done = [0]
    lock = threading.Lock()
    stop = time.time() + seconds

    def worker(i):
        s = socket.socket(socket.AF_UNIX)
        s.connect(str(c.sockdir / f"sock-{node}" / "ks.sock"))
        f = s.makefile("rwb")
        n = 0
        while time.time() < stop:
            a = Action("svc:backup", "data.read", "fs://prod/data", 1, ts=now)
            f.write((json.dumps({"op": "release", "grant": iss.issue(a, "x"), "action": a.to_dict(), "now": now}) + "\n").encode())
            f.flush()
            r = json.loads(f.readline())
            if not r["ok"]:
                raise SystemExit(f"release refused: {r['reason']}")
            n += 1
        with lock:
            done[0] += n
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    return done[0] / (time.time() - t0)


def main(clients=32, seconds=8.0):
    out = {}
    for mode in ("ha_pair", "ha_degraded"):
        c = Cluster(Path(tempfile.mkdtemp(prefix="bench")))
        pol = json.loads((Path(__file__).resolve().parents[1] / "policies/default.json").read_text())
        pol["data_budgets"]["budgets"]["svc:backup"]["prod.files"] = 10**9
        (c.tmp / "policy.json").write_text(json.dumps(pol))
        c.policy = c.tmp / "policy.json"
        try:
            c.start_witness()
            c.start("a")
            c.start("b")
            p = c.wait_primary(["a", "b"])
            c.wait_log(p, "HA standby in sync")
            if mode == "ha_degraded":
                c.kill("b" if p == "a" else "a")
                time.sleep(1.5)
            out[mode] = round(bench(c, p, clients, seconds))
        finally:
            c.stop()
    print(json.dumps({"clients": clients, "releases_per_s": out}))


if __name__ == "__main__":
    main(int(sys.argv[1]) if len(sys.argv) > 1 else 32, float(sys.argv[2]) if len(sys.argv) > 2 else 8.0)
