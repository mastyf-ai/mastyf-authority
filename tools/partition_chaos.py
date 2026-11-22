"""Network splits, not just crashes, against the real binaries - then check the history (Jepsen-style).

  PYTHONPATH=src:tests .venv/bin/python tools/partition_chaos.py [--rounds 30] [--seed 1]

Two engines, the key service and a gateway, with a cuttable TCP proxy in front of each engine (so a split
can isolate an engine that is still alive and still has clients that reach it directly). Each round picks
a fault at random: split the active engine from the gateway (the gateway promotes the standby while the old
engine keeps running), split the standby, kill an engine, pause one (SIGSTOP), or heal everything. Clients
keep deciding and asking the key service for records - through the gateway, and straight at whichever
engine they last reached (a stale client). An admin freezes a new identity every round.

The checker reads the whole history afterwards:
  frozen-stays-frozen   after a freeze was confirmed to the admin, the key service never releases records
                        to that identity again (whichever engine signed the grant)
  one-honoured-engine   in any second, released grants come from a single epoch
  no-lost-freeze        every confirmed freeze is still in force on the engine that is active at the end
Output: artifacts/partition_chaos.json
"""

from __future__ import annotations

import argparse
import json
import random
import signal
import socket
import sys
import threading
import time
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests")]
from authority.crypto import b64d  # noqa: E402
from test_failover import BIN, Cluster, _free_port  # noqa: E402

KA = "k-alice-000000000000000000"
KADMIN = "k-admin-000000000000000000"


class Proxy:
    """TCP proxy that can drop and refuse connections (a network split)."""

    def __init__(self, target_port: int):
        self.target = target_port
        self.port = _free_port()
        self.cut = False
        self.conns: list[socket.socket] = []
        self.lock = threading.Lock()
        self.srv = socket.socket()
        self.srv.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.srv.bind(("127.0.0.1", self.port))
        self.srv.listen(128)
        threading.Thread(target=self._accept, daemon=True).start()

    def _accept(self):
        while True:
            c, _ = self.srv.accept()
            if self.cut:
                c.close()
                continue
            try:
                u = socket.create_connection(("127.0.0.1", self.target), timeout=2)
            except OSError:
                c.close()
                continue
            with self.lock:
                self.conns += [c, u]
            for a, b in ((c, u), (u, c)):
                threading.Thread(target=self._pipe, args=(a, b), daemon=True).start()

    def _pipe(self, a, b):
        try:
            while not self.cut:
                d = a.recv(65536)
                if not d:
                    break
                b.sendall(d)
        except OSError:
            pass
        for s in (a, b):
            try:
                s.close()
            except OSError:
                pass

    def split(self, on: bool):
        self.cut = on
        if on:
            with self.lock:
                for s in self.conns:
                    try:
                        s.shutdown(socket.SHUT_RDWR)
                        s.close()
                    except OSError:
                        pass
                self.conns = []


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--rounds", type=int, default=30)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--stack", action="store_true", help="let faults pile up instead of healing after each")
    ap.add_argument("--out", default=str(ROOT / "artifacts/partition_chaos.json"))
    a = ap.parse_args()
    rng = random.Random(a.seed)
    import tempfile
    tmp = Path(tempfile.mkdtemp(prefix="pchaos", dir=str(Path.home() / ".cache")))
    c = Cluster(tmp)
    # engines listen on pa/pb; the gateway and the peer links go through cuttable proxies
    real = {"a": c.pa, "b": c.pb}
    c.start_ks()
    prox = {n: Proxy(p) for n, p in real.items()}
    history: list[dict] = []
    hlock = threading.Lock()

    def log(**e):
        e["t"] = time.time()
        with hlock:
            history.append(e)

    import os

    def start(name, role="auto"):
        # as on Kubernetes: --role auto, engine 0 / engine 1, peer and follow through the gateway
        os.environ["AUTHORITY_ORDINAL"] = "0" if name == "a" else "1"
        os.environ["AUTHORITY_FENCE_WAIT"] = "20"
        c.start_engine(name, role, ["--peer", f"https://localhost:{c.pg}", "--follow", f"https://localhost:{c.pg}"])

    # gateway upstreams = the proxies
    import subprocess
    start("a")
    c.procs["gw"] = subprocess.Popen(
        [str(BIN / "mastyf-gateway"), "--listen", f"127.0.0.1:{c.pg}", "--tls-cert", c.cert, "--tls-key", c.tkey,
         "--callers", str(c.tmp / "callers.json"), "--upstream", f"127.0.0.1:{prox['a'].port}",
         "--upstream", f"127.0.0.1:{prox['b'].port}", "--promote-key-file", str(c.tmp / "promote.key"),
         "--failover-after", "2", "--rate", "100000", "--burst", "100000"], stderr=open(c.tmp / "gw.log", "ab"))
    c._wait(lambda: socket.create_connection(("127.0.0.1", c.pg), timeout=0.2).close() or True)
    start("b")
    stop = threading.Event()
    down_since: dict[str, float] = {}

    def supervisor():  # restarts an exited engine after 3 s, like a Kubernetes StatefulSet
        while not stop.is_set():
            for n in ("a", "b"):
                pr = c.procs.get(n)
                if pr is not None and pr.poll() is not None:
                    down_since.setdefault(n, time.time())
                    if time.time() - down_since[n] > 3:
                        down_since.pop(n, None)
                        log(kind="restart", engine=n, exit=pr.returncode)
                        start(n)
            time.sleep(0.5)
    threading.Thread(target=supervisor, daemon=True).start()
    gw_ok: dict[int, int] = defaultdict(int)
    gw_try: dict[int, int] = defaultdict(int)
    windows: list[list] = []  # [freeze confirmed at, unfreeze sent at (or None)] for alice

    def client(direct: bool, idx: int):
        port = None
        while not stop.is_set():
            ident = rng.choice(["human:alice"])
            act = {"identity": ident, "action_type": "data.read", "resource": f"db://crm/customers/{idx}", "count": 1}
            try:
                sec = int(time.time())
                if port is None:
                    gw_try[sec] += 1
                st, d = c.call("POST", "/v1/decide", KA, {"action": act}, port=port)
                if port is None and st == 200:
                    gw_ok[sec] += 1
                if st == 200 and d.get("verdict") == "ALLOW" and d.get("grant"):
                    g = json.loads(b64d(d["grant"].split(".")[0]))
                    r = c.ks({"op": "release", "grant": d["grant"], "action": {**act, "ts": time.time()}})
                    log(kind="release", ok=r.get("ok"), identity=ident, epoch=g.get("ep", 0), iat=g["iat"],
                        via="direct" if port else "gw", reason=r.get("reason", "")[:80])
                if direct and port is None:
                    port = rng.choice([real["a"], real["b"]])  # a stale client pinned to one engine
            except (OSError, ValueError, KeyError):
                port = None
            time.sleep(0.05)

    # alice gets approvals so reads are ALLOW (grant_for_alice handles one escalation path)
    try:
        c.grant_for_alice()
    except AssertionError:
        pass
    threads = [threading.Thread(target=client, args=(d, i), daemon=True) for i, d in enumerate([False, False, True])]
    for t in threads:
        t.start()
    # nemesis cycles (Jepsen): one fault at a time, held a few seconds, then heal and recover - a two-engine
    # system promises to survive any single failure; --stack keeps faults piling up (no promise holds there,
    # but the safety checks still must)
    faults = ["split-active", "split-standby", "kill-engine", "pause-engine"] + (["heal", "heal"] if a.stack else [])
    paused: set[str] = set()
    rounds = []
    for r in range(a.rounds):
        # every few rounds an admin freezes alice (her key was stolen), later lifts it; her reads never stop
        who = "human:alice"
        if r % 4 == 1:
            try:
                st, _ = c.call("POST", "/v1/freeze", KADMIN, {"identity": who, "reason": f"round {r}"})
                if st == 200:
                    windows.append([time.time(), None])
                    log(kind="freeze_confirmed", identity=who)
                else:
                    log(kind="freeze_refused", identity=who, status=st)
            except (OSError, ValueError):
                log(kind="freeze_error", identity=who)
        elif r % 4 == 3 and windows and windows[-1][1] is None:
            windows[-1][1] = time.time() - 0.001  # anything issued after this may be legitimately allowed again
            for port in (None, real["a"], real["b"]):
                try:
                    c.call("POST", "/v1/unfreeze", KADMIN, {"identity": who, "operator": "chaos"}, port=port)
                except (OSError, ValueError):
                    pass
        # the victim (stolen session) keeps trying, directly at both engines and via the gateway
        for port in (None, real["a"], real["b"]):
            try:
                act = {"identity": "human:alice", "action_type": "data.read", "resource": "db://crm/customers/1", "count": 1}
                st, d = c.call("POST", "/v1/decide", KA, {"action": act}, port=port)
            except (OSError, ValueError):
                pass
        f = rng.choice(faults)
        health = {}
        for n in ("a", "b"):
            try:
                health[n] = c.health(real[n])
            except (OSError, ValueError):
                health[n] = None
        active = [n for n, h in health.items() if h and h.get("role") == "active"]
        target = active[0] if active else rng.choice(["a", "b"])
        other = "b" if target == "a" else "a"
        if f == "split-active":
            prox[target].split(True)
        elif f == "split-standby":
            prox[other].split(True)
        elif f == "kill-engine":
            if c.procs.get(target) and c.procs[target].poll() is None:
                c.procs[target].kill()
                c.procs[target].wait()
        elif f == "pause-engine":
            if c.procs.get(target) and c.procs[target].poll() is None:
                c.procs[target].send_signal(signal.SIGSTOP)
                paused.add(target)
        else:
            for p in prox.values():
                p.split(False)
            for n in list(paused):
                c.procs[n].send_signal(signal.SIGCONT)
                paused.discard(n)
            # (exited engines are restarted by the supervisor)
        log(kind="fault", fault=f, target=target, roles={n: (h or {}).get("role") for n, h in health.items()},
            epochs={n: (h or {}).get("epoch") for n, h in health.items()})
        rounds.append({"round": r, "fault": f, "target": target})
        time.sleep(rng.uniform(4, 8))
        if not a.stack:  # heal and let it recover
            for pp in prox.values():
                pp.split(False)
            for n in list(paused):
                c.procs[n].send_signal(signal.SIGCONT)
                paused.discard(n)
            log(kind="fault", fault="heal", target="all", roles={}, epochs={})
            time.sleep(10)
    # heal and settle
    for p in prox.values():
        p.split(False)
    for n in list(paused):
        c.procs[n].send_signal(signal.SIGCONT)
    time.sleep(20)
    stop.set()
    final = {}
    for n in ("a", "b"):
        try:
            final[n] = c.health(real[n])
        except (OSError, ValueError):
            final[n] = None
    try:
        alerts = c.call("GET", "/v1/alerts", KADMIN)[1]
    except (OSError, ValueError):
        alerts = {}
    c.stop()

    # ---- checker
    rel = [e for e in history if e["kind"] == "release" and e["ok"]]
    # a grant issued after a confirmed freeze (and before it was lifted) must never release anything
    v_frozen = [e for e in rel if any(f < e["iat"] and (u is None or e["iat"] < u) for f, u in windows)]
    # once a grant of epoch E has been released, a grant of a lower epoch must never be released again (the key
    # service fenced E before E decided anything). Times are when the client got the answer: allow 0.3 s for
    # requests that were already in flight.
    v_two = {}
    best_t: dict[int, float] = {}
    for e in sorted(rel, key=lambda x: x["t"]):
        ep = e.get("epoch") or 0
        newer = [t for epx, t in best_t.items() if epx > ep and t < e["t"] - 0.3]
        if newer:
            v_two[round(e["t"], 3)] = {"released_epoch": ep, "after_epoch_seen_at": round(min(newer), 3), "via": e["via"]}
        best_t.setdefault(ep, e["t"])
    frozen_now = set((alerts or {}).get("frozen", {}) or {})
    still = bool(windows and windows[-1][1] is None)
    lost = (["human:alice"] if still and "human:alice" not in frozen_now else []) if alerts else \
        ["(no active engine reachable at the end)"]
    out = {
        "rounds": rounds, "releases_ok": len(rel), "releases_refused": sum(1 for e in history if e["kind"] == "release" and not e["ok"]),
        "freeze_windows": windows,
        "freezes_refused_or_failed": sum(1 for e in history if e["kind"] in ("freeze_refused", "freeze_error")),
        "violations": {"frozen_stays_frozen": v_frozen[:10], "stale_epoch_released_after_newer": dict(list(v_two.items())[:10]),
                       "lost_freezes": lost},
        "refusal_reasons": dict(sorted(__import__("collections").Counter(
            e["reason"].split(":")[0] for e in history if e["kind"] == "release" and not e["ok"]).items())),
        "final": final,
        "epochs_seen": sorted({e.get("epoch") for e in rel if e.get("epoch") is not None}),
        "availability_through_gateway": round(sum(1 for t in gw_try if gw_ok.get(t)) / max(1, len(gw_try)), 4),
        "longest_outage_s": max((len(list(g)) for k, g in __import__("itertools").groupby(
            [bool(gw_ok.get(t)) for t in range(min(gw_try or [0]), max(gw_try or [0]) + 1)]) if not k), default=0),
        "restarts": sum(1 for e in history if e["kind"] == "restart"),
    }
    print(json.dumps({k: v for k, v in out.items() if k != "rounds"}, indent=1, default=str))
    Path(a.out).write_text(json.dumps(out, indent=1, default=str))


if __name__ == "__main__":
    main()
