"""Load test for the Python authority HTTP server: throughput, latency, and behaviour under a flood.

  PYTHONPATH=src python tools/loadtest.py [seconds] [clients]

Runs the real server in-process (default policy, trained model if artifacts/risk_model.json exists),
with keep-alive callers sending realistic decide requests from several identities, then a burst of
idle connections to check that the connection cap answers 503 instead of falling over.
"""

from __future__ import annotations

import hashlib
import http.client
import json
import random
import socket
import statistics
import sys
import tempfile
import threading
import time
from pathlib import Path

from authority.audit import AuditLog
from authority.crypto import Signer
from authority.engine import Authority
from authority.grants import GrantIssuer, GrantVerifier
from authority.model import RiskModel
from authority.policy import Policy
from authority.server import BoundedServer, make_handler

ROOT = Path(__file__).resolve().parents[1]


def main(seconds: float = 10.0, clients: int = 32) -> dict:
    pol = Policy.load(ROOT / "policies/default.json")
    tmp = Path(tempfile.mkdtemp(prefix="mastyf-load"))
    signer = Signer.generate()
    model_path = ROOT / "artifacts" / "risk_model.json"
    model = RiskModel.load(model_path) if model_path.exists() else None
    auth = Authority(pol, GrantIssuer(signer, 60), AuditLog(tmp / "audit.jsonl", signer), model=model)
    idents = [n for n in pol.identities if not pol.identities[n].approver][:6] or list(pol.identities)[:6]
    keys = {f"key-{i}": who for i, who in enumerate(idents)}
    callers = {hashlib.sha256(k.encode()).hexdigest(): v for k, v in keys.items()}
    httpd = BoundedServer(("127.0.0.1", 0), make_handler(auth, callers, GrantVerifier(signer.public_key)), max_clients=64)
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    port = httpd.server_address[1]
    lat: list[float] = []
    verdicts: dict[str, int] = {}
    errors = [0]
    lock = threading.Lock()
    stop = time.time() + seconds

    def worker(i: int) -> None:
        rng = random.Random(i)
        key = list(keys)[i % len(keys)]
        who = keys[key]
        c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        mine, mine_v = [], {}
        while time.time() < stop:
            act = {"identity": who, "action_type": rng.choice(["data.read", "data.read", "file.write", "data.export"]),
                   "resource": rng.choice(["db://crm/customers/query", "s3://corp-reports/q3.csv", "fs://prod/data"]),
                   "count": rng.choice([1, 5, 20, 200, 5000])}
            body = json.dumps({"action": act})
            t0 = time.perf_counter()
            try:
                c.request("POST", "/v1/decide", body, {"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
                r = c.getresponse()
                d = json.loads(r.read())
                mine.append(time.perf_counter() - t0)
                mine_v[d.get("verdict", "?")] = mine_v.get(d.get("verdict", "?"), 0) + 1
            except Exception:  # noqa: BLE001
                with lock:
                    errors[0] += 1
                c.close()
                c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
        with lock:
            lat.extend(mine)
            for k, v in mine_v.items():
                verdicts[k] = verdicts.get(k, 0) + v

    ts = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    elapsed = time.time() - t0

    # flood: 200 idle connections against a cap of 64
    socks, refused = [], 0
    for _ in range(200):
        s = socket.create_connection(("127.0.0.1", port), timeout=5)
        socks.append(s)
    time.sleep(0.5)
    for s in socks[64:]:
        s.settimeout(2)
        try:
            refused += s.recv(64).startswith(b"HTTP/1.1 503")
        except OSError:
            pass
    for s in socks:
        s.close()
    time.sleep(0.5)
    c = http.client.HTTPConnection("127.0.0.1", port, timeout=10)
    c.request("GET", "/healthz")
    healthy_after = c.getresponse().status == 200
    httpd.shutdown()
    lat.sort()
    out = {"seconds": round(elapsed, 1), "clients": clients, "requests": len(lat), "errors": errors[0],
           "req_per_s": round(len(lat) / elapsed), "p50_ms": round(statistics.median(lat) * 1000, 2),
           "p99_ms": round(lat[int(len(lat) * 0.99)] * 1000, 2), "verdicts": verdicts, "model": model is not None,
           "flood_connections": 200, "flood_answered_503": refused, "healthy_after_flood": healthy_after}
    print(json.dumps(out, indent=2))
    return out


if __name__ == "__main__":
    main(float(sys.argv[1]) if len(sys.argv) > 1 else 10.0, int(sys.argv[2]) if len(sys.argv) > 2 else 32)
