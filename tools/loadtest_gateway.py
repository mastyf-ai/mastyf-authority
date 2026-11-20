"""Decisions per second through the Rust gateway (TLS, keep-alive) to the Python engine with the model.

  PYTHONPATH=src:tests python tools/loadtest_gateway.py [seconds] [clients]
"""

from __future__ import annotations

import hashlib
import http.client
import json
import random
import socket
import ssl
import statistics
import subprocess
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
from test_rust_ha import _certs, _free_port

ROOT = Path(__file__).resolve().parents[1]


def main(seconds=10.0, clients=32):
    tmp = Path(tempfile.mkdtemp(prefix="gwload"))
    pol = Policy.load(ROOT / "policies/default.json")
    signer = Signer.generate()
    auth = Authority(pol, GrantIssuer(signer, 60), AuditLog(tmp / "a.log", signer),
                     model=RiskModel.load(ROOT / "artifacts/risk_model.json"))
    idents = [n for n in pol.identities if not pol.identities[n].approver][:6]
    keys = {f"key-{i}": w for i, w in enumerate(idents)}
    callers = {hashlib.sha256(k.encode()).hexdigest(): v for k, v in keys.items()}
    (tmp / "callers.json").write_text(json.dumps(callers))
    httpd = BoundedServer(("127.0.0.1", 0), make_handler(auth, callers, GrantVerifier(signer.public_key)))
    threading.Thread(target=httpd.serve_forever, daemon=True).start()
    tls = _certs(tmp)
    port = _free_port()
    gw = subprocess.Popen([str(ROOT / "rust/keyservice/target/release/mastyf-gateway"), "--listen", f"127.0.0.1:{port}",
                           "--tls-cert", tls[1], "--tls-key", tls[3], "--callers", str(tmp / "callers.json"),
                           "--upstream", f"127.0.0.1:{httpd.server_address[1]}", "--rate", "100000", "--burst", "100000"],
                          stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    ctx = ssl.create_default_context(cafile=tls[5])
    lat, errors, lock, stop = [], [0], threading.Lock(), time.time() + seconds

    def worker(i):
        rng = random.Random(i)
        key = list(keys)[i % len(keys)]
        c = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=10)
        mine = []
        while time.time() < stop:
            act = {"identity": keys[key], "action_type": rng.choice(["data.read", "file.write", "data.export"]),
                   "resource": rng.choice(["db://crm/customers/query", "fs://prod/data"]), "count": rng.choice([1, 20, 5000])}
            t0 = time.perf_counter()
            try:
                c.request("POST", "/v1/decide", json.dumps({"action": act}),
                          {"Authorization": f"Bearer {key}", "Content-Type": "application/json"})
                r = c.getresponse()
                r.read()
                if r.status != 200:
                    raise RuntimeError(r.status)
                mine.append(time.perf_counter() - t0)
            except Exception:  # noqa: BLE001
                with lock:
                    errors[0] += 1
                c.close()
                c = http.client.HTTPSConnection("localhost", port, context=ctx, timeout=10)
        with lock:
            lat.extend(mine)
    ts = [threading.Thread(target=worker, args=(i,)) for i in range(clients)]
    t0 = time.time()
    for t in ts:
        t.start()
    for t in ts:
        t.join()
    el = time.time() - t0
    gw.kill()
    httpd.shutdown()
    lat.sort()
    out = {"via": "mastyf-gateway (TLS 1.3)", "clients": clients, "requests": len(lat), "errors": errors[0],
           "req_per_s": round(len(lat) / el), "p50_ms": round(statistics.median(lat) * 1000, 2),
           "p99_ms": round(lat[int(len(lat) * 0.99)] * 1000, 2)}
    print(json.dumps(out))


if __name__ == "__main__":
    main(float(sys.argv[1]) if len(sys.argv) > 1 else 10.0, int(sys.argv[2]) if len(sys.argv) > 2 else 32)
