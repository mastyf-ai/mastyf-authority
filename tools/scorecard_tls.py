"""Start the Rust gateway with a test certificate and scan its TLS with testssl.sh.

  PYTHONPATH=src:tests python tools/scorecard_tls.py  -> artifacts/scorecard/testssl.json
"""

from __future__ import annotations

import hashlib
import json
import socket
import subprocess
import tempfile
import time
from pathlib import Path

from test_rust_ha import _certs, _free_port

ROOT = Path(__file__).resolve().parents[1]


def main() -> None:
    tmp = Path(tempfile.mkdtemp(prefix="tls"))
    tls = _certs(tmp)
    (tmp / "callers.json").write_text(json.dumps({hashlib.sha256(b"k").hexdigest(): "human:alice"}))
    port = _free_port()
    gw = subprocess.Popen([str(ROOT / "rust/keyservice/target/release/mastyf-gateway"), "--listen", f"127.0.0.1:{port}",
                           "--tls-cert", tls[1], "--tls-key", tls[3], "--callers", str(tmp / "callers.json"),
                           "--upstream", "127.0.0.1:9"], stderr=subprocess.DEVNULL)
    for _ in range(50):
        try:
            socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
            break
        except OSError:
            time.sleep(0.1)
    out = ROOT / "artifacts" / "scorecard" / "testssl.json"
    out.unlink(missing_ok=True)
    try:
        subprocess.run(["testssl.sh", "--quiet", "--warnings", "off", "--sneaky", "-p", "-S", "-U", "-s", "-f",
                        "--jsonfile", str(out), f"127.0.0.1:{port}"], timeout=900, capture_output=True)
    finally:
        gw.kill()
    res = json.loads(out.read_text())
    bad = [r for r in res if r.get("severity") in ("CRITICAL", "HIGH", "MEDIUM")]
    print(json.dumps({"checks": len(res), "critical_high_medium": [(r["id"], r["severity"], r["finding"][:80]) for r in bad]},
                     indent=1))


if __name__ == "__main__":
    main()
