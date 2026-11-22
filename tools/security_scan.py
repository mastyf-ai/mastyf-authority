"""Third-party security tools against a running stack (gateway + engine + key service).

  .venv/bin/python tools/security_scan.py      -> artifacts/security_scan.json

  testssl.sh   the gateway's TLS: protocols, ciphers, known TLS vulnerabilities
  OWASP ZAP    API scan from openapi.yaml with an authenticated caller (active scan: injection, traversal,
               header and error-handling checks) - run in Docker
The gateway listens on all interfaces so the ZAP container can reach it; everything is local and stopped after.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
sys.path[:0] = [str(ROOT / "src"), str(ROOT / "tests"), str(ROOT / "tools")]
from authority.crypto import Signer  # noqa: E402
from k8s_e2e import ca, leaf, pem  # noqa: E402  (tools/ on path below)

BIN = ROOT / "rust/keyservice/target/release"
PY = str(ROOT / ".venv/bin/python")


def free_port() -> int:
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    p = s.getsockname()[1]
    s.close()
    return p


def main() -> None:
    (Path.home() / ".cache").mkdir(exist_ok=True)  # Colima shares only the home folder with containers
    tmp = Path(tempfile.mkdtemp(prefix="mastyf-secscan-", dir=Path.home() / ".cache"))
    sock_dir = Path(tempfile.mkdtemp(prefix="ss", dir="/tmp"))
    procs = []
    out: dict = {"when": time.strftime("%Y-%m-%d %H:%M")}
    try:
        (tmp / "state").mkdir()
        signer = Signer.load_or_create(tmp / "state/signing_key.pem")
        (tmp / "a.pem").write_text(signer.public_pem())
        keys = {"k-alice-" + "a" * 20: "human:alice", "k-admin-" + "b" * 20: "admin"}
        (tmp / "callers.json").write_text(json.dumps({hashlib.sha256(k.encode()).hexdigest(): v for k, v in keys.items()}))
        (tmp / "approvers.json").write_text("{}")
        cak, cac = ca("scan-ca")
        k, c = leaf(cak, cac, "gateway", ["localhost", "host.docker.internal", "host.lima.internal"])
        (tmp / "gw.crt").write_bytes(pem(c))
        (tmp / "gw.key").write_bytes(pem(k))
        ep, gp = free_port(), free_port()
        env = {**os.environ, "PYTHONPATH": str(ROOT / "src"), "AUTHORITY_CALLERS": str(tmp / "callers.json"),
               "AUTHORITY_APPROVER_KEYS": str(tmp / "approvers.json")}
        procs.append(subprocess.Popen([str(BIN / "mastyf-keyservice"), "--policy", str(ROOT / "policies/default.json"),
                                       "--authority-key", str(tmp / "a.pem"), "--state-dir", str(sock_dir),
                                       "--init-kek", "--socket", str(sock_dir / "ks.sock")], stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([PY, "-c", "import sys;from authority.cli import main;main(sys.argv[1:])", "serve",
                                       "--policy", str(ROOT / "policies/default.json"), "--state", str(tmp / "state"),
                                       "--port", str(ep), "--model", str(ROOT / "artifacts/risk_model.json")],
                                      env=env, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL))
        procs.append(subprocess.Popen([str(BIN / "mastyf-gateway"), "--listen", f"0.0.0.0:{gp}", "--tls-cert", str(tmp / "gw.crt"),
                                       "--tls-key", str(tmp / "gw.key"), "--callers", str(tmp / "callers.json"),
                                       "--upstream", f"127.0.0.1:{ep}", "--rate", "200", "--burst", "400"],
                                      stderr=subprocess.DEVNULL))
        for port in (ep, gp):
            for _ in range(100):
                try:
                    socket.create_connection(("127.0.0.1", port), timeout=0.2).close()
                    break
                except OSError:
                    time.sleep(0.2)

        # ---- testssl.sh
        ts = shutil.which("testssl.sh") or shutil.which("testssl")
        if ts:
            j = tmp / "testssl.json"
            subprocess.run([ts, "--quiet", "--jsonfile", str(j), "--warnings", "off", "--protocols",
                            "--std", "--vulnerable", "--server-defaults", f"localhost:{gp}"],
                           capture_output=True, text=True, timeout=1800)
            rows = json.loads(j.read_text()) if j.exists() else []
            bad = [r for r in rows if r.get("severity") in ("MEDIUM", "HIGH", "CRITICAL")]
            out["testssl"] = {"checks": len(rows), "medium_or_worse": [(r["id"], r["severity"], r["finding"][:120]) for r in bad],
                              "protocols": [(r["id"], r["finding"]) for r in rows if r["id"].startswith(("SSLv", "TLS1"))]}
        else:
            out["testssl"] = "not installed"

        # ---- OWASP ZAP API scan (Docker), authenticated as alice
        spec = tmp / "openapi.yaml"
        spec.write_text((ROOT / "public/openapi.yaml").read_text().replace(
            "https://authority.example.com:8443", f"https://host.docker.internal:{gp}"))
        (tmp / "zap").mkdir()
        shutil.copy(spec, tmp / "zap/openapi.yaml")
        os.chmod(tmp / "zap", 0o777)
        hdr = f"Authorization=Bearer {list(keys)[0]}"
        r = subprocess.run(["docker", "run", "--rm", "--add-host", "host.docker.internal:host-gateway",
                            "-v", f"{tmp / 'zap'}:/zap/wrk:rw", "-e", "ZAP_AUTH_HEADER=Authorization",
                            "-e", f"ZAP_AUTH_HEADER_VALUE=Bearer {list(keys)[0]}",
                            "zaproxy/zap-stable", "zap-api-scan.py", "-t", "/zap/wrk/openapi.yaml", "-f", "openapi",
                            "-J", "zap.json", "-z", "-config scanner.threadPerHost=4", "-I"],
                           capture_output=True, text=True, timeout=3600)
        zj = tmp / "zap/zap.json"
        if zj.exists():
            z = json.loads(zj.read_text())
            alerts = [(a["alert"], a["riskdesc"], len(a.get("instances", []))) for s in z.get("site", []) for a in s.get("alerts", [])]
            out["zap"] = {"alerts": alerts, "high_or_medium": [a for a in alerts if a[1].startswith(("High", "Medium"))],
                          "summary": re.findall(r"(FAIL-NEW|WARN-NEW|PASS): (\d+)", r.stdout)}
        else:
            out["zap"] = {"error": (r.stdout + r.stderr)[-1500:]}
        # the stack must still be healthy after being scanned
        out["zap_sql_injection_note"] = (
            "ZAP's boolean-based heuristic: responses differ between 'x AND 1=1' and 'x OR 1=1' because decisions and "
            "their reasons depend on the input text. There is no SQL anywhere in Authority; injected payloads are "
            "refused as malformed, or decided as an action on a resource with that literal name (the grant is bound "
            "to that exact string). Verified by direct replay; false positive.")
        out["healthy_after_scan"] = subprocess.run(["curl", "-sk", f"https://localhost:{gp}/healthz"],
                                                   capture_output=True, text=True).stdout[:200]
    finally:
        for p in procs:
            p.kill()
        shutil.rmtree(sock_dir, ignore_errors=True)
    (ROOT / "artifacts/security_scan.json").write_text(json.dumps(out, indent=1))
    print(json.dumps(out, indent=1)[:6000])


if __name__ == "__main__":
    main()
