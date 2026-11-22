"""End-to-end test of the Helm chart on a real Kubernetes cluster (kind, 1 control plane + 2 workers).

  .venv/bin/python tools/k8s_e2e.py [--keep]      (needs docker, kind, kubectl, helm)

Builds the gateway, key-service and engine images, generates every secret and certificate, installs the
chart with key-service high availability, then checks: decisions through the gateway; one active and one
standby engine at the same position; failover when the active engine pod is killed and the old pod
rejoining as standby; key-service failover when the primary pod is killed; and that the network policies
stop a stray pod from reaching the engines or the key service. Writes artifacts/k8s_e2e.json.
"""

from __future__ import annotations

import base64
import datetime as dt
import hashlib
import http.client
import json
import secrets
import socket
import ssl
import subprocess
import sys
import tempfile
import time
from pathlib import Path

from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec, ed25519
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = Path(__file__).resolve().parents[1]
CLUSTER, NS, REL, TAG, REG = "mastyf-e2e", "authority", "t", "vtest", "mastyf.local"
KEYS = {"alice": "k-alice-" + secrets.token_hex(12), "dana": "k-dana-" + secrets.token_hex(12),
        "admin": "k-admin-" + secrets.token_hex(12), "replica": "k-replica-" + secrets.token_hex(12)}
IDS = {"alice": "human:alice", "dana": "human:dana", "admin": "admin", "replica": "replica"}


def sh(cmd: str, check=True, capture=True, timeout=1800) -> str:
    r = subprocess.run(cmd, shell=True, capture_output=capture, text=True, timeout=timeout)
    if check and r.returncode != 0:
        raise RuntimeError(f"{cmd}\n{r.stdout}\n{r.stderr}")
    return (r.stdout or "").strip()


def kc(args: str, **k) -> str:
    return sh(f"kubectl --context kind-{CLUSTER} -n {NS} {args}", **k)


# ------------------------------------------------------------------ certificates and secrets
def _name(cn):
    return x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def ca(cn):
    k = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(_name(cn)).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
         .not_valid_after(now + dt.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=True, path_length=None), True)
         .sign(k, hashes.SHA256()))
    return k, c


def leaf(cak, cac, cn, sans):
    k = ec.generate_private_key(ec.SECP256R1())
    now = dt.datetime.now(dt.timezone.utc)
    c = (x509.CertificateBuilder().subject_name(_name(cn)).issuer_name(cac.subject).public_key(k.public_key())
         .serial_number(x509.random_serial_number()).not_valid_before(now - dt.timedelta(minutes=5))
         .not_valid_after(now + dt.timedelta(days=2)).add_extension(x509.BasicConstraints(ca=False, path_length=None), True)
         .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH, ExtendedKeyUsageOID.CLIENT_AUTH]), False)
         .add_extension(x509.SubjectAlternativeName([x509.DNSName(s) for s in sans]), False)
         .sign(cak, hashes.SHA256()))
    return k, c


def pem(x) -> bytes:
    if isinstance(x, x509.Certificate):
        return x.public_bytes(serialization.Encoding.PEM)
    return x.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8, serialization.NoEncryption())


def make_secrets(d: Path) -> dict:
    sign = ed25519.Ed25519PrivateKey.generate()
    dana = ed25519.Ed25519PrivateKey.generate()
    pub = lambda k: k.public_key().public_bytes(serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo)  # noqa: E731
    files = {
        "mastyf-signing-key": {"signing_key.pem": pem(sign), "authority.pub.pem": pub(sign)},
        "mastyf-callers": {"callers.json": json.dumps({hashlib.sha256(v.encode()).hexdigest(): IDS[k] for k, v in KEYS.items()}).encode()},
        "mastyf-approvers": {"approvers.json": json.dumps({"human:dana": pub(dana).decode()}).encode()},
        "mastyf-replica-key": {"replica.key": KEYS["replica"].encode()},
        "mastyf-kek": {"kek.b64": base64.b64encode(secrets.token_bytes(32))},
    }
    gk, gc = ca("gateway-ca")
    k, c = leaf(gk, gc, "gateway", [f"{REL}-gateway", f"{REL}-gateway.{NS}.svc", f"{REL}-gateway.{NS}.svc.cluster.local", "localhost"])
    files["mastyf-gateway-tls"] = {"tls.crt": pem(c), "tls.key": pem(k), "ca.crt": pem(gc)}
    sk, sc = ca("keyservice-ca")
    ck, cc = ca("keyservice-clients-ca")
    k, c = leaf(sk, sc, "keyservice", [f"{REL}-keyservice", f"{REL}-keyservice.{NS}.svc", "localhost"])
    k2, c2 = leaf(ck, cc, "engine", ["engine"])
    files["mastyf-keyservice-tls"] = {"server.crt": pem(c), "server.key": pem(k), "ca.crt": pem(sc),
                                      "clients-ca.crt": pem(cc), "client.crt": pem(c2), "client.key": pem(k2)}
    hk, hc = ca("ha-ca")
    names = [f"{REL}-ks-a-0.{REL}-ks-a", f"{REL}-ks-b-0.{REL}-ks-b"] + [f"{REL}-witness-{i}.{REL}-witness" for i in range(3)]
    k, c = leaf(hk, hc, "ha", names)
    files["mastyf-keyservice-ha-tls"] = {"ha.crt": pem(c), "ha.key": pem(k), "ha-ca.crt": pem(hc)}
    for name, kv in files.items():
        sd = d / name
        sd.mkdir()
        for f, b in kv.items():
            (sd / f).write_bytes(b)
        kc(f"create secret generic {name} " + " ".join(f"--from-file={f}={sd / f}" for f in kv))
    (d / "client.crt").write_bytes(pem(c2))
    (d / "client.key").write_bytes(pem(k2))
    (d / "ks-ca.crt").write_bytes(pem(sc))
    (d / "gw-ca.crt").write_bytes(pem(gc))
    return {"gw_ca": str(d / "gw-ca.crt")}


# ------------------------------------------------------------------ checks
class GW:
    def __init__(self, port, ca_file):
        self.port, self.ctx = port, ssl.create_default_context(cafile=ca_file)

    def call(self, method, path, who=None, body=None, timeout=10):
        c = http.client.HTTPSConnection("localhost", self.port, context=self.ctx, timeout=timeout)
        try:
            c.request(method, path, json.dumps(body) if body is not None else None,
                      {"Authorization": f"Bearer {KEYS[who]}", "Content-Type": "application/json"} if who else {})
            r = c.getresponse()
            return r.status, json.loads(r.read() or b"{}")
        finally:
            c.close()

    def decide(self):
        return self.call("POST", "/v1/decide", "alice",
                         {"action": {"identity": "human:alice", "action_type": "auth.login", "resource": "sso://corp"}})


def engine_health(i: int) -> dict:
    out = kc(f"exec {REL}-engine-{i} -c engine -- python -c "
             f"\"import urllib.request,json;print(urllib.request.urlopen('http://127.0.0.1:8740/healthz',timeout=3).read().decode())\"",
             check=False)
    try:
        return json.loads(out.splitlines()[-1])
    except (ValueError, IndexError):
        return {}


def wait(pred, limit=300, every=1.0, what=""):
    end = time.time() + limit
    while time.time() < end:
        try:
            if pred():
                return
        except Exception:  # noqa: BLE001 - keep polling until the deadline
            pass
        time.sleep(every)
    raise TimeoutError(what)


def main() -> None:
    keep = "--keep" in sys.argv
    report: dict = {"when": time.strftime("%Y-%m-%d %H:%M"), "steps": []}
    step = lambda name, **kw: (report["steps"].append({"step": name, **kw}), print(f"- {name} {kw}", flush=True))  # noqa: E731
    tmp = Path(tempfile.mkdtemp(prefix="k8s-e2e-"))
    if CLUSTER not in sh("kind get clusters", check=False):
        (tmp / "kind.yaml").write_text("kind: Cluster\napiVersion: kind.x-k8s.io/v1alpha4\n"
                                       "nodes: [{role: control-plane}, {role: worker}, {role: worker}]\n")
        sh(f"kind create cluster --name {CLUSTER} --config {tmp / 'kind.yaml'} --wait 180s", timeout=900)
    step("cluster", nodes=sh(f"kubectl --context kind-{CLUSTER} get nodes --no-headers | wc -l").strip())
    for name, f in (("authority", "Dockerfile.authority"), ("keyservice", "Dockerfile.keyservice"),
                    ("gateway", "Dockerfile.gateway")):
        img = f"{REG}/mastyf-authority-{name}:{TAG}"
        sh(f"docker build -q -f {ROOT / 'deploy' / f} -t {img} {ROOT}", timeout=3600)
        sh(f"kind load docker-image {img} --name {CLUSTER}", timeout=900)
    step("images built and loaded")
    sh(f"kubectl --context kind-{CLUSTER} create namespace {NS}", check=False)
    info = make_secrets(tmp)
    vals = tmp / "values.yaml"
    vals.write_text(json.dumps({
        "image": {"registry": REG, "tag": TAG, "pullPolicy": "Never"},
        "policy": {"json": (ROOT / "policies/default.json").read_text()},
        "engine": {"resources": {"requests": {"cpu": "200m", "memory": "256Mi"}, "limits": {"memory": "1Gi"}},
                   "storage": {"size": "1Gi"}, "snapshotSeconds": 30},
        "gateway": {"resources": {"requests": {"cpu": "50m", "memory": "32Mi"}, "limits": {"memory": "128Mi"}},
                    "failoverAfterSeconds": 3},
        "keyservice": {"ha": {"enabled": True, "witnesses": 1}, "storage": {"size": "1Gi"},
                       "resources": {"requests": {"cpu": "50m", "memory": "32Mi"}, "limits": {"memory": "256Mi"}}},
        "monitoring": {"prometheusRule": False},
    }))
    sh(f"helm --kube-context kind-{CLUSTER} -n {NS} upgrade --install {REL} {ROOT / 'deploy/helm/mastyf-authority'} "
       f"-f {vals} --wait=false", timeout=600)
    t0 = time.time()
    wait(lambda: engine_health(0).get("role") == "active" and engine_health(1).get("role") == "standby", 600,
         5, "engines up (one active, one standby)")
    wait(lambda: "1/1" in kc(f"get pods -l app.kubernetes.io/component=gateway --no-headers"), 300, 3, "gateway")
    step("installed", seconds=round(time.time() - t0))
    pf = subprocess.Popen(f"kubectl --context kind-{CLUSTER} -n {NS} port-forward svc/{REL}-gateway 18443:8443",
                          shell=True, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        gw = GW(18443, info["gw_ca"])
        wait(lambda: gw.call("GET", "/healthz")[0] == 200, 60, 1, "port-forward")
        ok = sum(gw.decide()[0] == 200 for _ in range(50))
        step("decisions through the gateway", ok_of_50=ok)
        wait(lambda: engine_health(1)["seq"] == engine_health(0)["seq"], 60, 2, "standby caught up")
        step("standby at the same position", seq=engine_health(0)["seq"])
        assert gw.call("POST", "/v1/freeze", "admin", {"identity": "human:bob", "reason": "e2e drill"})[0] == 200

        # engine failover: kill the active pod
        kc(f"delete pod {REL}-engine-0 --force --grace-period=0", check=False)
        t1 = time.time()
        wait(lambda: gw.decide()[0] == 200, 120, 0.25, "decisions after engine failover")
        took = time.time() - t1
        h1 = engine_health(1)
        frozen = gw.call("GET", "/v1/alerts", "admin")[1].get("frozen", {})
        step("engine failover", seconds=round(took, 1), engine1=h1.get("role"), epoch=h1.get("epoch"),
             freeze_kept="human:bob" in frozen)
        assert h1.get("role") == "active" and h1.get("epoch", 0) >= 1, f"standby was not promoted: {h1}"
        assert "human:bob" in frozen
        wait(lambda: engine_health(0).get("role") == "standby" and engine_health(0)["seq"] == engine_health(1)["seq"],
             300, 3, "old pod rejoins as standby")
        step("old engine pod rejoined as standby", seq=engine_health(0)["seq"])

        # key-service failover: kill the primary (the ready pod)
        def ks_ready():
            return {line.split()[0]: line.split()[1] for line in
                    kc("get pods -l app.kubernetes.io/component=keyservice --no-headers").splitlines()}
        wait(lambda: "1/1" in ks_ready().values(), 300, 3, "key service primary ready")
        primary = next(p for p, r in ks_ready().items() if r == "1/1")
        sts = primary.rsplit("-", 1)[0]
        # same node coming back within its lease is a valid recovery; to test failover to the OTHER node,
        # keep the primary down (scale its StatefulSet to 0)
        kc(f"scale statefulset {sts} --replicas=0")
        t2 = time.time()
        wait(lambda: any(r == "1/1" for p, r in ks_ready().items() if p != primary), 180, 0.5, "key service failover")
        step("key service failover to the other node", killed=primary, seconds=round(time.time() - t2, 1),
             new_primary=[p for p, r in ks_ready().items() if r == "1/1"])
        kc(f"scale statefulset {sts} --replicas=1")
        wait(lambda: primary in ks_ready() and "Running" in kc(f"get pod {primary} --no-headers"), 180, 2, "old key service back")
        time.sleep(10)
        st = ks_ready()
        step("old key-service node back as standby", ready=st)
        assert st.get(primary) == "0/1", st  # a standby has no client port: not ready
        # a promotion still works afterwards (fences the new key-service primary)
        kc(f"delete pod {REL}-engine-1 --force --grace-period=0", check=False)
        t3 = time.time()
        wait(lambda: gw.decide()[0] == 200, 180, 0.25, "second engine failover")
        step("second engine failover (fencing the new key-service primary)", seconds=round(time.time() - t3, 1),
             engine0=engine_health(0).get("role"), epoch=engine_health(0).get("epoch"))

        # network policies: a stray pod may reach the gateway, but not the engines or the key service
        targets = [("gateway", f"{REL}-gateway", 8443), ("engine", f"{REL}-engine-0.{REL}-engine", 8740),
                   ("keyservice", f"{REL}-keyservice", 8443)]
        code = ("import socket\n" + "".join(
            f"s=socket.socket();s.settimeout(4);print('PROBE {n}', 'OPEN' if s.connect_ex(('{h}',{p}))==0 else 'BLOCKED')\n"
            for n, h, p in targets))
        (tmp / "probe.py").write_text(code)
        out = kc(f"run probe-{secrets.token_hex(3)} --rm -i --restart=Never --image={REG}/mastyf-authority-authority:{TAG} "
                 f"--image-pull-policy=Never --command -- python -c \"$(cat {tmp / 'probe.py'})\"", check=False, timeout=180)
        seen = dict(line.split()[1:3] for line in out.splitlines() if line.startswith("PROBE "))
        step("network policy (stray pod)", **seen)
        assert seen == {"gateway": "OPEN", "engine": "BLOCKED", "keyservice": "BLOCKED"}, seen
        report["ok"] = True
    except Exception as e:  # noqa: BLE001
        report["ok"] = False
        report["error"] = f"{type(e).__name__}: {e}"
        print(kc("get pods -o wide", check=False))
        raise
    finally:
        pf.terminate()
        (ROOT / "artifacts/k8s_e2e.json").write_text(json.dumps(report, indent=1))
        if not keep:
            sh(f"kind delete cluster --name {CLUSTER}", check=False, timeout=300)


if __name__ == "__main__":
    main()
