"""Differential test: Rust script-integrity check and change gates must agree with Python on
random scripts and random gate-action sequences."""

import json
import random
import subprocess
from pathlib import Path

import pytest

from authority import script_integrity
from authority.actions import Action
from authority.crypto import Signer, b64d, b64e
from authority.gates import ChangeGate, GatePolicy, gate_message
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"
pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first")

BASE = (ROOT / "fixtures/tag_v1.js").read_text()
FRAGS = [
    "var x = 1;", "// comment é ü 😀", "fetch('/api')", "navigator.sendBeacon(u, d)", "new Image().src = u",
    "document.querySelector(\"input[autocomplete='cc-number']\")", "var cvv = f.value;", "type='password'",
    "'https://collector.example-sink.invalid/c'", "\"evil-host.top\"", "//cdn.other.com/x.js", "eval(s)",
    "atob('aGVsbG8=')", "String.fromCharCode(72,105)", "'" + "A" * 220 + "'", "\\x41\\x42\\x43\\x44\\x45\\x46\\x47\\x48",
    "e.clipboardData.setData('t', v)", "t.replace(/0x[a-f0-9]{40}/i, w)", "0x" + "ab" * 20,
    "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq", "document.addEventListener('submit', f)",
    "document.addEventListener('keydown', f)", "new WebSocket('wss://ws.example.com')", "form.action = u",
    "document.createElement('script')", "".join(chr(0x4e00 + i) for i in range(300)), "mnemonic seed phrase",
]


import base64 as _b64  # noqa: E402

import optimjack_fixtures as OJ  # noqa: E402

FRAGS += [OJ._LOADER_1, OJ._LOADER_2, OJ._LOADER_3[:4000], "eval(atob('" + _b64.b64encode(b"fetch('//x.invalid/a')").decode() + "'))",
          "Function.prototype.call = function(){}", "window.fetch = function(u,o){}", "html2canvas(document.body)",
          "if(/iPhone|iPad|iPod/.test(navigator.userAgent)){}", "var f=document.createElement('iframe');f.style.display='none';",
          "setInterval(function(){ location.reload(); }, 60000)", "document.cookie.slice(0,8000)", "document.cookie = 'a=1'",
          "function luhn(n){ var s=0; }", "m = v.match(/(?:\\d[ -]?){13,19}/)", "String.fromCharCode(104,116,116,112,115,58,47,47)",
          "'\\x68\\x74\\x74\\x70\\x73\\x3a\\x2f\\x2f'", "new MutationObserver(function(){ n.value = x; })",
          "navigator.clipboard.writeText = function(t){}", "sessionStorage.setItem('cc_last', m)"]


def mk(rng):
    parts = [BASE] + [rng.choice(FRAGS) for _ in range(rng.randint(0, 5))]
    rng.shuffle(parts)
    return "\n".join(parts)


@pytest.fixture
def rust(tmp_path):
    auth = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin")}
    (tmp_path / "a.pem").write_text(auth.public_pem())
    (tmp_path / "appr.json").write_text(json.dumps({n: s.public_pem() for n, s in appr.items()}))
    p = subprocess.Popen([str(BIN), "--policy", str(ROOT / "policies/default.json"), "--authority-key",
                          str(tmp_path / "a.pem"), "--approvers", str(tmp_path / "appr.json"), "--fake-clock"],
                         stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)

    def ask(req):
        p.stdin.write(json.dumps(req) + "\n")
        p.stdin.flush()
        return json.loads(p.stdout.readline())

    yield ask, auth, appr
    p.stdin.close()
    p.wait(timeout=10)


def test_script_check_agrees(rust):
    ask, _, _ = rust
    rng = random.Random(7)
    bad = []
    for i in range(1500):
        prev = None if rng.random() < 0.15 else (BASE if rng.random() < 0.6 else mk(rng))
        cand = prev if prev is not None and rng.random() < 0.05 else mk(rng)
        py = script_integrity.check(prev, cand)
        rs = ask({"op": "check_script", "previous": prev, "candidate": cand})
        a = (py["verdict"], sorted(f["code"] for f in py["findings"]), py["candidate_sha256"], py["sri"])
        b = (rs["verdict"], sorted(f["code"] for f in rs["findings"]), rs["candidate_sha256"], rs["sri"])
        if a != b:
            bad.append({"i": i, "py": a[:2], "rust": b[:2], "cand": cand[:200]})
    assert not bad, json.dumps(bad[:3], indent=1, ensure_ascii=False)


def test_gates_agree(rust):
    ask, auth, appr = rust
    rng = random.Random(11)
    t = [5_000_000.0]
    gp = GatePolicy.from_dict(json.loads((ROOT / "policies/default.json").read_text())["change_gates"])
    py = ChangeGate(gp, auth.public_key, {n: s.public_key for n, s in appr.items()}, now=lambda: t[0])
    iss = GrantIssuer(auth, 60, now=lambda: t[0])
    py.live["cdn://static/js/tag.js"] = BASE
    ask({"op": "gate_set_live", "resource": "cdn://static/js/tag.js", "content": BASE})
    bad = []
    for i in range(2000):
        t[0] += rng.choice([10, 600, 7200, 40000])
        kind = rng.choice(["artifact.publish", "repo.history_rewrite", "backup.delete", "file.write_bulk", "data.read"])
        content = None
        meta = {}
        if kind == "artifact.publish":
            content = mk(rng) if rng.random() < 0.6 else BASE + f"\n// build {i}\n"
            sha = script_integrity.check(None, content)["candidate_sha256"]
            meta = {"candidate_sha256": sha if rng.random() < 0.9 else "0" * 64}
            a = Action(rng.choice(["svc:ci-bot", "human:carol"]), kind, "cdn://static/js/tag.js", 1, ts=t[0], metadata=meta)
        elif kind == "repo.history_rewrite":
            a = Action(rng.choice(["human:carol", "human:bob"]), kind,
                       f"github://org/{rng.choice(['app', 'lib'])}/{rng.choice(['main', 'release/2', 'feature/9', 'x/y/z'])}",
                       rng.choice([1, 5, 12, 40]), ts=t[0])
        elif kind == "file.write_bulk":
            a = Action(rng.choice(["svc:backup", "human:bob"]), kind, "fs://prod/data", rng.choice([10, 3000, 7000, 20000]),
                       destination=rng.choice(["backup://vault", "backup://vault/x", None, "fs://prod/data"]), ts=t[0])
        else:
            a = Action("human:bob", kind, "backup://vault/nightly" if kind == "backup.delete" else "db://x", 5, ts=t[0])
        g = iss.issue(a, "d")
        sigs = []
        if rng.random() < 0.3:
            gid = json.loads(b64d(g.split(".")[0]))["gid"]
            names = rng.sample(list(appr), rng.choice([1, 2, 3]))
            sigs = [{"approver": n, "sig": b64e(appr[n].sign(gate_message(gid, a.fingerprint())))} for n in names]
        if rng.random() < 0.05:
            g = g[:-4] + "AAAA"
        rp = py.apply(g, a, sigs, content)
        rr = ask({"op": "gate", "grant": g, "action": a.to_dict(), "sigs": sigs, "content": content, "now": t[0]})
        if rp.ok != rr["ok"] or rp.reason.split(":")[0].split(" ")[0] != rr["reason"].split(":")[0].split(" ")[0]:
            bad.append({"i": i, "kind": kind, "py": [rp.ok, rp.reason], "rust": [rr["ok"], rr["reason"]]})
    assert not bad, json.dumps(bad[:4], indent=1)
