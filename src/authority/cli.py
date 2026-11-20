"""authority train | replay | serve | audit-verify"""

from __future__ import annotations

import argparse
import json
from pathlib import Path



def _enterprise(feature: str, module: str):
    """Import a Mastyf Authority Enterprise add-on, or exit with a clear message in the open edition."""
    import importlib
    try:
        return importlib.import_module(f"authority.{module}")
    except ModuleNotFoundError as e:
        if e.name != f"authority.{module}":
            raise
        raise SystemExit(f"{feature} is part of Mastyf Authority Enterprise (https://www.mastyf.ai/authority).")

def main(argv: list[str] | None = None) -> None:
    ap = argparse.ArgumentParser(prog="authority")
    sub = ap.add_subparsers(dest="cmd", required=True)

    t = sub.add_parser("train", help="generate synthetic incidents, train the risk model, evaluate")
    t.add_argument("--policy", default="policies/default.json")
    t.add_argument("--out", default="artifacts")
    t.add_argument("--train-worlds", type=int, default=100)
    t.add_argument("--test-worlds", type=int, default=50)

    r = sub.add_parser("replay", help="run the incidents end to end through the authority")
    r.add_argument("--policy", default="policies/default.json")
    r.add_argument("--model", default="artifacts/risk_model.json")
    r.add_argument("--no-model", action="store_true")
    r.add_argument("--out", default="artifacts")
    r.add_argument("--per-family", type=int, default=6)

    c = sub.add_parser("ceiling", help="worst-case damage of a compromise, computed from the policy")
    c.add_argument("--policy", default="policies/default.json")
    c.add_argument("--k", type=int, default=1, help="identities compromised together")
    c.add_argument("--devices-stolen", action="store_true", help="attacker also controls their registered devices")
    c.add_argument("--case-records", type=int, default=None, help="most records on one person's active cases")
    c.add_argument("--json", action="store_true")

    b = sub.add_parser("bounded", help="measure data budgets: full system and worst case (authority bypassed)")
    b.add_argument("--policy", default="policies/default.json")
    b.add_argument("--model", default="artifacts/risk_model.json")
    b.add_argument("--out", default="artifacts")
    b.add_argument("--per-family", type=int, default=6)
    b.add_argument("--learned", action="store_true", help="learn budgets from the warmup period")

    t2 = sub.add_parser("redteam", help="adaptive attacker that searches for the best evasion strategy")
    t2.add_argument("--policy", default="policies/default.json")
    t2.add_argument("--model", default="artifacts/risk_model.json")
    t2.add_argument("--out", default="artifacts")
    t2.add_argument("--budget", type=int, default=120, help="strategies to try")
    t2.add_argument("--hand-set", action="store_true", help="use hand-set budgets instead of learned")
    t2.add_argument("--novelty", action="store_true", help="enable new-record / distinct-record limits")

    ap_ = sub.add_parser("approver", help="approver tool (runs on the approver's machine)")
    ap_.add_argument("op", choices=["keygen", "pending", "approve", "deny"])
    ap_.add_argument("--out", default="~/.mastyf/approver.pem")
    ap_.add_argument("--url", default="http://127.0.0.1:8740")
    ap_.add_argument("--api-key", default="")
    ap_.add_argument("--key", default="~/.mastyf/approver.pem")
    ap_.add_argument("--as", dest="approver", default="")
    ap_.add_argument("--fingerprint", default="")
    ap_.add_argument("--requester", default="")
    ap_.add_argument("--reason", default="")

    ln = sub.add_parser("learn", help="learn data and change-gate budgets from a clean period of real logs")
    ln.add_argument("--source", choices=["cloudtrail", "okta", "github", "github-security", "actions"], required=True)
    ln.add_argument("--input", required=True, help="JSON lines file (actions, or raw log records)")
    ln.add_argument("--policy", default="policies/default.json")
    ln.add_argument("--out", required=True, help="where to write the policy with learned budgets")
    ln.add_argument("--teams", help="JSON {identity: [team, ...]} or a SCIM directory.json: learn per-team limits")

    pc = sub.add_parser("policy", help="policy tools")
    pcs = pc.add_subparsers(dest="pcmd", required=True)
    cmp_ = pcs.add_parser("compile", help="expand teams into the per-identity policy the key service reads")
    cmp_.add_argument("input")
    cmp_.add_argument("output")
    cmp_.add_argument("--directory", help="SCIM directory.json (identity-provider groups)")

    sh = sub.add_parser("shadow", help="pilot mode: score real logs, enforce nothing, write a report")
    sh.add_argument("--source", choices=["cloudtrail", "okta", "github", "github-security", "actions"], required=True)
    sh.add_argument("--input", required=True)
    sh.add_argument("--policy", default="policies/default.json")
    sh.add_argument("--model", default="artifacts/risk_model.json")
    sh.add_argument("--learn-days", type=int, default=30)
    sh.add_argument("--out", default="shadow_report.json")

    s = sub.add_parser("serve", help="run the HTTP authority")
    s.add_argument("--policy", default="policies/default.json")
    s.add_argument("--model", default="artifacts/risk_model.json")
    s.add_argument("--state", default="state")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8740)

    v = sub.add_parser("audit-verify", help="verify the audit log chain and signatures")
    v.add_argument("--state", default="state")

    a = ap.parse_args(argv)
    if a.cmd == "train":
        from .evaluate import run
        run(a.policy, a.out, a.train_worlds, a.test_worlds)
    elif a.cmd == "replay":
        from .replay import run
        summary = run(a.policy, None if a.no_model else a.model, a.out, a.per_family)
        print(json.dumps(summary, indent=2))
    elif a.cmd == "ceiling":
        from .ceiling import Threat, compute, report, to_json
        res = compute(json.loads(Path(a.policy).read_text()),
                      Threat(k=a.k, devices_stolen=a.devices_stolen, case_records=a.case_records))
        print(to_json(res) if a.json else report(res))
    elif a.cmd == "bounded":
        from .bounded import run
        run(a.policy, a.model, a.out, a.per_family, learned=a.learned)
    elif a.cmd == "redteam":
        from .redteam import search
        r = search(a.policy, a.model, a.out, a.budget, learned=not a.hand_set, novelty=a.novelty)
        print(json.dumps({k: r[k] for k in ("best_strategy", "best_stolen_min_of_2", "best_runs")}, indent=2))
    elif a.cmd == "approver":
        from . import approver as A
        if a.op == "keygen":
            print(A.keygen(a.out))
        elif a.op == "pending":
            print(A.show(A.pending(a.url, a.api_key)))
        elif a.op == "approve":
            print(json.dumps(A.approve(a.url, a.api_key, a.key, a.approver, a.fingerprint, a.requester, a.reason)))
        else:
            print(json.dumps(A.deny(a.url, a.api_key, a.approver, a.fingerprint, a.reason)))
    elif a.cmd == "learn":
        from .actions import Action
        from .learn import learn_data_budgets, learn_gate_budgets
        with open(a.input) as f:
            acts = ([Action.from_dict(json.loads(x)) for x in f if x.strip()] if a.source == "actions"
                    else list(_enterprise("Log connectors (CloudTrail, Okta, GitHub)", "connectors").read(a.source, f)))
        pol = json.loads(Path(a.policy).read_text())
        classes = pol["data_budgets"]["classes"]
        if a.teams:
            from .learn import learn_teams
            team_map = _enterprise("Team learning from the identity provider", "scim").team_map
            team_of = team_map(json.loads(Path(a.teams).read_text()), pol.get("teams", {}))
            learned = learn_teams(acts, classes, team_of)
            for t, spec in learned.items():
                cur = pol.setdefault("teams", {}).setdefault(t, {})
                cur.update(spec)
            Path(a.out).write_text(json.dumps(pol, indent=2))
            print(f"learned limits for {len(learned)} teams from {len(acts)} actions -> {a.out}")
            return
        pol["data_budgets"]["budgets"] = learn_data_budgets(acts, classes)
        g = learn_gate_budgets(acts)
        pol.setdefault("change_gates", {}).update(g)
        pol["version"] = pol.get("version", "") + "+learned"
        Path(a.out).write_text(json.dumps(pol, indent=2))
        print(f"learned budgets for {len(pol['data_budgets']['budgets'])} identities from {len(acts)} actions -> {a.out}")
    elif a.cmd == "shadow":
        shadow_main = _enterprise("Shadow mode", "shadow").main
        rep = shadow_main(a.source, a.input, a.policy, a.model, a.out, a.learn_days)
        print(json.dumps({k: rep[k] for k in ("actions_learned_from", "actions_scored", "verdicts",
                                               "would_interrupt_per_day")}, indent=2))
    elif a.cmd == "serve":
        from .audit import AuditLog
        from .crypto import Signer
        from .engine import Authority
        from .grants import GrantIssuer
        from .model import RiskModel
        from .policy import Policy
        from .server import serve
        policy = Policy.load(a.policy)
        signer = Signer.load_or_create(Path(a.state) / "signing_key.pem")
        model = RiskModel.load(a.model) if Path(a.model).exists() else None
        import os

        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        keys_path = os.environ.get("AUTHORITY_APPROVER_KEYS", "")
        approver_keys = {k: load_pem_public_key(v.encode())
                         for k, v in (json.loads(Path(keys_path).read_text()) if keys_path else {}).items()}
        from .audit import verify_log
        log_path = Path(a.state) / "audit.jsonl"
        records = []
        if log_path.exists():
            ok, msg = verify_log(log_path, signer.public_key)
            if not ok:
                raise SystemExit(f"audit log failed verification ({msg}): refusing to start with tampered state")
            records = [json.loads(x) for x in log_path.read_text().splitlines() if x.strip()]
        devices, enroll = None, None
        dev_path = os.environ.get("AUTHORITY_DEVICES", "")  # same file the key service reads (--devices)
        if dev_path:
            from .binding import DeviceRegistry
            from .enroll import Enrollment
            rp = os.environ.get("AUTHORITY_RP_ID", "")
            if not rp:
                raise SystemExit("AUTHORITY_RP_ID (the passkey domain, e.g. authority.corp.example) is required")
            devices = (DeviceRegistry.from_json(json.loads(Path(dev_path).read_text())) if Path(dev_path).exists()
                       else DeviceRegistry(rp_id=rp))
            devices.origin = os.environ.get("AUTHORITY_ORIGIN", f"https://{rp}")
        auth = Authority(policy, GrantIssuer(signer, policy.grant_ttl_seconds),
                         AuditLog(log_path, signer), model=model, approver_keys=approver_keys, devices=devices)
        auth.policy_source = json.loads(Path(a.policy).read_text())  # teams recompile on directory changes
        if records:
            print(f"restored state from {auth.restore(records)} audit records (chain verified)", flush=True)
        if devices is not None:
            def is_approver(name):
                r = policy.identities.get(name)
                return bool(r and r.approver and r.kind == "human")
            enroll = Enrollment(devices, approver_keys=approver_keys, audit=auth.audit.append,
                                alert=lambda who, text: auth._alert("device_change", identity=who, detail=text),
                                save_path=dev_path, is_approver=is_approver)
        serve(auth, a.host, a.port, enroll)
    elif a.cmd == "policy" and a.pcmd == "compile":
        from .teams import expand
        d = json.loads(Path(a.directory).read_text()) if a.directory else None
        out = expand(json.loads(Path(a.input).read_text()), d)
        Path(a.output).write_text(json.dumps(out, indent=2))
        print(f"compiled {len(out.get('_compiled_from_teams', []))} teams -> {len(out.get('identities', {}))} identities -> {a.output}")
    elif a.cmd == "audit-verify":
        from .audit import verify_log
        from .crypto import Signer
        key = Path(a.state) / "signing_key.pem"
        if not key.exists():
            raise SystemExit(f"no signing key at {key}")
        signer = Signer.load_or_create(key)
        ok, msg = verify_log(Path(a.state) / "audit.jsonl", signer.public_key)
        print(("OK: " if ok else "FAILED: ") + msg)
        raise SystemExit(0 if ok else 1)


if __name__ == "__main__":
    main()
