"""authority train | replay | serve | audit-verify"""

from __future__ import annotations

import argparse
import json
import time
from pathlib import Path



def _enterprise(feature: str, module: str, licence_feature: str | None = None):
    """Import a Mastyf Authority Enterprise add-on, or exit with a clear message in the open edition.
    In the Enterprise package, also check that the licence includes `licence_feature`."""
    import importlib
    try:
        mod = importlib.import_module(f"authority.{module}")
    except ModuleNotFoundError as e:
        if e.name != f"authority.{module}":
            raise
        raise SystemExit(f"{feature} is part of Mastyf Authority Enterprise (https://www.mastyf.ai/authority).")
    if licence_feature:
        importlib.import_module("authority.licence").require(licence_feature, feature)
    return mod


def _connector_feature(source: str) -> str:
    return "authority_connector_github" if source in ("github", "github-security") else "authority_connectors"


def _model_path(name: str) -> str:
    """`production` means the licensed production model shipped inside the Enterprise package."""
    if name != "production":
        return name
    from importlib import resources
    p = resources.files("authority") / "models" / "production.json"
    if not p.is_file():
        raise SystemExit("The production model is part of Mastyf Authority Enterprise (https://www.mastyf.ai/authority).")
    return str(p)


def _load_model(name: str):
    import json as _json
    from .model import RiskModel
    path = _model_path(name)
    if not Path(path).exists():
        return None
    with open(path) as f:
        head = f.read(4096)
    if '"licence_feature"' in head or name == "production":
        stamp = _json.loads(Path(path).read_text()).get("licence_feature", "authority_model")
        _enterprise("The production risk model", "licence")
        import importlib
        importlib.import_module("authority.licence").require(stamp, "The production risk model")
    return RiskModel.load(path)

def _record_ok(rec: dict, public_key) -> bool:
    import hashlib

    from .audit import _canon
    from .crypto import b64d, verify
    body = {k: rec[k] for k in ("seq", "ts", "prev", "event")}
    return hashlib.sha256(_canon(body)).hexdigest() == rec["hash"] and verify(public_key, b64d(rec["sig"]),
                                                                                rec["hash"].encode())


def _snapshot_now(auth, signer, path) -> dict | None:
    """Snapshot the engine's state together with the audit position it reflects, then record it in the log."""
    from . import snapshot as snap
    with auth._lock:
        auth.audit.flush()  # the records the snapshot claims to cover are on disk first
        seq, head = auth.audit.position
        if seq == 0:
            return None
        info = snap.write(path, auth, signer, seq, head, auth.now())
        auth.last_snapshot_ts = time.time()
    if auth.role == "active":  # a standby's log must stay an exact copy of the active engine's
        auth.audit.append({"type": "snapshot", "covers_seq": seq, "sha256": info["sha256"], "bytes": info["bytes"]})
    return info


def _start_snapshots(auth, signer, path) -> None:
    import os
    import threading
    every_s = float(os.environ.get("AUTHORITY_SNAPSHOT_SECONDS", "300"))
    every_n = int(os.environ.get("AUTHORITY_SNAPSHOT_RECORDS", "250000"))

    def loop():
        last_t, last_seq = time.time(), auth.audit.position[0]
        while True:
            time.sleep(5)
            seq = auth.audit.position[0]
            if seq > last_seq + 1 and (seq - last_seq >= every_n or time.time() - last_t >= every_s):
                try:
                    _snapshot_now(auth, signer, path)
                except OSError as e:  # a full disk must not stop decisions; the audit log is still complete
                    print(f"WARNING: snapshot failed: {e}", flush=True)
                last_t, last_seq = time.time(), auth.audit.position[0]
    threading.Thread(target=loop, daemon=True, name="snapshots").start()


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
    s.add_argument("--role", choices=["active", "standby", "auto"], default="active",
                   help="standby: follow --follow and take over when a gateway promotes it (failover.py); auto: "
                        "standby if another engine is active, else active only for ordinal 0 (AUTHORITY_ORDINAL "
                        "or the hostname's -N suffix, as in a Kubernetes StatefulSet)")
    s.add_argument("--follow", help="the active engine's gateway URL (https://...), for --role standby")
    s.add_argument("--peer", help="the other engine's gateway URL; an active engine that sees a newer active "
                                 "peer stops deciding (it was replaced during a failover)")

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
                    else list(_enterprise("Log connectors (CloudTrail, Okta, GitHub)", "connectors",
                                         _connector_feature(a.source)).read(a.source, f)))
        pol = json.loads(Path(a.policy).read_text())
        classes = pol["data_budgets"]["classes"]
        if a.teams:
            from .learn import learn_teams
            team_map = _enterprise("Team learning from the identity provider", "scim", "authority_scim").team_map
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
        _enterprise("Shadow mode", "shadow", "authority_shadow")
        if a.source != "actions":
            _enterprise("Log connectors (CloudTrail, Okta, GitHub)", "connectors", _connector_feature(a.source))
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
        model = _load_model(a.model)
        import os

        from cryptography.hazmat.primitives.serialization import load_pem_public_key
        keys_path = os.environ.get("AUTHORITY_APPROVER_KEYS", "")
        approver_keys = {k: load_pem_public_key(v.encode())
                         for k, v in (json.loads(Path(keys_path).read_text()) if keys_path else {}).items()}
        from . import snapshot as snap
        from .audit import GENESIS, iter_records, record_at, repair_tail, segments, verify_log
        log_path = Path(a.state) / "audit.jsonl"
        snap_path = Path(a.state) / "snapshot.json"
        cut = repair_tail(log_path)
        if cut:
            print(f"WARNING: removed a half-written final audit record ({cut} bytes) left by a power cut", flush=True)
        try:
            body = snap.read(snap_path, signer.public_key)
        except (ValueError, KeyError) as e:
            raise SystemExit(f"state snapshot failed verification ({e}): refusing to start. If you know why, move "
                             f"{snap_path} away and the engine rebuilds from the full audit log.")
        from_seq, from_hash = 0, GENESIS
        if body and body["seq"]:
            anchor = record_at(log_path, body["seq"])
            if anchor is None or anchor["hash"] != body["head"] or not _record_ok(anchor, signer.public_key):
                raise SystemExit("state snapshot does not match the audit log: refusing to start")
            from_seq, from_hash = body["seq"], body["head"]
        if segments(log_path):
            t0 = time.time()
            ok, msg = verify_log(log_path, signer.public_key, from_seq, from_hash)
            if not ok:
                raise SystemExit(f"audit log failed verification ({msg}): refusing to start with tampered state")
            print(f"audit log after the snapshot verified: {msg} ({time.time() - t0:.1f} s)", flush=True)
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
        t0 = time.time()
        if body:
            snap.load(auth, body["state"])
        n = auth.restore(iter_records(log_path, after_seq=from_seq))
        if body or n:
            print(f"restored state: snapshot at record {from_seq} + {n} later records ({time.time() - t0:.1f} s)",
                  flush=True)
        _start_snapshots(auth, signer, snap_path)
        from .failover import Follower, choose_role, set_aside, watch_peer
        auth.follower = None
        replica_key = os.environ.get("AUTHORITY_REPLICA_KEY", "")
        peer_ca = os.environ.get("AUTHORITY_PEER_CA") or None
        if a.role == "auto":
            import socket as _socket
            ordinal = os.environ.get("AUTHORITY_ORDINAL") or _socket.gethostname().rsplit("-", 1)[-1]
            a.role = choose_role(a.follow or a.peer, ordinal, peer_ca)
            print(f"role auto (ordinal {ordinal}): starting {a.role}", flush=True)
        if a.role == "standby":
            if not (a.follow and replica_key):
                raise SystemExit("--role standby needs --follow URL and AUTHORITY_REPLICA_KEY")
            auth.role = "standby"
            auth.follower = Follower(auth, a.follow, replica_key, signer.public_key, peer_ca)

            def diverged(why):
                where = set_aside(a.state, why)
                print(f"DIVERGED: this engine's log has records the active engine never received ({why}). "
                      f"Moved them to {where}; restarting to resync.", flush=True)
                os._exit(3)  # a supervisor (systemd, Kubernetes) restarts it with an empty state
            auth.follower.on_diverged = diverged
            auth.follower.start()
            print(f"standby: following {a.follow} from record {auth.audit.position[0]}", flush=True)
        if a.peer:
            def superseded(h):
                if auth.role == "active":
                    auth.role = "fenced"
                    auth._alert("engine_superseded", peer_epoch=h.get("epoch"), own_epoch=auth.issuer.epoch)
                    print(f"FENCED: peer is active at epoch {h.get('epoch')} > {auth.issuer.epoch}; this engine "
                          f"no longer decides. Rebuild it as a standby (fresh state directory).", flush=True)
            watch_peer(auth, a.peer, replica_key, peer_ca, superseded)
        if devices is not None:
            def is_approver(name):
                r = policy.identities.get(name)
                return bool(r and r.approver and r.kind == "human")
            enroll = Enrollment(devices, approver_keys=approver_keys, audit=auth.audit.append,
                                alert=lambda who, text: auth._alert("device_change", identity=who, detail=text),
                                save_path=dev_path, is_approver=is_approver)
        import signal as _signal

        def _stop(*_):
            raise KeyboardInterrupt
        _signal.signal(_signal.SIGTERM, _stop)
        try:
            serve(auth, a.host, a.port, enroll)
        except KeyboardInterrupt:
            pass
        finally:
            _snapshot_now(auth, signer, snap_path)
            auth.audit.close()
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
