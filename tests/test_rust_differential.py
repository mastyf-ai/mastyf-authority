"""Differential test: the Rust key service must make the same decision as the Python one on
thousands of random requests (valid, forged, expired, replayed, wrong action, odd Unicode,
over budget, with and without approver overruns). Any disagreement is a bug in one of them."""

import json
import random
import subprocess
from pathlib import Path

import pytest

from authority.actions import Action
from authority.budgets import BudgetPolicy, KeyService, overrun_message
from authority.crypto import Signer, b64d, b64e
from authority.grants import GrantIssuer

ROOT = Path(__file__).resolve().parents[1]
BIN = ROOT / "rust/keyservice/target/release/mastyf-keyservice"

pytestmark = pytest.mark.skipif(not BIN.exists(), reason="build rust/keyservice first (cargo build --release)")

IDS = ["human:alice", "human:bob", "svc:export-job", "svc:status-page", "svc:backup", "human:zoë", "x"]
TYPES = ["data.read", "data.export", "secret.read", "repo.push"]
RES = ["db://crm/customers/query", "db://crm/customers", "vault://prod/ssh/hosts", "vault://prod/db",
       "fs://home/users/.ssh", "fs://prod/data", "db://status/components", "db://other", "db://crm/customers/ü"]
DESTS = [None, "s3://corp-warehouse/nightly", "S3://Corp-Warehouse/x", "https://Evil.net/u", "s3://corp-reports/w",
         "s3://corp-partner-9/d", "host.Example", "https://ünï.net/"]


def test_python_and_rust_agree(tmp_path):
    run_diff(tmp_path, json.loads((ROOT / "policies/default.json").read_text()), novelty=False)


def test_python_and_rust_agree_with_novelty_limits(tmp_path):
    pol = json.loads((ROOT / "policies/default.json").read_text())
    pol["data_budgets"]["novelty"] = {"human:alice": {"crm.customer": {"new_per_day": 60, "distinct_30d": 150}},
                                      "human:bob": {"ssh.key": {"new_per_day": 5, "distinct_30d": 20}}}
    pol["data_budgets"]["canary_records"] = ["c24?", "k39"]  # rare bait ids inside the pools
    run_diff(tmp_path, pol, novelty=True)


def test_python_and_rust_agree_with_weekly_limits(tmp_path):
    pol = json.loads((ROOT / "policies/default.json").read_text())
    pol["data_budgets"]["long_budgets"] = {
        "human:alice": {"crm.customer": {"7d": 1200, "28d": 3000}, "crm.customer@s3://corp-reports": {"7d": 900}},
        "human:bob": {"secret": {"28d": 12}, "ssh.key": {"7d": 15, "28d": 30}},
        "svc:export-job": {"crm.customer@s3://corp-warehouse": {"7d": 50000, "28d": 120000}}}
    assert run_diff(tmp_path, pol, novelty=False) > 0  # the weekly limits were exercised (and agreed)


def run_diff(tmp_path, pol, novelty):
    rng = random.Random(1234 + novelty)
    (tmp_path / "policy.json").write_text(json.dumps(pol))
    auth = Signer.generate()
    appr = {n: Signer.generate() for n in ("human:bob", "human:dana", "human:erin")}
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    (tmp_path / "appr.json").write_text(json.dumps({n: s.public_pem() for n, s in appr.items()}))
    t = [1_000_000.0]
    clock = lambda: t[0]  # noqa: E731
    py = KeyService(BudgetPolicy.from_dict(pol["data_budgets"]), auth.public_key,
                    {n: s.public_key for n, s in appr.items()}, now=clock)
    iss = GrantIssuer(auth, 60, now=clock)
    rogue = GrantIssuer(Signer.generate(), 60, now=clock)
    proc = subprocess.Popen([str(BIN), "--policy", str(tmp_path / "policy.json"), "--authority-key",
                             str(tmp_path / "auth.pem"), "--approvers", str(tmp_path / "appr.json"), "--fake-clock"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    pool = {"crm.customer": [f"c{i}" for i in range(250)], "ssh.key": [f"k{i}" for i in range(40)]}
    if novelty:  # both services hold the same record keys
        for cls, ids in pool.items():
            for rid in ids:
                py.new_record_key(rid, cls)
                proc.stdin.write(json.dumps({"op": "new_record_key", "record_id": rid, "class": cls}) + "\n")
                proc.stdin.flush()
                assert json.loads(proc.stdout.readline())["ok"]
    used_grants: list[tuple[str, Action]] = []
    mismatches, n = [], 3000
    long_hits = 0
    for i in range(n):
        t[0] += rng.choice([1, 30, 600, 3600, 20000])
        a = Action(rng.choice(IDS), rng.choice(TYPES), rng.choice(RES), rng.choice([0, 1, 5, 40, 999, 3000, 9000, 25000]),
                   destination=rng.choice(DESTS), ts=t[0] + rng.choice([0, 86400 * 5]))  # caller ts must be ignored
        if novelty and rng.random() < 0.7:
            cls = rng.choice(list(pool))
            n = rng.choice([1, 3, 10, 25])
            ids = [rng.choice(pool[cls]) for _ in range(n)] if rng.random() < 0.9 else [f"zz{i}" for i in range(n)]
            a = Action(rng.choice(["human:alice", "human:bob"]), rng.choice(["data.read", "secret.read"]),
                       "db://crm/customers/query" if cls == "crm.customer" else "vault://prod/ssh/hosts",
                       n if rng.random() < 0.9 else n + 1, ts=t[0], metadata={"record_ids": ids})
        kind = rng.random()
        con = {"budget_factor": rng.choice([0.0, 0.25, 0.5, 1.0, 3.0])} if rng.random() < 0.2 else None
        if kind < 0.70:
            g = iss.issue(a, "d", con)
        elif kind < 0.78:
            g = rogue.issue(a, "d")  # wrong key
        elif kind < 0.84 and used_grants:
            g, _ = rng.choice(used_grants)  # replay
        elif kind < 0.90:
            other = Action(a.identity, a.action_type, a.resource, a.count + 1, destination=a.destination, ts=a.ts,
                           metadata=a.metadata)
            g = iss.issue(other, "d")  # grant for a different action
        elif kind < 0.95:
            g = iss.issue(a, "d")
            t[0] += 120  # expired by the time it is used
        else:
            g = rng.choice(["", "x.y", "a.b.c", "!!!.???", iss.issue(a, "d")[:-3] + "AAA"])
        overrun = None
        if rng.random() < 0.25 and "." in g:
            try:
                gid = json.loads(b64d(g.split(".")[0]))["gid"]
                names = rng.sample(list(appr), rng.choice([1, 2, 3]))
                amt = rng.choice([a.count, a.count + 10, 1])
                overrun = [{"approver": nm, "amount": amt, "sig": b64e(appr[nm].sign(overrun_message(gid, amt)))}
                           for nm in names]
            except Exception:  # noqa: BLE001
                overrun = None
        rp = py.release(g, a, overrun)
        req = {"op": "release", "grant": g, "action": a.to_dict(), "overrun": overrun or [], "now": t[0]}
        proc.stdin.write(json.dumps(req) + "\n")
        proc.stdin.flush()
        rr = json.loads(proc.stdout.readline())
        same = (rp.ok == rr["ok"] and (not rp.ok or rp.remaining == rr["remaining"])
                and rp.reason.split(":")[0] == rr["reason"].split(":")[0])
        if " per 7d" in rp.reason or " per 28d" in rp.reason:
            long_hits += 1
            same = same and rp.reason == rr["reason"]
        if not same:
            mismatches.append({"i": i, "action": a.to_dict(), "py": [rp.ok, rp.reason, rp.remaining],
                               "rust": [rr["ok"], rr["reason"], rr.get("remaining")]})
        used_grants.append((g, a))
    proc.stdin.close()
    proc.wait(timeout=10)
    assert not mismatches, json.dumps(mismatches[:5], indent=1, ensure_ascii=False)
    return long_hits


def test_weekly_limit_sequence_python_and_rust(tmp_path):
    """Taking the full daily budget every day stops at the weekly limit, in both services, and frees up
    again as the week rolls on."""
    pol = json.loads((ROOT / "policies/default.json").read_text())
    pol["data_budgets"]["long_budgets"] = {"human:alice": {"crm.customer": {"7d": 2500, "28d": 6000}}}
    (tmp_path / "policy.json").write_text(json.dumps(pol))
    auth = Signer.generate()
    (tmp_path / "auth.pem").write_text(auth.public_pem())
    (tmp_path / "appr.json").write_text("{}")
    t = [1_000_000.0]
    py = KeyService(BudgetPolicy.from_dict(pol["data_budgets"]), auth.public_key, {}, now=lambda: t[0])
    iss = GrantIssuer(auth, 60, now=lambda: t[0])
    proc = subprocess.Popen([str(BIN), "--policy", str(tmp_path / "policy.json"), "--authority-key",
                             str(tmp_path / "auth.pem"), "--approvers", str(tmp_path / "appr.json"), "--fake-clock"],
                            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, text=True)
    got = []
    for day in range(12):
        t[0] = 1_000_000.0 + day * 86400
        a = Action("human:alice", "data.read", "db://crm/customers/query", 1000, ts=t[0])
        g = iss.issue(a, "d")
        rp = py.release(g, a)
        proc.stdin.write(json.dumps({"op": "release", "grant": g, "action": a.to_dict(), "overrun": [], "now": t[0]}) + "\n")
        proc.stdin.flush()
        rr = json.loads(proc.stdout.readline())
        assert (rp.ok, rp.reason) == (rr["ok"], rr["reason"]), (day, rp, rr)
        got.append(rp.ok)
    proc.stdin.close()
    proc.wait(timeout=10)
    # 1000/day against 2500 per 7 days: two days pass, then refused until the first day leaves the window
    assert got[:3] == [True, True, False] and got[7] is True and sum(got) < 7
