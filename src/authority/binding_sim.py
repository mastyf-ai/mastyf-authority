"""Measure device + purpose binding against a stolen login (worst case: authority bypassed, every
request carries a valid grant; only the key service decides).

Alice: book of 3,000 customers; each workday 2 new cases of 10 of her customers, each open 3 days;
reads her case records and ~2 one-off lookups outside cases per day. 60 days.

Attackers with alice's login:
  A  stolen password / session / API token, used from the attacker's machine
  B  malware on alice's own laptop (can use the device key while the laptop is on)
"""

from __future__ import annotations

import json
import random

from .actions import Action
from .binding import CaseRegistry, Device, DeviceRegistry, case_message
from .budgets import BudgetPolicy, KeyService
from .crypto import Signer, b64d, b64e
from .features import DAY
from .grants import GrantIssuer

DAYS = 60
BOOK = 3000
N = 1_000_000


def run(seed: int = 0, purpose: bool = True, device: bool = True, outside_allowance: int = 5) -> dict:
    rng = random.Random(seed)
    t = [0.0]
    clock = lambda: t[0]  # noqa: E731
    pol = {"classes": {"crm.customer": ["db://crm/customers*"]},
           "budgets": {"human:alice": {"crm.customer": 100_000}}, "canary_records": ["c*007"]}
    if device:
        pol["device_bound"] = ["human:*"]
    if purpose:
        pol["purpose_bound"] = {"human:alice": ["crm.customer"]}
    auth, case_sys = Signer.generate(), Signer.generate()
    devs = DeviceRegistry()
    laptop = Device()
    devs.register("human:alice", "alice-mbp", laptop.sign_public, laptop.kex_public)
    cases = CaseRegistry(case_sys.public_key, now=clock, outside_allowance=outside_allowance)
    ks = KeyService(BudgetPolicy.from_dict(pol), auth.public_key, {}, now=clock, custody=False,
                    devices=devs, cases=cases)
    iss = GrantIssuer(auth, 60, now=clock)
    book = [f"c{x}" for x in rng.sample(range(1000, N), BOOK * 2) if x % 1000 != 7][:BOOK]

    def req(who_ids: list[str], dev):
        a = Action("human:alice", "data.read", "db://crm/customers/query", len(who_ids), ts=t[0],
                   metadata={"record_ids": who_ids})
        g = iss.issue(a, "d")
        meta = {"record_ids": who_ids}
        if dev is not None:
            gid = json.loads(b64d(g.split(".")[0]))["gid"]
            meta.update(device_id="alice-mbp", device_proof=dev.prove(gid, a.fingerprint()))
        return ks.release(g, Action("human:alice", "data.read", "db://crm/customers/query", len(who_ids),
                                    ts=t[0], metadata=meta))

    stolen = {"A": set(), "B": set()}
    refused_legit = 0
    case_no = 0
    for day in range(DAYS):
        weekday = day % 7 < 5
        t[0] = day * DAY + 9 * 3600
        if weekday:
            for _ in range(2):
                case_no += 1
                recs = rng.sample(book, 10)
                exp = t[0] + 3 * DAY
                cases.assign(f"case-{case_no}", "human:alice", recs, exp,
                             b64e(case_sys.sign(case_message(f"case-{case_no}", "human:alice", recs, exp))))
            active = sorted(cases.allowed("human:alice"))
            # alice's real work
            for _ in range(4):
                t[0] += 1800
                ids = rng.sample(active, min(5, len(active)))
                if not req(ids, laptop).ok:
                    refused_legit += 1
            t[0] += 600
            if not req(rng.sample(book, 2), laptop).ok:  # one-off lookups outside her cases
                refused_legit += 1
        # attacker A: stolen session from its own machine, every evening
        t[0] = day * DAY + 20 * 3600
        target = rng.sample(book, 50)
        r = req(target, None)
        if r.ok:
            stolen["A"].update(target)
        # attacker B: malware on the laptop, every night: all active case records + max outside lookups
        t[0] = day * DAY + 23 * 3600
        active = sorted(cases.allowed("human:alice"))
        if active:
            r = req(active, laptop)
            if r.ok:
                stolen["B"].update(active)
        grab = rng.sample(book, 200)  # greedy: try to pull more of her book in one go
        if req(grab, laptop).ok:
            stolen["B"].update(grab)
        for _ in range(outside_allowance):
            x = [rng.choice(book)]
            if req(x, laptop).ok:
                stolen["B"].update(x)
    return {"purpose": purpose, "device": device, "A_stolen": len(stolen["A"]), "B_stolen": len(stolen["B"]),
            "B_share_of_book": round(len(stolen["B"]) / BOOK, 3), "legit_refused": refused_legit,
            "cases_assigned": case_no}


if __name__ == "__main__":
    for purpose, device in [(False, False), (False, True), (True, True)]:
        print(json.dumps(run(1, purpose=purpose, device=device)))
