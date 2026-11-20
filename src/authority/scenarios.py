"""Synthetic organisation traffic with attacks modelled on the incidents in
"File 084 · Five Days" (13–17 Nov 2026), plus legitimate look-alikes.

This is synthetic data. It encodes the *shape* of each incident (which identity,
which actions, what volume, over what time) as reported, not real logs. Numbers
from the model trained on it describe performance on this simulation only.

Attack families:
  public_service_pivot  Fugaku: in through a public status page, 3 days inside, SSH keys taken
  bulk_exfil            La Poste: millions of records exported over weeks
  supply_chain_publish  Optimizely: a trusted vendor script replaced with a skimmer
  history_rewrite       PolinRider: Git history rewritten to hide malicious commits
  ransomware_staging    Healthcare ransomware: credential grab, backups deleted, mass encryption

Hard negatives (legitimate but unusual): key rotation, quarterly export, feature-branch
rebases, hotfix release at night, export to a newly onboarded partner, backup bursts,
status-page bursts during an incident.
"""

from __future__ import annotations

import random
from dataclasses import dataclass

from .actions import Action
from .features import DAY, HOUR

FAMILIES = (
    "public_service_pivot",
    "bulk_exfil",
    "supply_chain_publish",
    "history_rewrite",
    "ransomware_staging",
)


@dataclass
class Event:
    action: Action
    label: int  # 1 = malicious step
    family: str | None = None


def _at(day: int, hour: float, rng: random.Random, spread: float = 0.95) -> float:
    return day * DAY + hour * HOUR + rng.uniform(0, HOUR * spread)


def _rand_host(rng: random.Random) -> str:
    word = "".join(rng.choice("abcdefghijklmnopqrstuvwxyz") for _ in range(rng.randint(5, 9)))
    return rng.choice([f"https://{word}.net/u", f"https://cdn-{word}.com/x", f"s3://{word}-bkp", f"https://{word}.top/c"])


def benign_day(day: int, rng: random.Random) -> list[Event]:
    ev: list[Event] = []
    A = lambda *a, **k: ev.append(Event(Action(*a, **k), 0))  # noqa: E731
    weekday = day % 7 < 5

    # alice: analyst
    if weekday:
        for _ in range(rng.randint(3, 8)):
            A("human:alice", "data.read", "db://crm/customers/query", rng.randint(10, 500), ts=_at(day, rng.randint(9, 17), rng))
        if day % 7 == 2:
            A("human:alice", "data.export", "db://crm/customers", rng.randint(500, 2000),
              destination="s3://corp-reports/weekly", ts=_at(day, rng.randint(10, 16), rng))
        if rng.random() < 0.03:  # new partner onboarded: novel destination, legitimate
            A("human:alice", "data.export", "db://crm/customers", rng.randint(300, 1500),
              destination=f"s3://corp-partner-{rng.randint(1, 99)}/drop", ts=_at(day, rng.randint(10, 16), rng))

    # bob: SRE
    if weekday:
        for _ in range(rng.randint(1, 3)):
            A("human:bob", "secret.read", rng.choice(["vault://prod/db/password", "vault://prod/api/token"]),
              rng.randint(1, 2), ts=_at(day, rng.randint(8, 19), rng))
        if rng.random() < 0.3:
            A("human:bob", "process.exec", "proc://prod/ops/runbook", 1, ts=_at(day, rng.randint(9, 18), rng))
    if day % 30 == 15:  # monthly SSH key rotation: big but legitimate
        for _ in range(rng.randint(3, 6)):
            A("human:bob", "secret.read", "vault://prod/ssh/hosts", rng.randint(20, 80), ts=_at(day, rng.randint(10, 15), rng))
    if rng.random() < 0.1:  # on-call at night
        A("human:bob", "secret.read", "vault://prod/db/password", 1, ts=_at(day, rng.randint(1, 4), rng))

    # carol: developer
    if weekday:
        for _ in range(rng.randint(1, 4)):
            A("human:carol", "repo.push", f"github://org/app/feature/{rng.randint(1, 40)}", rng.randint(1, 5),
              ts=_at(day, rng.randint(9, 19), rng))
        if rng.random() < 0.15:
            A("human:carol", "repo.history_rewrite", f"github://org/app/feature/{rng.randint(1, 40)}",
              rng.randint(3, 15), ts=_at(day, rng.randint(10, 18), rng))

    # status page: public-facing service
    for h in range(24):
        A("svc:status-page", "data.read", "db://status/components", rng.randint(1, 20), ts=_at(day, h, rng))
        if h % 6 == 0:
            A("svc:status-page", "network.egress", "net://out", 1, destination="https://monitoring.corp.example/push",
              ts=_at(day, h, rng))
    if rng.random() < 0.05:  # incident traffic burst
        for _ in range(rng.randint(3, 8)):
            A("svc:status-page", "data.read", "db://status/components", rng.randint(200, 800),
              ts=_at(day, rng.randint(0, 23), rng))

    # export job: nightly, plus a bigger monthly export to the same place
    A("svc:export-job", "data.export", "db://crm/customers", rng.randint(5000, 9000),
      destination="s3://corp-warehouse/nightly", ts=_at(day, 2, rng))
    if day % 30 == 0:
        A("svc:export-job", "data.export", "db://crm/customers", rng.randint(30000, 45000),
          destination="s3://corp-warehouse/monthly", ts=_at(day, 3, rng))

    # CI bot: publishes the site script
    if weekday and rng.random() < 0.6:
        A("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=_at(day, rng.randint(10, 17), rng))
    if rng.random() < 0.05:  # night hotfix
        A("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=_at(day, rng.randint(21, 23), rng))

    # backup: nightly
    n = rng.randint(1000, 5000)
    A("svc:backup", "data.read", "fs://prod/data", n, ts=_at(day, 1, rng))
    A("svc:backup", "file.write_bulk", "backup://vault/nightly", n, destination="backup://vault", ts=_at(day, 1, rng))
    return ev


def attack(family: str, start_day: int, rng: random.Random) -> list[Event]:
    ev: list[Event] = []
    A = lambda *a, **k: ev.append(Event(Action(*a, **k), 1, family))  # noqa: E731
    quiet = rng.random() < 0.5  # low-and-slow variant
    d0 = start_day
    h0 = rng.uniform(0, 23)

    if family == "public_service_pivot":
        sid = "svc:status-page"
        t = d0 * DAY + h0 * HOUR
        for _ in range(rng.randint(2, 5)):
            t += rng.uniform(0.2, 3) * HOUR
            A(sid, "process.exec", "proc://status-page/sh", 1, ts=t)
        t += rng.uniform(1, 6) * HOUR
        A(sid, "data.read", "fs://login-node/etc/passwd", 1, ts=t)
        total, taken = rng.randint(1500, 4500), 0
        while taken < total and t < (d0 + 3) * DAY:
            chunk = min(total - taken, rng.randint(10, 40) if quiet else rng.randint(300, 1500))
            t += rng.uniform(0.5, 4) * HOUR if quiet else rng.uniform(2, 10) * HOUR
            A(sid, "secret.read", "fs://home/users/.ssh", chunk, ts=t)
            t += rng.uniform(60, 600)
            A(sid, "network.egress", "net://out", chunk, destination=_rand_host(rng), ts=t)
            taken += chunk

    elif family == "bulk_exfil":
        sid = rng.choice(["human:alice", "svc:export-job"])
        dest = _rand_host(rng)
        t = d0 * DAY + h0 * HOUR
        for _ in range(rng.randint(8, 40)):
            if quiet:
                chunk = rng.randint(1000, 2000) if sid == "human:alice" else rng.randint(5000, 9000)
                t += rng.uniform(1, 8) * HOUR
            else:
                chunk = rng.randint(100_000, 1_000_000)
                t += rng.uniform(4, 24) * HOUR
            A(sid, "data.export", "db://crm/customers", chunk, destination=dest, ts=t)

    elif family == "supply_chain_publish":
        variant = rng.choice(["odd_hour", "stolen_token", "blend_in"])
        if variant == "odd_hour":
            A("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=_at(d0, rng.randint(0, 5), rng))
        elif variant == "stolen_token":
            A("human:carol", "artifact.publish", "cdn://static/js/tag.js", 1, ts=_at(d0, rng.randint(0, 23), rng))
        else:  # indistinguishable by behaviour; only the script integrity check can catch it
            A("svc:ci-bot", "artifact.publish", "cdn://static/js/tag.js", 1, ts=_at(d0, rng.randint(10, 17), rng))

    elif family == "history_rewrite":
        t = d0 * DAY + h0 * HOUR
        for _ in range(rng.randint(2, 8)):
            t += rng.uniform(0.1, 2) * HOUR
            repo = rng.choice(["app", "lib-auth", "lib-crypto", "sdk-js", "infra"])
            branch = rng.choice(["main", "release/2.4", f"feature/{rng.randint(1, 40)}"])
            A("human:carol", "repo.history_rewrite", f"github://org/{repo}/{branch}", rng.randint(20, 200), ts=t)

    elif family == "ransomware_staging":
        sid = "human:bob"
        t = d0 * DAY + rng.uniform(0, 5) * HOUR  # night
        for _ in range(rng.randint(2, 6)):
            t += rng.uniform(300, 3600)
            A(sid, "secret.read", rng.choice(["vault://prod/db", "vault://prod/ssh/hosts", "vault://prod/admin"]),
              rng.randint(5, 30) if quiet else rng.randint(50, 200), ts=t)
        t += rng.uniform(300, 3600)
        A(sid, "backup.delete", "backup://vault/nightly", rng.randint(1, 60), ts=t)
        for _ in range(rng.randint(3, 10)):
            t += rng.uniform(60, 900)
            A(sid, "file.write_bulk", "fs://prod/data", rng.randint(2000, 50000), ts=t)
    else:
        raise ValueError(family)
    return ev


def world(seed: int, family: str | None, days: int = 60, attack_from: int = 32) -> list[Event]:
    """One simulated org: `days` of benign traffic, with at most one attack after day `attack_from`."""
    rng = random.Random(seed)
    events: list[Event] = []
    for d in range(days):
        events.extend(benign_day(d, rng))
    if family:
        events.extend(attack(family, rng.randint(attack_from, days - 4), rng))
    events.sort(key=lambda e: e.action.ts)
    return events
