"""Stream GH Archive (public GitHub activity, https://www.gharchive.org) and keep only the gated actions of
real companies' GitHub organisations. Nothing but the filtered events is stored.

  python -I tools/gha_fetch.py 2026-10-01 30 datasets/gha     (start day, days, output dir)
"""

from __future__ import annotations

import datetime as dt
import gzip
import io
import json
import subprocess
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

# GitHub organisations owned by companies (their employees do most of the work in them)
ORGS = {
    "microsoft", "Azure", "aws", "awslabs", "aws-samples", "google", "GoogleCloudPlatform", "elastic", "grafana",
    "hashicorp", "cloudflare", "getsentry", "vercel", "supabase", "PostHog", "mozilla", "github", "Shopify",
    "stripe", "DataDog", "confluentinc", "mongodb", "redis", "openshift", "redhat-developer", "canonical",
    "airbytehq", "temporalio", "hmcts", "giantswarm", "dotnet", "facebook", "netflix", "Netflix", "uber", "airbnb",
    "docker", "gravitational", "tailscale", "snowflakedb", "databricks", "cockroachdb", "pingcap", "chainguard-dev",
    "SAP", "IBM", "oracle", "nvidia", "NVIDIA", "intel", "Adyen", "zalando", "spotify", "linkedin", "twilio",
}
KEEP = {"PushEvent", "CreateEvent", "DeleteEvent", "PullRequestEvent", "ReleaseEvent", "MemberEvent", "PublicEvent"}


def fetch_hour(day: dt.date, hour: int, out: Path) -> tuple[str, int]:
    name = f"{day.isoformat()}-{hour}"
    dest = out / f"{name}.jsonl.gz"
    if dest.exists():
        return name, -1
    for _ in range(4):
        r = subprocess.run(["curl", "-sf", "--max-time", "300", f"https://data.gharchive.org/{name}.json.gz"],
                           capture_output=True)
        if r.returncode == 0:
            break
    else:
        return name, 0
    kept = []
    try:
        with gzip.open(io.BytesIO(r.stdout), "rt", errors="replace") as f:
            for line in f:
                if '"org"' not in line:
                    continue
                e = json.loads(line)
                if e.get("type") in KEEP and (e.get("org") or {}).get("login") in ORGS:
                    p = e.get("payload") or {}
                    kept.append({"t": e["created_at"], "type": e["type"], "actor": e["actor"]["login"],
                                 "org": e["org"]["login"], "repo": e["repo"]["name"],
                                 "p": {k: p.get(k) for k in ("ref", "ref_type", "size", "action", "forced", "distinct_size")},
                                 "merged": ((p.get("pull_request") or {}).get("merged")),
                                 "base": ((p.get("pull_request") or {}).get("base") or {}).get("ref")})
    except (OSError, EOFError, ValueError):
        return name, 0
    tmp = dest.with_suffix(".tmp")
    with gzip.open(tmp, "wt") as g:
        for k in kept:
            g.write(json.dumps(k) + "\n")
    tmp.rename(dest)
    return name, len(kept)


def main() -> None:
    start, days, out = dt.date.fromisoformat(sys.argv[1]), int(sys.argv[2]), Path(sys.argv[3])
    out.mkdir(parents=True, exist_ok=True)
    jobs = [(start + dt.timedelta(days=d), h) for d in range(days) for h in range(24)]
    total = failed = 0
    with ThreadPoolExecutor(12) as ex:
        for i, (name, n) in enumerate(ex.map(lambda j: fetch_hour(j[0], j[1], out), jobs)):
            if n == 0:
                failed += 1
            total += max(n, 0)
            if i % 48 == 0:
                print(f"{i}/{len(jobs)} hours, {total:,} events kept, {failed} failed", flush=True)
    print(f"done: {len(jobs)} hours, {total:,} events kept, {failed} hours failed", flush=True)


if __name__ == "__main__":
    main()
