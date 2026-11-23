"""Mastyf Authority for GitHub, in shadow mode: which GitHub actions should have needed a second person?

Two ways to run it, same rules and the same report:
  - the GitHub Action (`action/`): a weekly job in the customer's own GitHub. Nothing leaves GitHub.
  - the hosted GitHub App (Mastyf's service): decides webhook events as they arrive.

Weekly job (`authority github-report`), no server and no database:
  - Branch activity comes from GitHub's repository activity API (90 days of pushes, force-pushes and branch
    deletions, with who and when). The last `days` are judged; the older history teaches Authority what is normal
    for each person.
  - Settings that have no activity log for most plans (who is an owner, which repositories are public, branch
    protection, rulesets, deploy keys, admin collaborators) are compared with last week's snapshot. The snapshot is
    kept, compressed, in a hidden comment inside the previous report issue: the customer's own repository is the
    only storage.
  - With only the workflow's own token it covers the repository it runs in. With a read-only organisation token
    (secret MASTYF_ORG_TOKEN) it covers every repository and organisation-level changes; the report explains how.

Nothing is blocked: this reports what Authority *would* have done.
"""

from __future__ import annotations

import base64
import datetime as dt
import json
import time
import urllib.error
import urllib.parse
import urllib.request
import zlib
from collections import Counter
from pathlib import Path

from .actions import Action
from .audit import AuditLog
from .crypto import Signer
from .engine import ALLOW, DENY, ESCALATE, Authority
from .grants import GrantIssuer
from .policy import Policy

API = "https://api.github.com"
OFFER = "https://www.mastyf.ai/authority"
LABEL = "mastyf-authority"
SNAP = "mastyf-snapshot"
GH_TYPES = ["repo.push", "repo.history_rewrite", "storage.delete", "data.export", "permission.grant",
            "security.control_change"]
ORG_TOKEN_HELP = "https://mastyf-ai.github.io/mastyf-authority/github-app/#org-token"


# --------------------------------------------------------------------------------------------- policy


def base_policy() -> dict:
    p = json.loads((Path(__file__).resolve().parent / "policies" / "default.json").read_text()) \
        if (Path(__file__).resolve().parent / "policies" / "default.json").exists() \
        else json.loads((Path(__file__).resolve().parents[2] / "policies" / "default.json").read_text())
    p["version"] = "github-shadow-2026-11-24"
    p["identities"] = {}
    p["always_escalate"] = ["storage.delete", "security.control_change", "permission.grant", "data.export"]
    p["protected_branches"] = ["main", "master", "release/*", "production", "prod"]
    p["destinations"] = {"allow": [], "deny": p.get("destinations", {}).get("deny", [])}
    p["thresholds"] = {"repo.history_rewrite": {"per_action": 50, "per_day": 100}}
    p["canaries"] = {"resources": [], "values": []}
    for k in ("teams", "data_budgets", "change_gates", "undo_windows", "origins"):
        p.pop(k, None)
    p.setdefault("model", {})["skip"] = []
    return p


def who(login: str, kind: str = "User") -> str:
    login = login or "unknown"
    return ("svc:" if kind == "Bot" or login.endswith("[bot]") else "human:") + login


def _act(identity: str, t: str, res: str, n: int = 1, dest: str | None = None, meta: dict | None = None) -> dict:
    return {"identity": identity, "action_type": t, "resource": res, "count": max(1, int(n)), "destination": dest,
            "metadata": meta or {}}


def to_action(event: str, p: dict) -> tuple[dict, str] | None:
    """A webhook event (hosted app) as (Authority action, plain-English description), or None if not judged."""
    org = (p.get("organization") or {}).get("login") or (p.get("repository") or {}).get("owner", {}).get("login", "")
    repo = (p.get("repository") or {}).get("name", "")
    sender = p.get("sender") or {}
    ident = who(sender.get("login", "unknown"), sender.get("type", "User"))
    base = f"github://{org}/{repo}"
    act = p.get("action")
    if event == "push":
        branch = p.get("ref", "").removeprefix("refs/heads/")
        if not p.get("ref", "").startswith("refs/heads/") or p.get("deleted"):
            return None
        n = len(p.get("commits") or []) or 1
        if p.get("forced"):
            return (_act(ident, "repo.history_rewrite", f"{base}/{branch}", n),
                    f"force-pushed to `{branch}` in `{repo}`, rewriting its history")
        return _act(ident, "repo.push", f"{base}/{branch}", n), f"pushed to `{branch}` in `{repo}`"
    if event == "delete" and p.get("ref_type") == "branch":
        branch = p.get("ref", "")
        return _act(ident, "repo.history_rewrite", f"{base}/{branch}"), f"deleted branch `{branch}` in `{repo}`"
    if event == "repository":
        if act == "deleted":
            return _act(ident, "storage.delete", base), f"deleted the repository `{repo}`"
        if act == "publicized":
            return (_act(ident, "data.export", base, 1, f"https://github.com/{org}/{repo}"),
                    f"made the private repository `{repo}` public")
        if act == "transferred":
            return _act(ident, "data.export", base, 1, f"https://github.com/{org}/{repo}"), f"transferred `{repo}`"
        return None
    if event == "member" and act == "added":
        perm = ((p.get("changes") or {}).get("permission") or {}).get("to") or "write"
        user = (p.get("member") or {}).get("login", "?")
        return (_act(ident, "permission.grant", base, 1, meta={"to": user, "permission": perm}),
                f"gave `{user}` {perm} access to `{repo}`")
    if event == "organization" and act == "member_added":
        role = (p.get("membership") or {}).get("role", "member")
        user = ((p.get("membership") or {}).get("user") or {}).get("login", "?")
        if role != "admin":
            return None
        return (_act(ident, "permission.grant", f"github://{org}", 1, meta={"to": user, "role": role}),
                f"made `{user}` an owner of `{org}`")
    if event == "deploy_key" and act == "created":
        ro = (p.get("key") or {}).get("read_only", True)
        return (_act(ident, "permission.grant", f"{base}/deploy-keys", 1, meta={"read_only": ro}),
                f"added a {'read-only' if ro else 'read-write'} deploy key to `{repo}`")
    if event == "branch_protection_rule" and act in ("deleted", "edited"):
        rule = (p.get("rule") or {}).get("name", "?")
        return (_act(ident, "security.control_change", f"{base}/branch-protection/{rule}"),
                f"{'removed' if act == 'deleted' else 'changed'} branch protection `{rule}` in `{repo}`")
    if event == "repository_ruleset" and act == "deleted":
        rs = (p.get("repository_ruleset") or {}).get("name", "?")
        return _act(ident, "security.control_change", f"{base}/rulesets/{rs}"), f"deleted the ruleset `{rs}` in `{repo}`"
    return None


# --------------------------------------------------------------------------------------------- the engine


def preview_model(worlds: int = 60):
    """A small risk model trained right here on synthetic incidents (scenarios.py), so ordinary branch work is not
    held just because no model is loaded. Seconds on a GitHub runner; nothing is downloaded."""
    from .evaluate import _family_plan, build
    from .model import RiskModel
    from .scenarios import FAMILIES
    X, y, _ = build(list(range(20261124, 20261124 + worlds)), _family_plan(worlds, list(FAMILIES)),
                    Policy.from_dict(base_policy()).identity_meta())
    return RiskModel.train(X, y)


class _Clock:
    def __init__(self):
        self.t = time.time()

    def __call__(self):
        return self.t


class Shadow:
    """An Authority engine in shadow mode for one organisation: identities and protected branches are added as
    they appear; nobody is ever asked (held requests are dropped from the queue)."""

    def __init__(self, model=None):
        self.raw = base_policy()
        self.clock = _Clock()
        signer = Signer.generate()
        self.auth = Authority(Policy.from_dict(self.raw), GrantIssuer(signer, 60, now=self.clock),
                              AuditLog(None, signer, now=self.clock), model=model, now=self.clock)

    def _ensure(self, identity: str, default_branch: str | None) -> None:
        changed = False
        if identity not in self.raw["identities"]:
            self.raw["identities"][identity] = {"kind": "service" if identity.startswith("svc:") else "human",
                                                "allowed_actions": GH_TYPES}
            changed = True
        if default_branch and default_branch not in self.raw["protected_branches"]:
            self.raw["protected_branches"].append(default_branch)
            changed = True
        if changed:
            self.auth.policy = Policy.from_dict(self.raw)
            self.auth.state.meta = self.auth.policy.identity_meta()

    def learn(self, act: dict, ts: float, default_branch: str | None = None) -> None:
        """Older history: this is what normal looks like (no verdict)."""
        self._ensure(act["identity"], default_branch)
        self.clock.t = ts
        a = Action.from_dict({**act, "ts": ts})
        self.auth.state.observe(a, learn=True)
        self.auth.novelty.observe(a, learn=True)

    def decide(self, act: dict, ts: float, default_branch: str | None = None):
        self._ensure(act["identity"], default_branch)
        self.clock.t = ts
        d = self.auth.decide(Action.from_dict({**act, "ts": ts}))
        self.auth.pending.pop(d.fingerprint, None)
        return d


def record(d, ts: float, event: str, what: str, act: dict, repo: str = "") -> dict:
    return {"ts": ts, "event": event, "what": what, "actor": act["identity"], "repo": repo, "verdict": d.verdict,
            "reasons": d.reasons[:4], "stage": d.stage, "risk": None if d.risk is None else round(d.risk, 3)}


# --------------------------------------------------------------------------------------------- the report


def render_report(org: str, events: list[dict], days: int = 7, notes: list[str] | None = None,
                  hosted: bool = False) -> tuple[str, str]:
    held = [e for e in events if e["verdict"] == ESCALATE]
    refused = [e for e in events if e["verdict"] == DENY]
    ok = [e for e in events if e["verdict"] == ALLOW]
    people = len({e["actor"] for e in events})
    title = f"Mastyf Authority weekly report: {len(held)} held, {len(refused)} refused ({days} days)"
    L = [f"## What Authority would have done in `{org}`, last {days} days", "",
         "Shadow mode: nothing was blocked and nobody was asked. This is what *would* have happened with Authority "
         "enforcing.", "",
         "| | |", "|---|---|",
         f"| Actions checked | **{len(events)}** by {people} account{'s' if people != 1 else ''} |",
         f"| Would have waited for a second person's approval | **{len(held)}** |",
         f"| Would have been refused outright | **{len(refused)}** |",
         f"| Would have gone straight through | {len(ok)} |",
         f"| Interruptions per working day | {len(held) / 5:.1f} |", ""]

    def table(rows, head):
        out = [head, "", "| When (UTC) | Who | What | Why |", "|---|---|---|---|"]
        for e in rows[-25:]:
            why = "; ".join(e["reasons"][:2]).replace("|", "/")
            when = time.strftime("%a %d %b %H:%M", time.gmtime(e["ts"])) if e.get("ts") else "this week"
            actor = e["actor"].split(":", 1)[-1]
            out.append(f"| {when} | `{actor}` | {e['what']} | {why} |")
        return out + [""]

    if refused:
        L += table(refused, "### Would have been refused")
    if held:
        L += table(held, "### Would have waited for a second person")
    if not held and not refused:
        L += ["Nothing needed a second person this week. That is the normal case: Authority stays out of the way "
              "of everyday work.", ""]
    kinds = Counter(e["event"] for e in events)
    if kinds:
        L += ["Seen this week: " + ", ".join(f"{k} {v}" for k, v in kinds.most_common()) + ".", ""]
    for n in notes or []:
        L += [n, ""]
    L += ["---",
          "**With Authority enforcing**, each held action waits until another person in your organisation approves it "
          "with their passkey, and refused ones never happen. It also covers what GitHub cannot see: data exports, "
          "cloud consoles, AI agents and production secrets.", "",
          f"Free 60-day pilot on your own AWS, Okta and GitHub logs, for our first three founding design partners: "
          f"[{OFFER}]({OFFER}).", "",
          ("<sub>Mastyf Authority for GitHub keeps only the event kind, the account, repository, branch, time and "
           "verdict for 90 days, never code. Uninstalling the app deletes everything it kept.</sub>" if hosted else
           "<sub>Mastyf Authority keeps nothing outside your GitHub: this report and last week's snapshot (hidden in "
           "this issue) are the only records. Never code.</sub>")]
    return title, "\n".join(L)


def token_note(org: str) -> str:
    return (f"### See the whole of `{org}`\n\nThis week's report covers **only the repository this workflow runs in**, "
            "because a workflow's own token cannot see the rest of the organisation. To include every repository and "
            "organisation-level changes (new owners, repositories made public or deleted, protections removed, new "
            "deploy keys and admins), give it a **read-only** token:\n\n"
            "1. Create a fine-grained token at https://github.com/settings/personal-access-tokens/new: resource owner "
            f"`{org}`, **All repositories**, repository permissions **Administration: Read-only** (Metadata is added "
            "automatically), organisation permissions **Members: Read-only**. Nothing else.\n"
            "2. In this repository: **Settings → Secrets and variables → Actions → New repository secret**, named "
            "`MASTYF_ORG_TOKEN`, with the token as its value.\n"
            "3. Next week's report covers everything. To run it now: **Actions → Mastyf Authority → Run workflow**.\n\n"
            "The token never leaves GitHub: it is used only inside this workflow, on GitHub's runner. "
            f"More: {ORG_TOKEN_HELP}")


# --------------------------------------------------------------------------------------------- GitHub API


class Unavailable(Exception):
    """The feature is not available to this token or plan (403/404): skipped, and said so in the report."""


class GH:
    def __init__(self, token: str, api: str = API):
        self.token, self.api = token, api.rstrip("/")

    def req(self, method: str, path: str, body=None):
        url = path if path.startswith("http") else self.api + path
        r = urllib.request.Request(url, method=method, data=None if body is None else json.dumps(body).encode(),
                                   headers={"Authorization": f"Bearer {self.token}", "Accept": "application/vnd.github+json",
                                            "X-GitHub-Api-Version": "2022-11-28", "User-Agent": "mastyf-authority"})
        try:
            with urllib.request.urlopen(r, timeout=30) as resp:
                data = resp.read()
                return json.loads(data) if data else {}, resp.headers.get("Link", "")
        except urllib.error.HTTPError as e:
            if e.code in (403, 404):
                raise Unavailable(f"{e.code} {path.split('?')[0]}") from None
            raise

    def get(self, path: str):
        return self.req("GET", path)[0]

    def pages(self, path: str, limit: int = 10) -> list:
        out, url = [], path + ("&" if "?" in path else "?") + "per_page=100"
        for _ in range(limit):
            data, link = self.req("GET", url)
            out += data if isinstance(data, list) else data.get("repositories", [])
            nxt = [p.split(";")[0].strip("<> ") for p in link.split(",") if 'rel="next"' in p]
            if not nxt:
                break
            url = nxt[0]
        return out


def _ts(s: str) -> float:
    return dt.datetime.fromisoformat(s.replace("Z", "+00:00")).timestamp()


def repo_state(gh: GH, full: str, default_branch: str) -> dict:
    """What the snapshot keeps for one repository; None for each part this token cannot read."""
    st: dict = {}
    try:
        gh.get(f"/repos/{full}/branches/{urllib.parse.quote(default_branch, safe='')}/protection")
        st["protected"] = True
    except Unavailable as e:
        st["protected"] = False if str(e).startswith("404") else None
    try:
        st["rulesets"] = sorted(r["name"] for r in gh.pages(f"/repos/{full}/rulesets", 3))
    except Unavailable:
        st["rulesets"] = None
    try:
        st["deploy_keys"] = {str(k["id"]): {"title": k.get("title", ""), "read_only": k.get("read_only", True),
                                            "created_at": k.get("created_at"), "added_by": k.get("added_by")}
                             for k in gh.pages(f"/repos/{full}/keys", 3)}
    except Unavailable:
        st["deploy_keys"] = None
    try:
        st["admins"] = sorted(c["login"] for c in gh.pages(f"/repos/{full}/collaborators?permission=admin", 3))
    except Unavailable:
        st["admins"] = None
    return st


def diff_events(org: str, prev: dict, cur: dict, now: float) -> list[tuple[dict, str, str, float, str]]:
    """Changes since last week's snapshot as (action, description, event kind, when, repository). Who did it is
    unknown for most of these (GitHub has no activity log for them outside Enterprise), so the account is
    `unknown`; deploy keys carry their creation time and creator when GitHub gives them."""
    out = []
    unknown = who("unknown")
    pr, cr = prev.get("repos", {}), cur.get("repos", {})
    for name, r in cr.items():
        base = f"github://{org}/{name}"
        p = pr.get(name)
        if p is None:
            continue  # new repository: nothing to compare with yet
        if p.get("private") and r.get("private") is False:
            out.append((_act(unknown, "data.export", base, 1, f"https://github.com/{org}/{name}"),
                        f"made the private repository `{name}` public", "repository", now, name))
        if p.get("protected") is True and r.get("protected") is False:
            out.append((_act(unknown, "security.control_change", f"{base}/branch-protection/{r.get('default_branch')}"),
                        f"removed branch protection on `{r.get('default_branch')}` in `{name}`", "branch_protection", now, name))
        if p.get("rulesets") is not None and r.get("rulesets") is not None:
            for rs in sorted(set(p["rulesets"]) - set(r["rulesets"])):
                out.append((_act(unknown, "security.control_change", f"{base}/rulesets/{rs}"),
                            f"deleted the ruleset `{rs}` in `{name}`", "ruleset", now, name))
        if p.get("deploy_keys") is not None and r.get("deploy_keys") is not None:
            for kid, k in r["deploy_keys"].items():
                if kid not in p["deploy_keys"]:
                    when = _ts(k["created_at"]) if k.get("created_at") else now
                    actor = who(k["added_by"]) if k.get("added_by") else unknown
                    out.append((_act(actor, "permission.grant", f"{base}/deploy-keys", 1, meta={"read_only": k["read_only"]}),
                                f"added a {'read-only' if k['read_only'] else 'read-write'} deploy key "
                                f"`{k['title']}` to `{name}`", "deploy_key", when, name))
        if p.get("admins") is not None and r.get("admins") is not None:
            for u in sorted(set(r["admins"]) - set(p["admins"])):
                out.append((_act(unknown, "permission.grant", base, 1, meta={"to": u, "permission": "admin"}),
                            f"gave `{u}` admin access to `{name}`", "member", now, name))
    for name in sorted(set(pr) - set(cr)):
        if cur.get("complete"):
            out.append((_act(unknown, "storage.delete", f"github://{org}/{name}"),
                        f"deleted or transferred the repository `{name}`", "repository", now, name))
    if prev.get("owners") is not None and cur.get("owners") is not None:
        for u in sorted(set(cur["owners"]) - set(prev["owners"])):
            out.append((_act(unknown, "permission.grant", f"github://{org}", 1, meta={"to": u, "role": "admin"}),
                        f"made `{u}` an owner of `{org}`", "organization", now, ""))
    return out


def pack(snap: dict) -> str:
    return f"<!-- {SNAP}:{base64.b64encode(zlib.compress(json.dumps(snap, separators=(',', ':')).encode())).decode()} -->"


def unpack(body: str) -> dict:
    i = (body or "").find(f"<!-- {SNAP}:")
    if i < 0:
        return {}
    blob = body[i + len(f"<!-- {SNAP}:"):].split(" -->", 1)[0]
    try:
        return json.loads(zlib.decompress(base64.b64decode(blob)))
    except (ValueError, zlib.error):
        return {}


# --------------------------------------------------------------------------------------------- the weekly job


def weekly(gh: GH, report_repo: str, org_gh: GH | None = None, days: int = 7, now: float | None = None,
           model=None, post: bool = True, allow_public: bool = False) -> dict:
    """Collect, decide and (optionally) post one weekly report. Returns {title, body, url, events, notes}."""
    now = now or time.time()
    since = now - days * 86400
    owner = report_repo.split("/")[0]
    rr = gh.get(f"/repos/{report_repo}")
    if not rr.get("private") and not allow_public:
        raise SystemExit(f"{report_repo} is public: a report names accounts and repositories, and a public "
                         "repository's issues and Actions logs are public too. Run this workflow in a private "
                         "repository (e.g. a new one named mastyf-reports), or set allow-public: true.")
    full_scope = org_gh is not None
    scan = org_gh or gh
    notes: list[str] = []
    owner_type = gh.get(f"/users/{owner}").get("type", "User")
    if full_scope:
        try:
            listing = scan.pages(f"/orgs/{owner}/repos?type=all") if owner_type == "Organization" \
                else [r for r in scan.pages("/user/repos?affiliation=owner") if r["owner"]["login"] == owner]
            complete = True
        except Unavailable as e:
            listing, complete = [rr], False
            notes.append(f"The organisation token could not list repositories ({e}); only `{report_repo}` was checked.")
    else:
        listing, complete = [rr], False
    listing = [r for r in listing if not r.get("archived")]

    # last week's snapshot, from the newest earlier report
    prev, prev_issue = {}, None
    try:
        issues = gh.get(f"/repos/{report_repo}/issues?labels={LABEL}&state=all&per_page=5&sort=created&direction=desc")
        for it in issues:
            snap = unpack(it.get("body", ""))
            if snap:
                prev, prev_issue = snap, it
                break
    except Unavailable:
        pass

    shadow = Shadow(model)
    decided: list[dict] = []
    cur = {"taken": now, "complete": complete, "repos": {}, "owners": None}
    skipped = Counter()
    for r in listing:
        full, name, db = r["full_name"], r["name"], r.get("default_branch") or "main"
        # branch activity: up to 90 days; older than the window = learn what is normal, inside = decide
        try:
            acts = scan.pages(f"/repos/{full}/activity?time_period=quarter", 5)
        except Unavailable:
            acts = []
            skipped["activity"] += 1
        for a in sorted(acts, key=lambda a: a["timestamp"]):
            ts, kind, ref = _ts(a["timestamp"]), a.get("activity_type"), a.get("ref", "")
            if not ref.startswith("refs/heads/"):
                continue
            branch = ref.removeprefix("refs/heads/")
            actor = who((a.get("actor") or {}).get("login", "unknown"), (a.get("actor") or {}).get("type", "User"))
            res = f"github://{owner}/{name}/{branch}"
            if kind == "push":
                act, what, ev = _act(actor, "repo.push", res), f"pushed to `{branch}` in `{name}`", "push"
            elif kind == "force_push":
                act, what, ev = (_act(actor, "repo.history_rewrite", res),
                                 f"force-pushed to `{branch}` in `{name}`, rewriting its history", "force_push")
            elif kind == "branch_deletion":
                act, what, ev = _act(actor, "repo.history_rewrite", res), f"deleted branch `{branch}` in `{name}`", "branch_deletion"
            else:
                continue
            if ts < since:
                if kind == "push":
                    shadow.learn(act, ts, db)
                continue
            decided.append(record(shadow.decide(act, ts, db), ts, ev, what, act, name))
        st = {"private": r.get("private"), "default_branch": db}
        st.update(repo_state(scan, full, db))
        for k in ("protected", "rulesets", "deploy_keys", "admins"):
            if st.get(k) is None:
                skipped[k] += 1
        cur["repos"][name] = st
    if full_scope and owner_type == "Organization":
        try:
            cur["owners"] = sorted(m["login"] for m in scan.pages(f"/orgs/{owner}/members?role=admin", 5))
        except Unavailable:
            notes.append("The organisation token cannot read members, so new owners are not checked "
                         "(add organisation permission Members: Read-only).")

    if prev:
        for act, what, ev, ts, repo in diff_events(owner, prev, cur, now):
            decided.append(record(shadow.decide(act, ts), ts, ev, what, act, repo))
    else:
        notes.append("**First report:** this week's settings are recorded as the starting point. From next week, "
                     "changes to them (repositories made public or deleted, protections removed, new owners, deploy "
                     "keys and admins) are reported too.")
    if skipped:
        names = {"activity": "branch activity", "protected": "branch protection", "rulesets": "rulesets",
                 "deploy_keys": "deploy keys", "admins": "admin collaborators"}
        notes.append("Not visible to this token or plan, so not checked: " + ", ".join(
            f"{names[k]} ({v} repositor{'y' if v == 1 else 'ies'})" for k, v in skipped.items()) + ".")
    if not full_scope:
        notes.append(token_note(owner))
    decided.sort(key=lambda e: e["ts"])
    title, body = render_report(owner, decided, days, notes)
    body += "\n\n" + pack(cur)
    url = None
    if post:
        try:
            gh.req("POST", f"/repos/{report_repo}/labels", {"name": LABEL, "color": "e3b453",
                                                             "description": "Mastyf Authority weekly reports"})
        except (Unavailable, urllib.error.HTTPError):
            pass  # already exists
        url = gh.req("POST", f"/repos/{report_repo}/issues", {"title": title, "body": body, "labels": [LABEL]})[0].get("html_url")
        if prev_issue and prev_issue.get("state") == "open":
            try:
                gh.req("PATCH", f"/repos/{report_repo}/issues/{prev_issue['number']}", {"state": "closed"})
            except (Unavailable, urllib.error.HTTPError):
                pass
    return {"title": title, "body": body, "url": url, "events": decided, "notes": notes, "full_scope": full_scope}
