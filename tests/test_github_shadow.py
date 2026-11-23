"""The GitHub Action edition (github_shadow.py): a weekly shadow-mode report, run inside the customer's GitHub."""
import time

import pytest

from authority import github_shadow as G

NOW = 1_800_000_000.0
DAY = 86400


def iso(ts):
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime(ts))


class FakeGH:
    """Just enough of the GitHub REST API, from a dict of path -> response (or an exception class)."""

    def __init__(self, routes):
        self.routes, self.posted = routes, []

    def req(self, method, path, body=None):
        if method != "GET":
            self.posted.append((method, path, body))
            return {"html_url": "https://github.com/acme/mastyf-reports/issues/9", "number": 9}, ""
        for prefix, resp in self.routes.items():
            if path.split("?")[0] == prefix.split("?")[0] and (("?" not in prefix) or prefix.split("?")[1] in path):
                if isinstance(resp, Exception):
                    raise resp
                return resp, ""
        raise G.Unavailable(f"404 {path}")

    def get(self, path):
        return self.req("GET", path)[0]

    def pages(self, path, limit=10):
        return self.get(path)


def org_routes(private_api=True, protected=True, keys=None, owners=("alice",), issues=None, acts=None):
    acts = acts if acts is not None else [
        {"timestamp": iso(NOW - 40 * DAY + i * DAY), "activity_type": "push", "ref": "refs/heads/feature/x",
         "actor": {"login": "priya", "type": "User"}} for i in range(20)] + [
        {"timestamp": iso(NOW - 2 * DAY), "activity_type": "force_push", "ref": "refs/heads/main",
         "actor": {"login": "mallory", "type": "User"}},
        {"timestamp": iso(NOW - 1 * DAY), "activity_type": "push", "ref": "refs/heads/feature/x",
         "actor": {"login": "priya", "type": "User"}}]
    r = {
        "/repos/acme/mastyf-reports": {"full_name": "acme/mastyf-reports", "name": "mastyf-reports", "private": True,
                                       "default_branch": "main"},
        "/users/acme": {"type": "Organization"},
        "/orgs/acme/repos": [
            {"full_name": "acme/api", "name": "api", "private": private_api, "default_branch": "main"},
            {"full_name": "acme/mastyf-reports", "name": "mastyf-reports", "private": True, "default_branch": "main"}],
        "/repos/acme/api/activity": acts,
        "/repos/acme/mastyf-reports/activity": [],
        "/repos/acme/api/rulesets": [],
        "/repos/acme/api/keys": keys or [],
        "/repos/acme/api/collaborators": [{"login": "alice"}],
        "/repos/acme/mastyf-reports/rulesets": [], "/repos/acme/mastyf-reports/keys": [],
        "/repos/acme/mastyf-reports/collaborators": [{"login": "alice"}],
        "/orgs/acme/members": [{"login": u} for u in owners],
        "/repos/acme/mastyf-reports/issues": issues or [],
    }
    if protected:
        r["/repos/acme/api/branches/main/protection"] = {"url": "x"}
    return r


def test_refuses_public_report_repository():
    gh = FakeGH({"/repos/acme/site": {"full_name": "acme/site", "private": False}})
    with pytest.raises(SystemExit, match="public"):
        G.weekly(gh, "acme/site", now=NOW)


def test_without_org_token_covers_this_repository_and_asks_for_the_token():
    routes = org_routes()
    routes["/repos/acme/mastyf-reports/activity"] = [
        {"timestamp": iso(NOW - DAY), "activity_type": "force_push", "ref": "refs/heads/main",
         "actor": {"login": "mallory", "type": "User"}}]
    gh = FakeGH(routes)
    out = G.weekly(gh, "acme/mastyf-reports", now=NOW, post=False)
    assert not out["full_scope"]
    assert [e["verdict"] for e in out["events"]] == ["DENY"]  # force-push to main
    assert "MASTYF_ORG_TOKEN" in out["body"] and "Members: Read-only" in out["body"]
    assert "First report" in out["body"]


def test_first_week_with_org_token_then_second_week_diff():
    gh, org = FakeGH(org_routes()), FakeGH(org_routes())
    week1 = G.weekly(gh, "acme/mastyf-reports", org, now=NOW, post=True)
    assert week1["full_scope"] and "MASTYF_ORG_TOKEN" not in week1["body"]
    verdicts = {e["what"]: e["verdict"] for e in week1["events"]}
    assert verdicts["force-pushed to `main` in `api`, rewriting its history"] == "DENY"
    assert verdicts["pushed to `feature/x` in `api`"] == "ALLOW"  # ordinary work, learnt from the older history
    issue = [b for m, p, b in gh.posted if p.endswith("/issues")][0]
    snap = G.unpack(issue["body"])
    assert snap["repos"]["api"]["protected"] is True and snap["owners"] == ["alice"]

    # week 2: api made public, protection removed, a read-write deploy key and a new owner
    prev = [{"number": 9, "state": "open", "body": issue["body"]}]
    key = [{"id": 77, "title": "ci", "read_only": False, "created_at": iso(NOW + 3 * DAY), "added_by": "sam"}]
    r2 = org_routes(private_api=False, protected=False, keys=key, owners=("alice", "eve"), issues=prev, acts=[])
    gh2, org2 = FakeGH(r2), FakeGH(r2)
    week2 = G.weekly(gh2, "acme/mastyf-reports", org2, now=NOW + 7 * DAY, post=True)
    held = {e["what"] for e in week2["events"] if e["verdict"] == "ESCALATE"}
    assert "made the private repository `api` public" in held
    assert "removed branch protection on `main` in `api`" in held
    assert "added a read-write deploy key `ci` to `api`" in held
    assert "made `eve` an owner of `acme`" in held
    assert any(e["actor"] == "human:sam" for e in week2["events"])  # deploy keys carry who added them
    assert ("PATCH", "/repos/acme/mastyf-reports/issues/9", {"state": "closed"}) in gh2.posted  # last week's closed


def test_deleted_repository_only_when_the_listing_is_complete():
    prev = {"repos": {"old": {"private": True}}, "owners": None}
    cur_full = {"repos": {}, "complete": True}
    cur_partial = {"repos": {}, "complete": False}
    assert any("deleted or transferred" in d[1] for d in G.diff_events("acme", prev, cur_full, NOW))
    assert not G.diff_events("acme", prev, cur_partial, NOW)  # a token that sees less is not a deletion


def test_snapshot_round_trip_is_hidden_and_compact():
    snap = {"repos": {f"r{i}": {"private": True, "protected": True} for i in range(300)}}
    blob = G.pack(snap)
    assert blob.startswith("<!--") and blob.endswith("-->") and len(blob) < 4000
    assert G.unpack("report text\n\n" + blob) == snap
    assert G.unpack("no snapshot here") == {}


def test_unavailable_features_are_reported_not_fatal():
    routes = org_routes()
    for k in list(routes):
        if k.endswith(("/rulesets", "/keys", "/protection")):
            del routes[k]
    out = G.weekly(FakeGH(routes), "acme/mastyf-reports", FakeGH(routes), now=NOW, post=False)
    assert "Not visible to this token or plan" in out["body"]
