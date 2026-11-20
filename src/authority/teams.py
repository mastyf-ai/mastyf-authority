"""Teams: set limits once per team instead of once per person.

A policy may carry

    "teams": {
      "sales": {"allowed_actions": ["auth.login", "data.read"], "budgets": {"crm.customer": 5000},
                "idp_groups": ["Sales", "Sales EMEA"], "members": ["human:alice"]},
      ...
    }

and `expand(policy, directory)` turns it into the per-identity form the engine and the Rust key
service already enforce, so nothing downstream changes. Membership comes from the team's own
`members` list and from identity-provider groups (`directory`, kept up to date by SCIM, scim.py).

Rules, chosen to be predictable:
  * a person in several teams gets the union of their actions and, per data class, the LARGER budget
    (like any role-based system); approver if any of their teams is;
  * an explicit `identities[x]` entry replaces the team-derived rule for x, and an explicit
    `data_budgets.budgets[x][class]` replaces that one class;
  * people the directory marks inactive get nothing from teams (offboarding takes effect at once).
"""

from __future__ import annotations

import copy


def members_of(team: str, spec: dict, directory: dict | None) -> set[str]:
    out = set(spec.get("members", []))
    if directory:
        wanted = set(spec.get("idp_groups", [])) or {team}
        users = directory.get("users", {})
        for g in directory.get("groups", {}).values():
            if g.get("displayName") in wanted:
                for uid in g.get("members", []):
                    u = users.get(uid)
                    if u and u.get("active", True):
                        out.add(identity_of(u))
    inactive = {identity_of(u) for u in (directory or {}).get("users", {}).values() if not u.get("active", True)}
    return out - inactive


def identity_of(user: dict) -> str:
    """SCIM user -> authority identity: human:<userName, lower-case, before any @>."""
    name = str(user.get("userName", "")).strip().lower()
    return "human:" + (name.split("@", 1)[0] if name else str(user.get("id")))


def expand(policy: dict, directory: dict | None = None) -> dict:
    teams = policy.get("teams")
    if not teams:
        return policy
    out = copy.deepcopy(policy)
    explicit_ids = set(policy.get("identities", {}))
    explicit_budgets = policy.get("data_budgets", {}).get("budgets", {})
    rules: dict[str, dict] = {}
    budgets: dict[str, dict[str, int]] = {}
    for name, spec in teams.items():
        if name.startswith("_"):
            continue
        for ident in members_of(name, spec, directory):
            r = rules.setdefault(ident, {"kind": spec.get("kind", "human"), "allowed_actions": [], "teams": []})
            for act in spec.get("allowed_actions", []):
                if act not in r["allowed_actions"]:
                    r["allowed_actions"].append(act)
            r["approver"] = bool(r.get("approver")) or bool(spec.get("approver"))
            r["teams"].append(name)
            b = budgets.setdefault(ident, {})
            for cls, n in spec.get("budgets", {}).items():
                b[cls] = max(int(n), b.get(cls, 0))
    for ident, r in rules.items():
        if ident not in explicit_ids:
            out.setdefault("identities", {})[ident] = r
    if budgets:
        db = out.setdefault("data_budgets", {}).setdefault("budgets", {})
        for ident, b in budgets.items():
            merged = dict(b)
            merged.update(explicit_budgets.get(ident, {}))  # explicit per-person classes win
            db[ident] = merged
    out.pop("teams", None)
    out["_compiled_from_teams"] = sorted(n for n in teams if not n.startswith("_"))
    return out
