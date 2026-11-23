"""Risk model lab: try the behavioural risk model without touching the live engine.

Two sandboxed engines run side by side on a simulated clock, with the live policy and the same 30 days of
normal (synthetic) activity behind them:

  without   no risk model: what an engine without a model does today (sensitive actions wait for a person)
  with      a risk model: the engine's own model if it has one, else a preview model trained here, in about
            10 seconds, on synthetic incidents (scenarios.py). It is NOT the pre-trained model of the paid plans.

Everything a visitor tries happens only inside the lab (its own keys, an in-memory audit log, its own counters),
so it can be reset at any time. `replay` re-runs the actions the live engine held or refused, with the person's
own approve / deny decisions next to what the model would have done.
"""

from __future__ import annotations

import threading
import time

from .actions import Action
from .audit import AuditLog
from .crypto import Signer
from .engine import ALLOW, DENY, ESCALATE, Authority
from .features import DAY, HOUR
from .grants import GrantIssuer
from .policy import Policy
from .scenarios import FAMILIES, world

HISTORY_DAYS = 30
BASELINE_FROM_DAY = 10
SEED = 20261123

# What the model looks at, in words (behavioural features from features.py).
_FEATURES = [
    ("size", "How large this is compared with what they usually do"),
    ("new_type", "A kind of action they have never done before"),
    ("new_resource", "A system or data set they have never touched"),
    ("new_destination", "Data going somewhere new"),
    ("odd_hour", "An hour they are rarely active"),
    ("exfil_chain", "Reading data, then sending it somewhere new"),
]


class _Clock:
    def __init__(self, t: float = 0.0):
        self.t = t

    def __call__(self) -> float:
        return self.t


def _verdict(d) -> dict:
    return {"verdict": d.verdict, "reasons": d.reasons, "stage": d.stage,
            "risk": None if d.risk is None else round(d.risk, 3)}


class _Sandbox:
    """A pair of engines (without / with a model) on one simulated clock, with HISTORY_DAYS of normal activity."""

    def __init__(self, policy: Policy, model):
        self.policy = policy
        self.clock = _Clock()
        self.without = self._engine(None)
        self.with_ = self._engine(model)
        seen: set[str] = set()
        for e in world(SEED, None, days=HISTORY_DAYS):
            a = e.action
            if a.identity not in policy.identities:
                continue
            seen.add(a.identity)
            self.clock.t = a.ts
            for eng in (self.without, self.with_):
                if a.ts >= BASELINE_FROM_DAY * DAY:  # each identity's "normal" scores, once novelty has settled
                    eng.note_baseline(a)
                eng.state.observe(a, learn=True)
                eng.novelty.observe(a, learn=True)
        self.history_ids = sorted(seen)
        self.clock.t = HISTORY_DAYS * DAY + 9 * HOUR  # the lab's "today", 09:00

    def _engine(self, model) -> Authority:
        signer = Signer.generate()
        return Authority(self.policy, GrantIssuer(signer, self.policy.grant_ttl_seconds, now=self.clock),
                         AuditLog(None, signer, now=self.clock), model=model, now=self.clock)

    def _at_hour(self, hour: float | None) -> float:
        t = self.clock.t + 60
        if hour is None:
            return t
        target = int(t // DAY) * DAY + float(hour) * HOUR
        return target if target >= t else target + DAY

    def _explain(self, a: Action) -> list[dict]:
        f = self.with_.state.features(a)
        # f[1] count z-score (0 normal ... 6+ far outside their normal); f[2..5] new type / resource /
        # destination / hour rarity (0..1); f[14] read-then-send-somewhere-new chain
        vals = [f[1] / 6, f[2], f[3], f[4], f[5], f[14]]
        vals = [max(0.0, min(1.0, v)) for v in vals]
        return [{"key": k, "label": lab, "level": round(float(v), 2)} for (k, lab), v in zip(_FEATURES, vals)]

    def run(self, raw: dict, hour: float | None = None) -> dict:
        a = Action.from_dict({**raw, "ts": 0})
        self.clock.t = self._at_hour(hour)
        a = Action(**{**a.to_dict(), "ts": self.clock.t})
        explain = self._explain(a)
        d0, d1 = self.without.decide(a), self.with_.decide(a)
        t = self.clock.t
        return {"without": _verdict(d0), "with": _verdict(d1), "explain": explain,
                "lab_time": f"day {int(t // DAY) + 1}, {int(t % DAY // HOUR):02d}:{int(t % HOUR // 60):02d}"}


class Lab:
    def __init__(self, policy: Policy, model=None):
        self.policy = policy
        self.given_model = model
        self.model = model
        self.model_kind = "yours" if model is not None else "preview"
        self.lock = threading.Lock()
        self.state = "idle"  # idle -> training -> warming -> ready | error
        self.error = ""
        self.tries = 0
        self.history_ids: list[str] = []

    # ---------------------------------------------------------------- building
    def start(self) -> None:
        with self.lock:
            if self.state in ("training", "warming", "ready"):
                return
            self.state = "training"
        threading.Thread(target=self._build, daemon=True, name="risk-lab").start()

    def _build(self) -> None:
        try:
            if self.model is None:
                from .evaluate import _family_plan, build
                from .model import RiskModel
                n = 100  # `authority train` default; about 8 s
                X, y, _ = build(list(range(SEED, SEED + n)), _family_plan(n, list(FAMILIES)), self.policy.identity_meta())
                self.model = RiskModel.train(X, y)
                self.model.meta.update({"train_worlds": n, "note": "preview model: synthetic incidents only"})
            self.state = "warming"
            self._reset()
            self.state = "ready"
        except Exception as e:  # noqa: BLE001 - the lab is optional; the live engine is unaffected
            self.state, self.error = "error", f"{type(e).__name__}: {e}"

    def _reset(self) -> None:
        self.box = _Sandbox(self.policy, self.model)
        self.history_ids = self.box.history_ids
        self.tries = 0

    def reset(self) -> None:
        with self.lock:
            if self.state != "ready":
                raise RuntimeError("the lab is still starting")
            self._reset()

    # ---------------------------------------------------------------- using
    def status(self) -> dict:
        ids = sorted(self.policy.identities)
        return {"state": self.state, "error": self.error, "model": self.model_kind,
                "escalate_at": self.policy.escalate_at, "deny_at": self.policy.deny_at,
                "identities": [{"id": i, "allowed": sorted(self.policy.identities[i].allowed_actions),
                                "history": i in self.history_ids} for i in ids],
                "history_days": HISTORY_DAYS, "tries": self.tries}

    def try_action(self, raw: dict, hour: float | None = None) -> dict:
        with self.lock:
            if self.state != "ready":
                raise RuntimeError("the lab is still starting")
            self.tries += 1
            return self.box.run(raw, hour)

    def replay(self, records: list[dict]) -> dict:
        """The live engine's held / refused decisions, with what a person did and what the model would do."""
        outcome: dict[str, str] = {}
        for r in records:
            ev = r.get("event", r)
            if ev.get("type") == "approval":
                outcome[ev.get("fingerprint", "")] = "approved"
            elif ev.get("type") == "denial":
                outcome[ev.get("fingerprint", "")] = "denied"
        if self.state != "ready":
            raise RuntimeError("the lab is still starting")
        box = _Sandbox(self.policy, self.model)  # a fresh copy: what was tried in the lab does not colour the replay
        items, seen = [], set()
        for r in records:
            ev = r.get("event", r)
            if ev.get("type") != "decision" or ev.get("verdict") == ALLOW or not ev.get("action"):
                continue
            if ev.get("stage") == "approval" or ev["fingerprint"] in seen:
                continue
            seen.add(ev["fingerprint"])
            act = {k: v for k, v in ev["action"].items() if k in ("identity", "action_type", "resource", "count", "destination")}
            try:
                res = box.run(act, hour=time.gmtime(ev["action"].get("ts") or time.time()).tm_hour)
            except Exception as e:  # noqa: BLE001
                res = {"error": str(e)}
            items.append({"action": act, "live": {"verdict": ev["verdict"], "reasons": ev.get("reasons", [])},
                          "person": outcome.get(ev["fingerprint"], "waiting" if ev["verdict"] == ESCALATE else "-"),
                          "model": res.get("with"), "error": res.get("error")})
        held = [i for i in items if i["live"]["verdict"] == ESCALATE]
        auto = [i for i in held if i["model"] and i["model"]["verdict"] == ALLOW]
        agree_deny = [i for i in held if i["person"] == "denied" and i["model"] and i["model"]["verdict"] != ALLOW]
        miss_deny = [i for i in held if i["person"] == "denied" and i["model"] and i["model"]["verdict"] == ALLOW]
        return {"items": items[-50:], "summary": {
            "held": len(held), "model_would_allow": len(auto), "denied_by_you": sum(i["person"] == "denied" for i in held),
            "model_also_stopped": len(agree_deny), "model_would_have_let_through": len(miss_deny),
            "blocked_by_policy": sum(i["live"]["verdict"] == DENY for i in items)}}


_LAB: Lab | None = None
_LAB_LOCK = threading.Lock()


def lab_for(auth) -> Lab:
    global _LAB
    with _LAB_LOCK:
        if _LAB is None:
            _LAB = Lab(auth.policy, auth.model)
        _LAB.start()
        return _LAB
