"""The bucketed 24 h feature window: bounded memory for busy identities, and features close to the exact
whole-window scan (only window edges move, by at most a minute), so the trained model scores the same."""

import random
from pathlib import Path

import pytest

from _features_reference import FeatureState as Reference
from authority.actions import Action
from authority.features import FeatureState
from authority.model import RiskModel
from authority.policy import Policy
from authority.scenarios import FAMILIES, world

ROOT = Path(__file__).resolve().parents[1]
META = Policy.load(ROOT / "policies/default.json").identity_meta()
WINDOWED = range(9, 15)  # recent_actions_1h ... exfil_chain


def _compare(events, model=None):
    new, ref = FeatureState(META), Reference(META)
    diffs, total = [], 0
    for i, a in enumerate(events):
        f, g = new.features(a), ref.features(a)
        for j in range(len(f)):
            if j not in WINDOWED:
                assert f[j] == g[j], (i, j, a)  # everything outside the 24 h window is identical
        if model is not None:
            diffs.append(abs(model.score(f) - model.score(g)))
        total += 1
        learn = i % 7 != 3
        new.observe(a, learn=learn)
        ref.observe(a, learn=learn)
    return diffs, total


def test_close_to_exact_on_simulated_worlds():
    model_path = ROOT / "artifacts/risk_model.json"
    model = RiskModel.load(model_path) if model_path.exists() else None
    all_diffs = []
    for seed, fam in enumerate([None, *FAMILIES, None]):
        d, _ = _compare([e.action for e in world(seed + 40, fam, days=45, attack_from=30)], model)
        all_diffs += d
    if model is not None:
        all_diffs.sort()
        assert all_diffs[int(0.99 * (len(all_diffs) - 1))] < 0.05, all_diffs[-20:]


def test_busy_identity_memory_is_bounded():
    st = FeatureState(META)
    t = 1_000_000.0
    rng = random.Random(3)
    for i in range(200_000):  # 200k actions in one day from one identity
        t += 0.43
        a = Action("svc:export-job", "data.read", f"db://crm/t{rng.randrange(30)}/x", 3, ts=t)
        st.features(a)
        st.observe(a)
    w = st._win["svc:export-job"]
    assert len(w.buckets) <= 1441
    assert w.n == sum(b.n for b in w.buckets)
    assert len(w.prefixes) <= 30


@pytest.mark.parametrize("seed", [1, 2])
def test_window_totals_match_after_trimming(seed):
    rng = random.Random(seed)
    st, ref = FeatureState(META), Reference(META)
    t = 2_000_000.0
    for i in range(5000):
        t += rng.choice([1, 30, 600, 7200, 30000])
        a = Action("human:bob", rng.choice(["secret.read", "data.read", "network.egress"]),
                   f"vault://prod/s{rng.randrange(12)}", rng.randrange(1, 9),
                   rng.choice([None, f"s3://b{rng.randrange(4)}"]), ts=t)
        f, g = st.features(a), ref.features(a)
        # the distinct-resource count can differ only through actions within a minute of the window edge
        assert abs(f[11] - g[11]) < 0.7
        st.observe(a)
        ref.observe(a)
