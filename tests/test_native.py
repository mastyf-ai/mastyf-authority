"""The Rust scorer (authority._native) must give bit-identical scores to the Python reference, on real
feature rows, random and hostile values, and a model that also has an isolation forest."""

import json
import math
import random
from pathlib import Path

import numpy as np
import pytest

from authority.features import FEATURE_NAMES, FeatureState
from authority.model_json import JsonRiskModel
from authority.policy import Policy
from authority.scenarios import FAMILIES, world

native = pytest.importorskip("authority._native")
ROOT = Path(__file__).resolve().parents[1]
MODEL = ROOT / "artifacts/risk_model.json"


def _rows(n_random: int, seed: int = 1):
    st = FeatureState(Policy.load(ROOT / "policies/default.json").identity_meta())
    rows = []
    for k, fam in enumerate([None, *FAMILIES]):
        for e in world(70 + k, fam, days=30, attack_from=20):
            rows.append(st.features(e.action))
            st.observe(e.action)
    rng = random.Random(seed)
    nf = len(FEATURE_NAMES)
    specials = [0.0, -0.0, 1e-300, -1e300, 1e300, float("inf"), float("-inf"), float("nan"), 0.5, 1.0]
    for _ in range(n_random):
        r = [rng.choice(specials) if rng.random() < 0.05 else rng.uniform(-5, 50) * 10 ** rng.randint(-3, 4)
             for _ in range(nf)]
        rows.append(r)
    return rows


def _same(a, b):
    return a == b or (math.isnan(a) and math.isnan(b))


@pytest.mark.skipif(not MODEL.exists(), reason="trained model not present")
def test_shipped_model_bit_identical():
    m = JsonRiskModel(json.loads(MODEL.read_text()))
    assert m._native is not None
    rows = _rows(1_000_000)
    bad = [(r, m.score_py(r), m.score(r)) for r in rows if not _same(m.score_py(r), m.score(r))]
    assert not bad, bad[:3]


def test_isolation_forest_path_bit_identical():
    from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

    from authority.model import RiskModel
    from authority.model_json import export
    rows = _rows(0)
    X = np.asarray(rows[:6000], dtype=float)
    y = (np.random.default_rng(0).random(len(X)) < 0.1).astype(int)
    clf = HistGradientBoostingClassifier(max_iter=20).fit(X, y)
    iso = IsolationForest(n_estimators=25, random_state=0).fit(X)
    rm = RiskModel(clf, iso)
    s = -iso.score_samples(X)
    rm.q = (float(np.quantile(s, 0.995)), float(np.quantile(s, 0.9999)), float(s.max()))
    m = JsonRiskModel(export(rm))
    assert m._native is not None and m.iso is not None
    test = _rows(100_000, seed=2)
    bad = [r for r in test if not _same(m.score_py(r), m.score(r))]
    assert not bad, (len(bad), bad[:2])
