"""The one-row scoring path (used for every live decision) must equal the batch path exactly."""

from pathlib import Path

import numpy as np
import pytest

from authority.model import RiskModel

MODEL = Path(__file__).resolve().parents[1] / "artifacts" / "risk_model.json"


@pytest.mark.skipif(not MODEL.exists(), reason="train a model first")
def test_single_row_equals_batch():
    m = RiskModel.load(MODEL)
    rng = np.random.default_rng(1)
    X = np.abs(rng.normal(0, 4, (4000, len(m.d["features"]))))
    X[::7, 3] = np.nan
    X[::3] = np.round(X[::3])
    X[::11] = 0
    assert np.array_equal(m.score_many(X), np.array([m.score(list(r)) for r in X]), equal_nan=True)
