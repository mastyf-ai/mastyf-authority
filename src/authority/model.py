"""Behavioural risk model. It can only raise an action to escalate or deny; it never grants."""

from __future__ import annotations

from pathlib import Path

import numpy as np
from sklearn.ensemble import HistGradientBoostingClassifier, IsolationForest

from .features import FEATURE_NAMES, FeatureState
from .scenarios import Event

MODEL_FORMAT = 2


def featurize(events: list[Event], identity_meta: dict[str, dict]) -> tuple[np.ndarray, np.ndarray, list[Event]]:
    """Replay a world in time order. Every event updates the baseline, attacks included:
    a conservative stand-in for an attacker who is never stopped and slowly becomes 'normal'."""
    st = FeatureState(identity_meta)
    X, y = [], []
    for e in events:
        X.append(st.features(e.action))
        y.append(e.label)
        st.observe(e.action, learn=True)
    return np.asarray(X, dtype=np.float32), np.asarray(y, dtype=np.int8), events


class RiskModel:
    """Two parts, final risk = max of both:
    - supervised: gradient-boosted trees on labelled attack/benign traces (known attack shapes)
    - anomaly: isolation forest fitted on benign behaviour only (unknown attack shapes),
      calibrated on held-out benign rows so that the top 0.5% of normal behaviour maps to
      0.5 (escalate) and the top 0.01% maps to 0.9 (deny).
    """

    def __init__(self, clf: HistGradientBoostingClassifier, iso: IsolationForest | None = None,
                 q: tuple[float, float, float] | None = None, meta: dict | None = None):
        self.clf = clf
        self.iso = iso
        self.q = q
        self.meta = meta or {}

    @classmethod
    def train(cls, X: np.ndarray, y: np.ndarray, seed: int = 0) -> "RiskModel":
        clf = HistGradientBoostingClassifier(
            max_iter=300,
            learning_rate=0.08,
            max_leaf_nodes=31,
            l2_regularization=1.0,
            class_weight="balanced",
            random_state=seed,
        )
        clf.fit(X, y)
        rng = np.random.default_rng(seed)
        benign = X[y == 0]
        idx = rng.permutation(len(benign))
        fit_rows, cal_rows = benign[idx[: min(60_000, len(idx) // 2)]], benign[idx[len(idx) // 2:]]
        iso = IsolationForest(n_estimators=200, max_samples=4096, random_state=seed).fit(fit_rows)
        cal = -iso.score_samples(cal_rows)  # higher = more anomalous
        q = (float(np.quantile(cal, 0.995)), float(np.quantile(cal, 0.9999)), float(cal.max()))
        return cls(clf, iso, q, {"n": int(len(y)), "positives": int(y.sum()), "anomaly_quantiles": q})

    def anomaly_risk(self, X: np.ndarray) -> np.ndarray:
        if self.iso is None:
            return np.zeros(len(X))
        s = -self.iso.score_samples(X)
        q995, q9999, qmax = self.q
        span_hi = max(qmax - q9999, 1e-6)
        return np.interp(s, [0.0, q995, q9999, q9999 + 2 * span_hi], [0.0, 0.5, 0.9, 1.0])

    def supervised_risk(self, X: np.ndarray) -> np.ndarray:
        return self.clf.predict_proba(X)[:, 1]

    def score_many(self, X: np.ndarray) -> np.ndarray:
        return np.maximum(self.supervised_risk(X), self.anomaly_risk(X))

    def score(self, features: list[float]) -> float:
        return float(self.score_many(np.asarray([features], dtype=np.float32))[0])

    def save(self, path: str | Path) -> None:
        """Writes the data-only JSON format (no pickle). `path` may end in .json or .pkl."""
        from .model_json import save_json
        path = Path(path).with_suffix(".json")
        path.parent.mkdir(parents=True, exist_ok=True)
        save_json(self, path)

    @classmethod
    def load(cls, path: str | Path):
        """Loads the data-only JSON model; nothing in the file can run code. Only JSON is accepted."""
        from .model_json import load_json
        path = Path(path)
        if path.suffix != ".json":
            path = path.with_suffix(".json")
        if not path.exists():
            raise ValueError(f"model file not found: {path} (models are JSON only)")
        return load_json(path)
