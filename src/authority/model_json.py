"""Data-only model format: no pickle, nothing executable in the file.

Exports the trained risk model (gradient-boosted trees + isolation forest + calibration) to plain
JSON arrays and evaluates it with a small numpy evaluator that must reproduce sklearn's scores.
Loading a JSON model can never run code, unlike unpickling.
"""

from __future__ import annotations

import hashlib
import json
import math
from pathlib import Path

import numpy as np

from .features import FEATURE_NAMES

FORMAT = "mastyf-risk-model/1"
EULER = 0.5772156649015329


def _avg_path(n: np.ndarray) -> np.ndarray:
    n = np.asarray(n, dtype=np.float64)
    out = np.zeros_like(n)
    two = n == 2
    big = n > 2
    out[two] = 1.0
    out[big] = 2.0 * (np.log(n[big] - 1.0) + EULER) - 2.0 * (n[big] - 1.0) / n[big]
    return out


def export(model) -> dict:
    clf, iso = model.clf, model.iso
    trees = []
    for it in clf._predictors:
        nodes = it[0].nodes
        trees.append({
            "feature": nodes["feature_idx"].astype(int).tolist(),
            "threshold": nodes["num_threshold"].astype(float).tolist(),
            "left": nodes["left"].astype(int).tolist(),
            "right": nodes["right"].astype(int).tolist(),
            "leaf": nodes["is_leaf"].astype(int).tolist(),
            "missing_left": nodes["missing_go_to_left"].astype(int).tolist(),
            "value": nodes["value"].astype(float).tolist(),
        })
    if any(it[0].nodes["is_categorical"].any() for it in clf._predictors):
        raise ValueError("categorical splits are not supported by the JSON format")
    forest = None
    if iso is not None:
        forest = {"max_samples": int(iso.max_samples_), "trees": []}
        for est, feats in zip(iso.estimators_, iso.estimators_features_):
            t = est.tree_
            forest["trees"].append({
                "features": [int(f) for f in feats],
                "feature": t.feature.astype(int).tolist(),
                "threshold": t.threshold.astype(float).tolist(),
                "left": t.children_left.astype(int).tolist(),
                "right": t.children_right.astype(int).tolist(),
                "n": t.n_node_samples.astype(int).tolist(),
            })
    return {
        "format": FORMAT,
        "features": FEATURE_NAMES,
        "gbt": {"baseline": float(np.ravel(clf._baseline_prediction)[0]), "trees": trees},
        "iforest": forest,
        "calibration": list(model.q) if model.q else None,
        "meta": model.meta,
    }


class JsonRiskModel:
    """Evaluates an exported model. Same interface as RiskModel.score / score_many."""

    def __init__(self, d: dict):
        if d.get("format") != FORMAT:
            raise ValueError("unknown model format")
        if d.get("features") != FEATURE_NAMES:
            raise ValueError("model was trained with a different feature set; retrain")
        self.d = d
        self.meta = d.get("meta", {})
        self.gbt = [{k: np.asarray(v) for k, v in t.items()} for t in d["gbt"]["trees"]]
        self.base = d["gbt"]["baseline"]
        f = d.get("iforest")
        self.iso = None if f is None else [{k: np.asarray(v) for k, v in t.items()} for t in f["trees"]]
        self.max_samples = f["max_samples"] if f else 0
        self.q = tuple(d["calibration"]) if d.get("calibration") else None
        # plain-Python copies for the one-row path (a live decision): numpy per-node overhead dominates there
        self._gbt_l = [tuple(t[k].tolist() for k in ("leaf", "feature", "threshold", "missing_left", "left", "right", "value"))
                       for t in self.gbt]
        self._iso_l = None if self.iso is None else [
            (t["features"].tolist(), t["feature"].tolist(), t["threshold"].astype(np.float32).tolist(), t["left"].tolist(),
             t["right"].tolist(), _avg_path(t["n"]).tolist()) for t in self.iso]
        self._iso_norm = len(self.iso) * _avg_path(np.array([self.max_samples]))[0] if self.iso else 1.0

    def supervised_risk(self, X: np.ndarray) -> np.ndarray:
        X = np.asarray(X, dtype=np.float64)
        raw = np.full(len(X), self.base)
        for t in self.gbt:
            node = np.zeros(len(X), dtype=np.int64)
            active = t["leaf"][node] == 0
            while active.any():
                idx = np.where(active)[0]
                n = node[idx]
                xv = X[idx, t["feature"][n]]
                go_left = np.where(np.isnan(xv), t["missing_left"][n] == 1, xv <= t["threshold"][n])
                node[idx] = np.where(go_left, t["left"][n], t["right"][n])
                active = t["leaf"][node] == 0
            raw += t["value"][node]
        return 1.0 / (1.0 + np.exp(-raw))

    def anomaly_risk(self, X: np.ndarray) -> np.ndarray:
        if self.iso is None:
            return np.zeros(len(X))
        X = np.asarray(X, dtype=np.float32)
        depth = np.zeros(len(X))
        for t in self.iso:
            Xs = X[:, t["features"]]
            node = np.zeros(len(X), dtype=np.int64)
            d = np.zeros(len(X))
            active = t["left"][node] != -1
            while active.any():
                idx = np.where(active)[0]
                n = node[idx]
                go_left = Xs[idx, t["feature"][n]] <= t["threshold"][n].astype(np.float32)
                node[idx] = np.where(go_left, t["left"][n], t["right"][n])
                d[idx] += 1
                active = t["left"][node] != -1
            depth += d + _avg_path(t["n"][node])
        scores = 2.0 ** (-depth / (len(self.iso) * _avg_path(np.array([self.max_samples]))[0]))
        s = scores  # = -score_samples
        q995, q9999, qmax = self.q
        span_hi = max(qmax - q9999, 1e-6)
        return np.interp(s, [0.0, q995, q9999, q9999 + 2 * span_hi], [0.0, 0.5, 0.9, 1.0])

    def score_many(self, X: np.ndarray) -> np.ndarray:
        return np.maximum(self.supervised_risk(X), self.anomaly_risk(X))

    def score(self, features: list[float]) -> float:
        """One row, same result as score_many (tested), ~20x faster for a single decision."""
        import math
        x = [float(v) for v in features]
        raw = self.base
        for leaf, feat, thr, miss, left, right, value in self._gbt_l:
            n = 0
            while not leaf[n]:
                v = x[feat[n]]
                n = (left[n] if miss[n] == 1 else right[n]) if v != v else (left[n] if v <= thr[n] else right[n])
            raw += value[n]
        sup = 1.0 / (1.0 + math.exp(-raw))
        if self._iso_l is None:
            return sup
        x32 = np.asarray(x, dtype=np.float32).tolist()  # same float32 rounding as the batch path
        depth = 0.0
        for feats, feat, thr, left, right, avg in self._iso_l:
            n, d = 0, 0
            while left[n] != -1:
                n = left[n] if x32[feats[feat[n]]] <= thr[n] else right[n]
                d += 1
            depth += d + avg[n]
        s = 2.0 ** (-depth / self._iso_norm)
        q995, q9999, qmax = self.q
        span_hi = max(qmax - q9999, 1e-6)
        anom = float(np.interp(s, [0.0, q995, q9999, q9999 + 2 * span_hi], [0.0, 0.5, 0.9, 1.0]))
        return max(sup, anom)


def save_json(model, path: str | Path) -> None:
    path = Path(path)
    blob = json.dumps(export(model), separators=(",", ":")).encode()
    path.write_bytes(blob)
    path.with_suffix(".json.sha256").write_text(hashlib.sha256(blob).hexdigest())


def load_json(path: str | Path) -> JsonRiskModel:
    path = Path(path)
    blob = path.read_bytes()
    side = path.with_suffix(".json.sha256")
    if side.exists() and hashlib.sha256(blob).hexdigest() != side.read_text().strip():
        raise ValueError("model checksum mismatch")
    d = json.loads(blob)
    if not math.isfinite(d["gbt"]["baseline"]):
        raise ValueError("bad model")
    return JsonRiskModel(d)
