//! The tree walks of `authority.model_json.JsonRiskModel.score`, in Rust: the gradient-boosted trees' summed
//! margin and the isolation forest's summed depth, in the same order and precision as the Python reference
//! (f64 sums; f32-rounded features for the forest). The final transcendental steps (exp, pow, interp) stay in
//! Python: Rust's and the C library's exp differ in the last bit. Scores are bit-identical
//! (tests/test_native.py). Loaded only from the JSON model (data, never code).
#![forbid(unsafe_code)]
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;
use serde_json::Value;

const EULER: f64 = 0.5772156649015329;

struct Gbt {
    leaf: Vec<bool>,
    feature: Vec<usize>,
    threshold: Vec<f64>,
    missing_left: Vec<bool>,
    left: Vec<usize>,
    right: Vec<usize>,
    value: Vec<f64>,
}

struct Iso {
    features: Vec<usize>,
    feature: Vec<usize>,
    threshold: Vec<f32>,
    left: Vec<i64>,
    right: Vec<i64>,
    avg: Vec<f64>,
}

fn avg_path(n: f64) -> f64 {
    if n > 2.0 {
        2.0 * ((n - 1.0).ln() + EULER) - 2.0 * (n - 1.0) / n
    } else if n == 2.0 {
        1.0
    } else {
        0.0
    }
}

fn vec_f(v: &Value, k: &str) -> PyResult<Vec<f64>> {
    v[k].as_array().ok_or_else(|| PyValueError::new_err(format!("model: {k}")))?
        .iter().map(|x| x.as_f64().ok_or_else(|| PyValueError::new_err(format!("model: {k}")))).collect()
}

fn vec_i(v: &Value, k: &str) -> PyResult<Vec<i64>> {
    v[k].as_array().ok_or_else(|| PyValueError::new_err(format!("model: {k}")))?
        .iter().map(|x| x.as_i64().ok_or_else(|| PyValueError::new_err(format!("model: {k}")))).collect()
}

#[pyclass(frozen)]
struct Scorer {
    base: f64,
    gbt: Vec<Gbt>,
    iso: Option<Vec<Iso>>,
    n_features: usize,
}

#[pymethods]
impl Scorer {
    #[new]
    fn new(model_json: &str) -> PyResult<Self> {
        let d: Value = serde_json::from_str(model_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let n_features = d["features"].as_array().map(|a| a.len()).unwrap_or(0);
        let base = d["gbt"]["baseline"].as_f64().ok_or_else(|| PyValueError::new_err("model: baseline"))?;
        let mut gbt = vec![];
        for t in d["gbt"]["trees"].as_array().ok_or_else(|| PyValueError::new_err("model: trees"))? {
            let idx = |v: Vec<i64>| -> PyResult<Vec<usize>> {
                v.into_iter().map(|x| usize::try_from(x).map_err(|_| PyValueError::new_err("model: negative index")))
                    .collect()
            };
            let g = Gbt {
                leaf: vec_i(t, "leaf")?.into_iter().map(|x| x != 0).collect(),
                feature: idx(vec_i(t, "feature")?)?,
                threshold: vec_f(t, "threshold")?,
                missing_left: vec_i(t, "missing_left")?.into_iter().map(|x| x == 1).collect(),
                left: idx(vec_i(t, "left")?)?,
                right: idx(vec_i(t, "right")?)?,
                value: vec_f(t, "value")?,
            };
            let n = g.leaf.len();
            if [g.feature.len(), g.threshold.len(), g.missing_left.len(), g.left.len(), g.right.len(), g.value.len()]
                .iter().any(|&l| l != n)
                || (0..n).any(|i| !g.leaf[i] && (g.left[i] >= n || g.right[i] >= n || g.feature[i] >= n_features))
            {
                return Err(PyValueError::new_err("model: malformed tree"));
            }
            gbt.push(g);
        }
        let iso = match d.get("iforest") {
            Some(f) if !f.is_null() => {
                let mut trees = vec![];
                for t in f["trees"].as_array().ok_or_else(|| PyValueError::new_err("model: iforest"))? {
                    let feats: Vec<usize> = vec_i(t, "features")?.into_iter().map(|x| x as usize).collect();
                    let n: Vec<f64> = vec_i(t, "n")?.into_iter().map(|x| x as f64).collect();
                    let it = Iso {
                        features: feats,
                        feature: vec_i(t, "feature")?.into_iter().map(|x| x.max(0) as usize).collect(),
                        threshold: vec_f(t, "threshold")?.into_iter().map(|x| x as f32).collect(),
                        left: vec_i(t, "left")?,
                        right: vec_i(t, "right")?,
                        avg: n.iter().map(|&x| avg_path(x)).collect(),
                    };
                    trees.push(it);
                }
                Some(trees)
            }
            _ => None,
        };
        Ok(Scorer { base, gbt, iso, n_features })
    }

    /// The trees' summed raw margin (the risk is 1/(1+exp(-raw))).
    fn raw(&self, x: Vec<f64>) -> PyResult<f64> {
        if x.len() < self.n_features {
            return Err(PyValueError::new_err("too few features"));
        }
        let mut raw = self.base;
        for t in &self.gbt {
            let mut n = 0;
            while !t.leaf[n] {
                let v = x[t.feature[n]];
                n = if v.is_nan() {
                    if t.missing_left[n] { t.left[n] } else { t.right[n] }
                } else if v <= t.threshold[n] { t.left[n] } else { t.right[n] };
            }
            raw += t.value[n];
        }
        Ok(raw)
    }

    /// The isolation forest's summed path depth (f32-rounded features, as the Python reference), or None.
    fn iso_depth(&self, x: Vec<f64>) -> Option<f64> {
        let iso = self.iso.as_ref()?;
        if x.len() < self.n_features {
            return None;
        }
        let x32: Vec<f32> = x.iter().map(|&v| v as f32).collect();
        let mut depth = 0.0;
        for t in iso {
            let (mut n, mut d) = (0usize, 0.0);
            while t.left[n] != -1 {
                let v = x32[t.features[t.feature[n]]];
                n = if v <= t.threshold[n] { t.left[n] as usize } else { t.right[n] as usize };
                d += 1.0;
            }
            depth += d + t.avg[n];
        }
        Some(depth)
    }
}

#[pymodule]
fn _native(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<Scorer>()?;
    Ok(())
}
