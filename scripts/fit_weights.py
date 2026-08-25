# /// script
# requires-python = ">=3.11"
# dependencies = ["numpy", "pandas", "scikit-learn"]
# ///
"""Fit CVSS v3.x base metrics -> EPSS, and report how wrong the mapping is.

Two questions, both needed by the proposal:
  objective 2  -- can p(e) for a misconfig edge be derived from a CVSS vector?
                  Answer = R^2 on held-out CVEs.
  objective 4  -- how big should the weight perturbation be?
                  Answer = the measured residual spread, not a guessed +-10-50%.

Run:  uv run scripts/fit_weights.py
"""
import json
import os
import sys

import numpy as np
import pandas as pd
from sklearn.compose import ColumnTransformer
from sklearn.ensemble import HistGradientBoostingRegressor
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
from sklearn.model_selection import train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JOINED = os.path.join(ROOT, "data", "fit", "cvss_epss_joined.csv")
OUT = os.path.join(ROOT, "data", "fit")
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
SEED = 20260826
# EPSS is published to 5 decimals; clip keeps logit finite at both ends.
EPS = 1e-5


def logit(p):
    p = np.clip(p, EPS, 1 - EPS)
    return np.log(p / (1 - p))


def sigmoid(z):
    return 1.0 / (1.0 + np.exp(-z))


def evaluate(name, model, Xtr, ytr, Xte, yte, p_te):
    """Fit, then score in logit space (where we fit) and probability space
    (where the weights are actually used)."""
    model.fit(Xtr, ytr)
    pred_logit = model.predict(Xte)
    pred_p = sigmoid(pred_logit)
    rel = np.abs(pred_p - p_te) / np.maximum(p_te, EPS)
    return {
        "model": name,
        "r2_logit": float(r2_score(yte, pred_logit)),
        "r2_prob": float(r2_score(p_te, pred_p)),
        "resid_sd_logit": float(np.std(yte - pred_logit, ddof=1)),
        "mae_prob": float(np.mean(np.abs(pred_p - p_te))),
        # Relative error percentiles for perturbation magnitude:
        "rel_err_p50": float(np.percentile(rel, 50)),
        "rel_err_p90": float(np.percentile(rel, 90)),
        "rel_err_p95": float(np.percentile(rel, 95)),
    }


def main():
    if not os.path.exists(JOINED):
        sys.exit(f"missing {JOINED} -- run scripts/pull_data.py first")
    df = pd.read_csv(JOINED)
    df = df.dropna(subset=METRICS + ["epss", "base_score"])
    print(f"rows={len(df)}  EPSS median={df.epss.median():.5f} "
          f"max={df.epss.max():.5f}  p95={df.epss.quantile(0.95):.5f}")
    print(df.cvss_version.value_counts().to_string())

    y = logit(df.epss.to_numpy())
    idx_tr, idx_te = train_test_split(np.arange(len(df)), test_size=0.25,
                                      random_state=SEED)
    p_te = df.epss.to_numpy()[idx_te]

    # 1. the 8 base metrics, kept separate -- the proposal's method
    Xcat = df[METRICS]
    onehot = ColumnTransformer(
        [("oh", OneHotEncoder(handle_unknown="ignore"), METRICS)])
    results = [
        evaluate("ols_8metrics", Pipeline([("p", onehot), ("m", LinearRegression())]),
                 Xcat.iloc[idx_tr], y[idx_tr], Xcat.iloc[idx_te], y[idx_te], p_te),
        evaluate("gbm_8metrics",
                 Pipeline([("p", onehot),
                           ("m", HistGradientBoostingRegressor(random_state=SEED))]),
                 Xcat.iloc[idx_tr], y[idx_tr], Xcat.iloc[idx_te], y[idx_te], p_te),
    ]

    # 2. collapsed base score alone -- shows what the collapse throws away
    Xnum = df[["base_score"]]
    results.append(
        evaluate("ols_basescore_only", LinearRegression(),
                 Xnum.iloc[idx_tr], y[idx_tr], Xnum.iloc[idx_te], y[idx_te], p_te))

    # 3. predict the training mean for everyone -- the floor any model must beat
    class Mean:
        def fit(self, X, y): self.v = float(np.mean(y)); return self
        def predict(self, X): return np.full(len(X), self.v)
    results.append(
        evaluate("constant_baseline", Mean(),
                 Xnum.iloc[idx_tr], y[idx_tr], Xnum.iloc[idx_te], y[idx_te], p_te))

    res = pd.DataFrame(results)
    pd.set_option("display.width", 200)
    print("\n" + res.to_string(index=False))
    res.to_csv(os.path.join(OUT, "fit_report.csv"), index=False)

    best = max(results[:2], key=lambda r: r["r2_logit"])
    verdict = {
        "n_rows": int(len(df)),
        "seed": SEED,
        "best_cvss_only_model": best["model"],
        "r2_logit": best["r2_logit"],
        # Empirical perturbation magnitudes:
        "perturbation_relative_p50": best["rel_err_p50"],
        "perturbation_relative_p90": best["rel_err_p90"],
    }
    with open(os.path.join(OUT, "fit_verdict.json"), "w") as fh:
        json.dump(verdict, fh, indent=2)

    print(f"\nBest CVSS-only model: {best['model']}  R2(logit)={best['r2_logit']:.3f}")
    if best["r2_logit"] < 0.35:
        print("=> LOW R2 on absolute value. This is a finding, not a failure:\n"
              "   CVSS cannot recover EPSS because EPSS is trained on exploitation\n"
              "   telemetry that CVSS deliberately excludes. Objective 2 becomes\n"
              "   'mapping + measured uncertainty', and objective 4 inherits a\n"
              "   perturbation size that was measured rather than guessed:\n"
              f"   median relative error {best['rel_err_p50']*100:.0f}%, "
              f"p90 {best['rel_err_p90']*100:.0f}%.")
    else:
        print("=> R2 high enough that the fitted mapping stands on its own.")


def demo():
    """Self-check: logit/sigmoid round-trip and that
    evaluate() scores a perfect predictor perfectly."""
    p = np.array([1e-5, 0.001, 0.5, 0.97])
    assert np.allclose(sigmoid(logit(p)), p, atol=1e-9), "logit round-trip broken"

    rng = np.random.default_rng(0)
    X = pd.DataFrame({"base_score": rng.uniform(0, 10, 400)})
    truth = logit(sigmoid(X.base_score.to_numpy() - 5))
    tr, te = train_test_split(np.arange(400), test_size=0.25, random_state=0)
    r = evaluate("exact", LinearRegression(), X.iloc[tr], truth[tr],
                 X.iloc[te], truth[te], sigmoid(truth[te]))
    assert r["r2_logit"] > 0.999, r
    assert r["rel_err_p90"] < 1e-6, r
    print("demo ok")


if __name__ == "__main__":
    demo() if "--demo" in sys.argv else main()
