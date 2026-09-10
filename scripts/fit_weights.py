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
from sklearn.model_selection import KFold, cross_val_predict, train_test_split
from sklearn.pipeline import Pipeline
from sklearn.preprocessing import OneHotEncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JOINED = os.path.join(
    ROOT, "data", "fit",
    next((a for a in sys.argv[1:] if a.endswith(".csv")), "cvss_epss_joined.csv"))
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
    """Fit, then score three ways.

    Pooled R^2 is the wrong headline on its own: EPSS is heavily skewed toward
    ~0.0005, so pooled R^2 is dominated by the near-zero mass. But w(e)=-log p
    means low-p edges cost so much the attacker never takes them -- the choke
    point ranking is decided by the UPPER TAIL. And because the ranking is what
    the project claims, rank correlation matters more than absolute accuracy: a
    fit can miss every value yet order the edges correctly, and the choke points
    still come out right. Hence pooled R^2, tail R^2, and Spearman rho.
    """
    model.fit(Xtr, ytr)
    pred_logit = model.predict(Xte)
    pred_p = sigmoid(pred_logit)
    signed_rel = (pred_p - p_te) / np.maximum(p_te, EPS)
    rel = np.abs(signed_rel)
    tail = p_te >= np.percentile(p_te, 90)
    # tie-aware ranks: EPSS has huge ties at the low end, so a naive argsort
    # ranking would overstate agreement.
    rho = float(pd.Series(pred_p).corr(pd.Series(p_te), method="spearman"))
    return {
        "model": name,
        "r2_logit": float(r2_score(yte, pred_logit)),
        "r2_prob": float(r2_score(p_te, pred_p)),
        "r2_prob_top10pct": float(r2_score(p_te[tail], pred_p[tail])),
        "spearman_rho": rho,
        "resid_sd_logit": float(np.std(yte - pred_logit, ddof=1)),
        "mae_prob": float(np.mean(np.abs(pred_p - p_te))),
        # Relative error percentiles for perturbation magnitude:
        "rel_err_p50": float(np.percentile(rel, 50)),
        "rel_err_p90": float(np.percentile(rel, 90)),
        "rel_err_p95": float(np.percentile(rel, 95)),
        # asymmetry: if these two are far apart, a +-X% band is the wrong shape
        "signed_rel_p05": float(np.percentile(signed_rel, 5)),
        "signed_rel_p95": float(np.percentile(signed_rel, 95)),
        "frac_overpredicted": float(np.mean(signed_rel > 0)),
        "_resid_logit": yte - pred_logit,
        "_pred_p": pred_p,
    }


def export_coeffs(fitted, X_sample):
    """data/fit/fit_coeffs.json -- additive on the logit scale.

    Consumer contract (attackpath/weights.py):
        logit_p = intercept + sum(terms[f"{metric}:{level}"] for the 8 metrics)
        p       = 1 / (1 + exp(-logit_p))

    Levels are emitted as CVSS abbreviations (AV:N, AC:L, ...) not sklearn's
    spelled-out category names, so the keys match a vector string directly.
    """
    abbr = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P",
            "LOW": "L", "HIGH": "H", "NONE": "N", "REQUIRED": "R",
            "UNCHANGED": "U", "CHANGED": "C"}
    enc = fitted.named_steps["p"].named_transformers_["oh"]
    lin = fitted.named_steps["m"]
    terms = {}
    for name, coef in zip(enc.get_feature_names_out(METRICS), lin.coef_):
        metric, level = name.split("_", 1)
        terms[f"{metric}:{abbr.get(level, level)}"] = float(coef)
    # VERIFY the published contract end to end. Callers reconstruct p by summing
    # terms; every metric reported above came from the pipeline's .predict()
    # instead, so without this the JSON could disagree with the model and
    # weights.py would compute a wrong p(e) for every misconfig edge.
    # OneHotEncoder with no drop leaves the design rank-deficient, so lstsq
    # returns one of many valid solutions -- reconstruction should still be
    # exact, but "should" is not verified.
    inv = {"AV": {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L",
                  "PHYSICAL": "P"},
           "AC": {"LOW": "L", "HIGH": "H"},
           "PR": {"NONE": "N", "LOW": "L", "HIGH": "H"},
           "UI": {"NONE": "N", "REQUIRED": "R"},
           "S": {"UNCHANGED": "U", "CHANGED": "C"},
           "C": {"NONE": "N", "LOW": "L", "HIGH": "H"},
           "I": {"NONE": "N", "LOW": "L", "HIGH": "H"},
           "A": {"NONE": "N", "LOW": "L", "HIGH": "H"}}
    smp = X_sample.head(500)
    manual = np.array([
        float(lin.intercept_) + sum(terms[f"{m}:{inv[m][row[m]]}"] for m in METRICS)
        for _, row in smp.iterrows()])
    direct = fitted.predict(smp)
    gap = float(np.max(np.abs(manual - direct)))
    assert gap < 1e-6, (
        f"fit_coeffs.json does not reproduce the model: max gap {gap:.2e}. "
        f"Downstream p(e) would be wrong for every fitted edge.")
    print(f"coeffs contract verified on {len(smp)} rows (max gap {gap:.2e})")

    payload = {"intercept": float(lin.intercept_), "terms": terms,
               "scale": "logit", "cvss_version": "3.x", "seed": SEED,
               "contract": "p = 1/(1+exp(-(intercept + sum of the 8 selected terms)))",
               "verified_max_abs_gap": gap}
    with open(os.path.join(OUT, "fit_coeffs.json"), "w") as fh:
        json.dump(payload, fh, indent=2, sort_keys=True)
    print(f"coeffs -> fit_coeffs.json ({len(terms)} terms, additive on logit)")


def skew(x):
    """Sample skewness. numpy only -- scipy would be a dependency for one line."""
    x = np.asarray(x, float)
    c = x - x.mean()
    return float((c**3).mean() / (c**2).mean() ** 1.5)


def residual_report(df_te, resid, pred_p):
    """The shape of the error, not just its width.

    Check whether the measured residual spread can replace the arbitrary
    +-10-50% perturbation band. That is only legitimate if the residuals are
    roughly symmetric and roughly homoscedastic across CVSS metric levels --
    otherwise a symmetric band misstates the real uncertainty. So report both.
    """
    qs = [1, 5, 10, 25, 50, 75, 90, 95, 99]
    print("\nresidual (logit space) percentiles:")
    print("  " + "  ".join(f"p{q}={np.percentile(resid, q):+.2f}" for q in qs))
    print(f"  sd={np.std(resid, ddof=1):.3f}  skew={skew(resid):+.3f}  "
          f"mean={np.mean(resid):+.3f}  median={np.median(resid):+.3f}")

    rows = []
    for m in METRICS:
        for lvl, grp in df_te.groupby(m, observed=True):
            r = resid[df_te[m].to_numpy() == lvl]
            if len(r) < 30:
                continue
            rows.append({"metric": m, "level": lvl, "n": len(r),
                         "resid_median": float(np.median(r)),
                         "resid_sd": float(np.std(r, ddof=1)),
                         "resid_iqr": float(np.percentile(r, 75) - np.percentile(r, 25)),
                         "epss_median": float(grp.epss.median())})
    by_level = pd.DataFrame(rows)
    print("\nresiduals by CVSS metric level (heteroscedasticity check):")
    print(by_level.to_string(index=False))
    by_level.to_csv(os.path.join(OUT, "residuals_by_level.csv"), index=False)

    spread = by_level.resid_sd
    ratio = float(spread.max() / spread.min()) if len(spread) else float("nan")
    print(f"\nsd ratio across levels = {ratio:.2f}x "
          f"({'homoscedastic enough for one band' if ratio < 1.5 else 'HETEROSCEDASTIC -- one global band misstates uncertainty; perturb per metric level'})")

    # Contract read by attackpath/robustness.py -- do not rename these.
    #   resid_logit = logit(epss_true) - logit(epss_pred)   (positive => the
    #   fit UNDER-predicted, true exploitability is higher than CVSS suggests)
    keep = ["cve", "published", "vector", "base_score"]
    if "nvd_page" in df_te:
        keep.insert(2, "nvd_page")
    out = df_te[keep + METRICS].copy()
    out["epss_true"] = df_te.epss.to_numpy()
    out["epss_pred"] = pred_p
    out["resid_logit"] = resid
    out["resid_log"] = (np.log(np.clip(df_te.epss.to_numpy(), EPS, 1))
                        - np.log(np.clip(pred_p, EPS, 1)))
    out.to_csv(os.path.join(OUT, "residuals.csv"), index=False)
    # --- path-order preservation -------------------------------------------
    # Rank correlation on EDGES does not imply correct PATH order: path cost is
    # a SUM of -log p, and a monotone per-edge map can reverse it (two edges at
    # p=.9 beat one at p=.8, but a map .9->.5/.8->.45 flips that). Order IS
    # preserved exactly when the fit is a power law p_hat ~ p^k, because then
    # -log p_hat = k(-log p) rescales every path cost by the same k.
    # So the governing quantity is the spread of the LOG-space residual
    #     r = log(p_true) - log(p_pred)
    # not rho. With |r| <= delta on every edge, two paths keep their order
    # whenever their true cost gap exceeds delta * (len(P) + len(Q)).
    p_true = df_te.epss.to_numpy()
    r_log = np.log(np.clip(p_true, EPS, 1)) - np.log(np.clip(pred_p, EPS, 1))
    r_log -= np.median(r_log)          # a constant offset IS the power-law k
    d50, d90 = np.percentile(np.abs(r_log), [50, 90])
    print(f"\nlog-space residual after removing the constant (power-law) part:"
          f"  p50={d50:.3f}  p90={d90:.3f} nats")

    # Measure the perturbation magnitude for the edges that actually decide
    # paths. Under w = -log p those are the upper-tail ones, so a pooled |r|
    # misstates the band whenever the residuals are heteroscedastic -- and they
    # are. Report the tail separately.
    cut = np.percentile(p_true, 90)
    bands = {"pooled": np.ones(len(r_log), bool),
             "bottom 90%": p_true < cut,
             "TOP EPSS DECILE": p_true >= cut}
    print("  |r| by EPSS band (top-decile row governs shortest paths):")
    tail50 = tail90 = None
    for name, mask in bands.items():
        if mask.sum() < 30:
            continue
        a = np.abs(r_log[mask])
        q50, q90 = np.percentile(a, [50, 90])
        print(f"    {name:18s} n={mask.sum():<6d} p50={q50:.3f}  p90={q90:.3f} nats")
        if name.startswith("TOP"):
            tail50, tail90 = q50, q90

    print("  path-order resolution -- two paths keep their true order only if\n"
          "  their cost gap (nats of -log p) exceeds delta*(lenP+lenQ):")
    for L in (2, 4, 8):
        line = (f"    paths of {L} edges each: gap must exceed "
                f"{2*L*d50:.2f} (pooled p50) / {2*L*d90:.2f} (pooled p90) nats")
        if tail50 is not None:
            line += f"  | top decile: {2*L*tail50:.2f} / {2*L*tail90:.2f}"
        print(line)
    print("  NOTE: necessary condition only. exp 6 measures the real thing.")

    # Cluster check. NVD is CVE-ID ordered, so each page is a narrow publication
    # window and --stride 6 samples ~33 of 192 windows: this is a CLUSTER sample
    # of windows, not a representative draw of 2017-2026. Which CVEs land in the
    # top EPSS decile is time-correlated (one window holding a mass-exploited
    # family drags the tail), so the top-decile point estimate needs its
    # between-page spread reported next to it.
    if "nvd_page" in df_te:
        per = []
        for pg, g in df_te.assign(_r=np.abs(r_log)).groupby("nvd_page"):
            tail_g = g[g.epss >= cut]
            if len(tail_g) >= 30:
                per.append(tail_g._r.median())
        if len(per) >= 5:
            per = np.array(per)
            print(f"  top-decile |r| p50 ACROSS {len(per)} NVD pages: "
                  f"min={per.min():.3f} p25={np.percentile(per,25):.3f} "
                  f"median={np.median(per):.3f} p75={np.percentile(per,75):.3f} "
                  f"max={per.max():.3f}")
            se = per.std(ddof=1) / np.sqrt(len(per))
            print(f"  between-page sd={per.std(ddof=1):.3f}  cluster SE of the "
                  f"mean={se:.3f}  => report 1.79 +/- {1.96*se:.2f}, not a bare "
                  f"point estimate")

    cells = out.groupby("vector").size()
    print(f"per-CVE residuals -> {os.path.join(OUT, 'residuals.csv')}  "
          f"({len(out)} rows, {len(cells)} distinct vectors, "
          f"median {cells.median():.0f}/vector, "
          f"{(cells >= 10).sum()} vectors with >=10 residuals)")
    return {"resid_log_abs_p50": float(d50), "resid_log_abs_p90": float(d90),
            "resid_log_abs_p50_top_decile": None if tail50 is None else float(tail50),
            "resid_log_abs_p90_top_decile": None if tail90 is None else float(tail90)}


def main():
    if not os.path.exists(JOINED):
        sys.exit(f"missing {JOINED} -- run scripts/pull_data.py first")
    df = pd.read_csv(JOINED)
    df = df.dropna(subset=METRICS + ["epss", "base_score", "published"])
    # NVD only began scoring v3 systematically in 2016. Pre-2016 CVEs carry a v3
    # vector only if someone revisited them later -- which skews toward the
    # notable, actually-exploited ones, i.e. high EPSS. Including that subgroup
    # biases the fit. Drop it.
    before = len(df)
    df = df[df.published.astype(str) >= "2016-01-01"]
    if before != len(df):
        print(f"dropped {before - len(df)} pre-2016 CVEs (backfilled v3, biased subgroup)")
    print(f"rows={len(df)}  EPSS median={df.epss.median():.5f} "
          f"max={df.epss.max():.5f}  p95={df.epss.quantile(0.95):.5f}")
    print(df.cvss_version.value_counts().to_string())

    if len(df) < 500:
        sys.exit(f"only {len(df)} usable rows -- too thin to fit. Let the pull "
                 f"run longer, or lower --stride in scripts/pull_data.py.")

    # Effective sample size, not row count. CVEs arrive in correlated batches
    # (same CNA, same day, identical vector, often identical EPSS), so rows are
    # near-duplicates. The model is really a per-vector-cell mean lookup, which
    # is exactly what "what p do I assign this vector" needs -- but perturbation analysis consumes
    # the UNCERTAINTY on each cell mean, and that is governed by the number of
    # distinct cells and how many rows back each one, not by len(df).
    cells = df.groupby(METRICS, observed=True).size()
    print(f"distinct CVSS metric cells={len(cells)}  "
          f"rows/cell median={cells.median():.0f} p10={cells.quantile(.1):.0f} "
          f"max={cells.max()}")
    if "scorer" in df:
        print("scorer mix: " + df.scorer.value_counts().to_dict().__repr__())
    print("published range: " + df.published.min() + " .. " + df.published.max())
    print("by year: " + df.published.str[:4].value_counts().sort_index().to_dict().__repr__())

    y = logit(df.epss.to_numpy())
    idx_tr, idx_te = train_test_split(np.arange(len(df)), test_size=0.25,
                                      random_state=SEED)
    p_te = df.epss.to_numpy()[idx_te]

    # 1. the 8 base metrics, kept separate -- the proposal's method
    Xcat = df[METRICS]
    onehot = ColumnTransformer(
        [("oh", OneHotEncoder(handle_unknown="ignore"), METRICS)])
    ols = Pipeline([("p", onehot), ("m", LinearRegression())])
    results_models = {"ols_8metrics": ols}
    results = [
        evaluate("ols_8metrics", ols,
                 Xcat.iloc[idx_tr], y[idx_tr], Xcat.iloc[idx_te], y[idx_te], p_te),
        evaluate("gbm_8metrics",
                 results_models.setdefault("gbm_8metrics", Pipeline(
                     [("p", onehot),
                      ("m", HistGradientBoostingRegressor(random_state=SEED))])),
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

    residuals = {r["model"]: (r.pop("_resid_logit"), r.pop("_pred_p"))
                 for r in results}
    export_coeffs(results_models["ols_8metrics"], Xcat)
    res = pd.DataFrame(results)
    pd.set_option("display.width", 200)
    print("\n" + res.to_string(index=False))
    res.to_csv(os.path.join(OUT, "fit_report.csv"), index=False)
    with open(os.path.join(OUT, "fit_report.json"), "w") as fh:
        json.dump({r["model"]: {k: v for k, v in r.items() if k != "model"}
                   for r in results}, fh, indent=2)

    best = max(results[:2], key=lambda r: r["r2_logit"])

    # Out-of-fold residuals for EVERY row, not just the 25% holdout.
    # robustness.py conditions the noise draw on the exact CVSS vector cell an
    # edge sits in; a single holdout leaves most cells with too few residuals to
    # do that, so 5-fold OOF gives 4x the density at the cost of 5 cheap fits.
    # cross_val_predict clones the estimator, so passing the fitted one is safe.
    print("\ncomputing out-of-fold residuals (5-fold) for the full sample...")
    oof_logit = cross_val_predict(
        results_models[best["model"]], Xcat, y,
        cv=KFold(n_splits=5, shuffle=True, random_state=SEED))
    band_stats = residual_report(df, y - oof_logit, sigmoid(oof_logit))

    # Provenance: EPSS is re-scored daily, so a fit is only reproducible if the
    # exact snapshot and page set are pinned alongside the seed.
    raw = os.path.join(ROOT, "data", "raw")
    epss_file = next((f for f in sorted(os.listdir(raw))
                      if f.startswith("epss_scores-")), None)
    n_pages = len([f for f in os.listdir(os.path.join(raw, "nvd"))
                   if f.endswith(".json.gz")])
    verdict = {
        "n_rows": int(len(df)),
        "seed": SEED,
        "epss_snapshot": epss_file,
        "nvd_pages_cached": n_pages,
        "joined_csv": os.path.basename(JOINED),
        "published_range": [str(df.published.min()), str(df.published.max())],
        "best_cvss_only_model": best["model"],
        "r2_logit": best["r2_logit"],
        "r2_prob_top10pct": best["r2_prob_top10pct"],
        "spearman_rho": best["spearman_rho"],
        # Empirical perturbation magnitudes:
        "perturbation_relative_p50": best["rel_err_p50"],
        "perturbation_relative_p90": best["rel_err_p90"],
        "signed_rel_p05": best["signed_rel_p05"],
        "signed_rel_p95": best["signed_rel_p95"],
        "resid_logit_skew": None,     # filled below
        "resid_log_abs_p50": None,    # pooled perturbation magnitude
        "resid_log_abs_p90": None,
        "resid_log_abs_p50_top_decile": None,   # top-decile perturbation magnitude
        "resid_log_abs_p90_top_decile": None,
    }
    verdict["resid_logit_skew"] = skew(residuals[best["model"]][0])
    verdict.update(band_stats)
    with open(os.path.join(OUT, "fit_verdict.json"), "w") as fh:
        json.dump(verdict, fh, indent=2)

    print(f"\nBest CVSS-only model: {best['model']}  R2(logit)={best['r2_logit']:.3f}  "
          f"R2(top decile)={best['r2_prob_top10pct']:.3f}  "
          f"Spearman rho={best['spearman_rho']:.3f}")
    if best["spearman_rho"] > 0.5 and best["r2_logit"] < 0.35:
        print("=> NOTE: weak on absolute value, usable on ORDER. That is the case\n"
              "   that matters -- choke point ranking depends on ordering edges,\n"
              "   not on getting each p(e) exactly right. Say this explicitly in\n"
              "   the report; it is a different conclusion from 'the fit failed'.")
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
