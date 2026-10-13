#!/usr/bin/env python3
"""Independent audit of the EPSS x NVD join and the fit's split optimism.

  uv run --group fit scripts/audit_data.py

1. Re-joins data/raw (EPSS gz + cached NVD pages) with code that does not share
   anything with pull_data.py and asserts it equals data/fit/cvss_epss_joined.csv.
2. Re-scores the OLS fit under splits the fit script does not use: whole NVD
   pages held out, whole years held out, and train<=2022 -> test>=2023.
"""
import collections
import csv
import gzip
import json
import os

import numpy as np
import pandas as pd
from scipy.stats import spearmanr
from sklearn.linear_model import LinearRegression
from sklearn.metrics import r2_score
from sklearn.model_selection import GroupKFold, KFold, cross_val_predict
from sklearn.preprocessing import OneHotEncoder

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW, JOINED = f"{ROOT}/data/raw", f"{ROOT}/data/fit/cvss_epss_joined.csv"
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
EPS = 1e-5


def join_from_raw():
    ep = {}
    with gzip.open(next(f"{RAW}/{f}" for f in sorted(os.listdir(RAW)) if f.startswith("epss_scores-")), "rt") as fh:
        for line in fh:
            if line.startswith("#") or line.startswith("cve,"):
                continue
            c, e, _ = line.strip().split(",")
            ep[c] = float(e)
    mine = {}
    for f in sorted(os.listdir(f"{RAW}/nvd")):
        for it in json.load(gzip.open(f"{RAW}/nvd/{f}", "rt"))["vulnerabilities"]:
            c = it["cve"]
            m = c.get("metrics", {})
            e = m.get("cvssMetricV31") or m.get("cvssMetricV30") or []
            if c.get("vulnStatus") == "Rejected" or not e or c["id"] not in ep:
                continue
            x = next((v for v in e if v.get("type") == "Primary"), e[0])["cvssData"]
            mine.setdefault(c["id"], (x["vectorString"], x["baseScore"], ep[c["id"]], c["published"][:10]))
    return mine


def check_join():
    mine = join_from_raw()
    csv_rows = {r["cve"]: r for r in csv.DictReader(open(JOINED))}
    assert set(mine) == set(csv_rows), (len(mine), len(csv_rows))
    for c, (vec, bs, e, pub) in mine.items():
        r = csv_rows[c]
        assert r["vector"] == vec and r["published"] == pub, c
        assert abs(float(r["base_score"]) - bs) < 1e-9 and abs(float(r["epss"]) - e) < 1e-9, c
    print(f"join OK: {len(mine)} CVEs identical to {os.path.basename(JOINED)} (vector, base score, EPSS, date)")


def check_splits():
    df = pd.read_csv(JOINED).dropna(subset=METRICS + ["epss", "base_score", "published"])
    df = df[df.published.astype(str) >= "2016-01-01"].reset_index(drop=True)   # same filter as fit_weights.py
    p = np.clip(df.epss.to_numpy(), EPS, 1 - EPS)
    y = np.log(p / (1 - p))
    X = OneHotEncoder(handle_unknown="ignore").fit_transform(df[METRICS].astype(str))
    yr = df.published.str[:4].astype(int)
    print(f"fit rows: {len(df)} from {df.nvd_page.nunique()} NVD pages")

    def cv(name, splitter, groups=None):
        pr = cross_val_predict(LinearRegression(), X, y, cv=splitter, groups=groups)
        print(f"  {name:30s} R2_logit {r2_score(y, pr):6.3f}   rho {spearmanr(y, pr)[0]:.3f}")

    cv("random 5-fold (rows)", KFold(5, shuffle=True, random_state=1))
    cv("hold out whole NVD pages", GroupKFold(5), df.nvd_page)
    cv("hold out whole years", GroupKFold(5), yr)
    tr = (yr <= 2022).to_numpy()
    pr = LinearRegression().fit(X[tr], y[tr]).predict(X[~tr])
    print(f"  {'train<=2022 -> test>=2023':30s} R2_logit {r2_score(y[~tr], pr):6.3f}   rho {spearmanr(y[~tr], pr)[0]:.3f}")


if __name__ == "__main__":
    check_join()
    check_splits()
