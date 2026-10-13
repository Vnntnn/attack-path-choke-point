#!/usr/bin/env python3
"""Recompute the headline numbers from results/ and data/fit/ and assert that
the documents quote exactly those values.

  uv run scripts/check_claims.py

Each claim = (what, value computed from raw files, text it must appear as, files).
A failure means a document and the data disagree -- fix the document, or rerun.
"""
import json
import os

import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
R = lambda p: os.path.join(ROOT, p)
rd = lambda f: pd.read_csv(R(f"results/{f}.csv"))
txt = lambda *fs: "\n".join(open(R(f), encoding="utf-8").read() for f in fs)

ABS, CH5 = "docs/report/abstract.tex", "docs/report/chapters/ch5.tex"
claims = []   # (label, needle, files)


def claim(label, needle, *files):
    claims.append((label, needle, files or (CH5,)))


# ---- grid size
a = rd("exp1a")
n_graphs, n_w = a.graph_id.nunique(), a.drop_duplicates(["graph_id", "weight_model"]).shape[0]
claim("structures", f"{n_graphs} โครงสร้าง", CH5)
claim("weighted graphs", f"{n_w} กราฟ", CH5)

# ---- exp 1: global dominator set
g = a.drop_duplicates("graph_id")
k = int((g.n_global > 0).sum())
claim("global non-empty count", f"{k} / {n_graphs}", CH5)
claim("global non-empty count (abstract)", f"{k} จาก {n_graphs}", ABS)
claim("global non-empty pct", f"{100*k/n_graphs:.1f}%", ABS, CH5)
micro = g[g.segmentation == "micro"]
claim("micro count", f"{int((micro.n_global > 0).sum())} / {len(micro)}", CH5)
ne = a[a.n_global > 0]
claim("cut in dominator set, prob epss", f"{ne[(ne.capacity=='prob')&(ne.weight_model=='epss')].cut_in_global.mean()*100:.0f}%", CH5)
claim("cut in dominator set, prob epss (abstract)", f"{ne[(ne.capacity=='prob')&(ne.weight_model=='epss')].cut_in_global.mean()*100:.0f}", ABS)

# ---- exp 2 / 3 / 4 / 6 / 7
e2 = rd("exp2")
sym50 = e2[(e2.noise_model == "symmetric") & (e2.noise_level == 0.5)].groupby("graph_id").jaccard5.mean().mean()
emp8 = e2[(e2.noise_model == "empirical") & (e2.noise_level == 8.0)].groupby("graph_id").jaccard5.mean().mean()
claim("exp2 symmetric 50%", f"{sym50:.3f}", ABS, CH5)
claim("exp2 empirical x8", f"{emp8:.3f}", CH5)
for nm, lv in [("symmetric", 0.1), ("symmetric", 0.2), ("symmetric", 0.3)]:
    v = e2[(e2.noise_model == nm) & (e2.noise_level == lv)].groupby("graph_id").jaccard5.mean().mean()
    claim(f"exp2 {nm} {lv}", f"{v:.3f}", CH5)
for lv in (0.5, 1.0, 2.0, 4.0):
    v = e2[(e2.noise_model == "empirical") & (e2.noise_level == lv)].groupby("graph_id").jaccard5.mean().mean()
    claim(f"exp2 empirical {lv}", f"{v:.3f}", CH5)
e3 = rd("exp3")
for fr, s in e3.groupby("drop_frac").jaccard5.mean().items():
    claim(f"exp3 drop {fr}", f"{s:.2f}", CH5)
for fr, s in e3.groupby("drop_frac").kendall_tau.mean().items():
    claim(f"exp3 drop {fr} tau", f"{s:.3f}", CH5)
e4 = rd("exp4").assign(pair=lambda d: d.model_a + "+" + d.model_b)
j, jt = e4.groupby("pair").jaccard5.mean(), e4.groupby("pair").kendall_tau.mean()
claim("exp4 epss-cvss", f"{j['epss+cvss']:.3f}", CH5)
claim("exp4 epss-random", f"{j['epss+random']:.3f}", CH5)
for pair in ("epss+uniform", "uniform+random", "cvss+uniform", "cvss+random"):
    claim(f"exp4 {pair} jaccard5", f"{j[pair]:.3f}", CH5)
    claim(f"exp4 {pair} tau", f"{jt[pair]:.3f}", CH5)
for nm, lv in [("symmetric", 0.5), ("empirical", 8.0)]:
    for wm in ("epss", "cvss", "uniform", "random"):
        v = e2[(e2.noise_model == nm) & (e2.noise_level == lv) & (e2.weight_model == wm)] \
            .groupby("graph_id").jaccard5.mean().mean()
        claim(f"exp2 {nm} {lv} {wm}", f"{v:.3f}", CH5)
for fr, s in (e3.pairs_reachable_after / e3.pairs_reachable_before).groupby(e3.drop_frac).mean().items():
    claim(f"exp3 drop {fr} pairs-kept", f"{s*100:.0f}%", CH5)
e7 = rd("exp7"); e7e = e7[e7.weight_model == "epss"]
claim("exp7 on-prem cheapest crosses", f"{e7e.cheapest_cross_share_onprem_target.mean()*100:.1f}%", CH5)
claim("exp7 on-prem must cross", f"{e7e.cross_required_share_onprem_target.mean()*100:.1f}%", CH5)
claim("exp7 pooled cheapest crosses", f"{e7e.cheapest_cross_share.mean()*100:.1f}%", CH5)
claim("exp7 pooled must cross", f"{e7e.cross_required_share.mean()*100:.1f}%", CH5)
for seg, s in e7e.groupby("segmentation").cheapest_cross_share_onprem_target.mean().items():
    claim(f"exp7 onprem cheapest {seg}", f"{s*100:.1f}%", CH5)
for cd, s in e7e.groupby("cross_density").cheapest_cross_share_onprem_target.mean().items():
    claim(f"exp7 onprem cheapest density={cd}", f"{s*100:.1f}%", CH5)
e6 = rd("exp6")
claim("exp6 jaccard5", f"{e6.jaccard5.mean():.3f}", CH5)
claim("exp6 jaccard10", f"{e6.jaccard10.mean():.3f}", CH5)
claim("exp6 tau", f"{e6.kendall_tau.mean():.3f}", CH5)
claim("exp6 top path differs", f"{int((e6.top_path_same == 0).sum())} จาก {len(e6)}", CH5)
claim("exp6 top path same pct", f"{e6.top_path_same.mean()*100:.0f}%", CH5)
q = e6.cost_ratio.quantile([0.1, 0.5, 0.9])
claim("exp6 cost ratio p10-p90", f"{q[0.1]:.2f}--{q[0.9]:.2f}", CH5)

# ---- fit
v = json.load(open(R("data/fit/fit_verdict.json")))
claim("fit R2 logit", f"{v['r2_logit']:.3f}", ABS, CH5)
claim("fit rho", f"{v['spearman_rho']:.3f}", CH5)
claim("top-decile |r| p50", f"{v['resid_log_abs_p50_top_decile']:.3f}", CH5)
claim("pooled |r| p50", f"{v['resid_log_abs_p50']:.3f}", CH5)

bad = 0
for label, needle, files in claims:
    for f in files:
        hay = txt(f)
        ok = needle in hay or needle.replace("%", r"\%") in hay
        bad += not ok
        print(f"{'ok  ' if ok else 'FAIL'} {label:42s} {needle!r:18s} in {f}")
print(f"\n{len(claims)} claims, {bad} failing")
raise SystemExit(1 if bad else 0)
