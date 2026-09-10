#!/usr/bin/env python3
"""exp 6 — does the CVSS->EPSS fit error move the choke-point ranking?

Same graphs, same real CVE ids, two weightings:
  epss    the CVE's true EPSS score
  fitted  the fit's prediction from that CVE's own CVSS vector

Spearman rho on p cannot answer this. Path cost is a SUM of -log p, so a
monotone per-edge transform can still reverse the order of two paths: two
edges at p=0.9 beat one at p=0.8 (0.81 > 0.8), but under a monotone map
0.9->0.5, 0.8->0.45 the order flips (0.25 < 0.45). Order is preserved exactly
when the fit is a power law p_hat ~ p^k, since -log p_hat = k(-log p) rescales
every path by one constant. So what matters is the spread of the log-space
residual, and this experiment measures its effect directly.

  uv run experiments/exp6_fit_error.py
"""
from __future__ import annotations

import argparse
import math
import random

import networkx as nx

from attackpath import chokepoints as cp
from attackpath import gen
from attackpath import results as rs
from attackpath import robustness as rb
from attackpath import weights as wt
from experiments.run import BASE_SEED, CROSS, SEG

EXTRA = ["jaccard5", "jaccard10", "jaccard5_tie", "jaccard10_tie",
         "kendall_tau", "global_set_jaccard",
         "cheapest_cost_epss", "cheapest_cost_fitted", "cost_ratio",
         "log_resid_sd", "top_path_same", "n_cve_edges", "n_edges_fitted",
         "n_inf_epss", "n_inf_fitted", "n_tie_at_5_epss", "n_tie_at_5_fitted"]


def _cheapest(G, ent, tgt):
    best, path = math.inf, None
    for e in ent:
        d, pth = nx.single_source_dijkstra(G, e, weight="w")
        for t in tgt:
            if t in d and d[t] < best:
                best, path = d[t], pth[t]
    return best, path


def run(n, cross, seg, seed, cat):
    G = gen.generate(n=n, cross_density=cross, segmentation=seg, seed=seed)
    ent = [x for x, d in G.nodes(data=True) if d.get("entry")]
    tgt = [x for x, d in G.nodes(data=True) if d.get("target")]
    arms = {}
    for model in ("epss", "fitted"):
        H = G.copy()
        wt.assign(H, model, random.Random(seed), cat)
        H.graph["n_requested"] = n
        arms[model] = H
    a, b = arms["epss"], arms["fitted"]

    # per-edge log-space residual: log p_true - log p_fitted, on CVE edges only
    resid = [math.log(a.edges[e]["p"]) - math.log(b.edges[e]["p"])
             for e in a.edges if a.edges[e]["kind"] == "cve"]
    mean = sum(resid) / len(resid) if resid else 0.0
    sd = (sum((r - mean) ** 2 for r in resid) / len(resid)) ** 0.5 if resid else 0.0

    sa, sb = cp.delta_cost_scores(a, ent, tgt), cp.delta_cost_scores(b, ent, tgt)
    ca, pa = _cheapest(a, ent, tgt)
    cb, pb = _cheapest(b, ent, tgt)
    pairs = len(cp.pairwise_dominators(a, ent, tgt))
    da = cp.rank_diagnostics(sa, pairs)
    db = cp.rank_diagnostics(sb, pairs)
    row = dict(rs.graph_row(a), graph_id=f"{n}-{cross}-{seg}-s{seed}",
               weight_model="epss|fitted",
               jaccard5=rb.jaccard_at_k(cp.rank_nodes(sa), cp.rank_nodes(sb), 5),
               jaccard10=rb.jaccard_at_k(cp.rank_nodes(sa), cp.rank_nodes(sb), 10),
               jaccard5_tie=rb.jaccard_at_k_tie_aware(sa, sb, 5),
               jaccard10_tie=rb.jaccard_at_k_tie_aware(sa, sb, 10),
               kendall_tau=rb.kendall_tau(sa, sb),
               global_set_jaccard=rb.set_jaccard(
                   cp.global_chokepoints(a, ent, tgt),
                   cp.global_chokepoints(b, ent, tgt)),
               cheapest_cost_epss=round(ca, 4), cheapest_cost_fitted=round(cb, 4),
               cost_ratio=round(cb / ca, 4) if ca else None,
               log_resid_sd=round(sd, 4),
               top_path_same=int(pa == pb),
               n_cve_edges=len(resid),
               n_edges_fitted=sum(1 for *_, d in b.edges(data=True)
                                  if d["p_source"] == "fitted"),
               n_inf_epss=da["n_inf"], n_inf_fitted=db["n_inf"],
               n_tie_at_5_epss=da["n_tie_at_5"],
               n_tie_at_5_fitted=db["n_tie_at_5"])
    return row


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--n", type=int, default=200)
    ap.add_argument("--reps", type=int, default=5)
    a = ap.parse_args()
    cat = wt.Catalog()
    if not cat.coeffs:
        raise SystemExit("data/fit/fit_coeffs.json missing -- run the fit first")
    if not cat.cve:
        raise SystemExit("data/fit/cvss_epss_joined.csv missing -- run the pull")
    with rs.Writer("exp6", EXTRA) as w:
        i = 0
        for c in CROSS:
            for s in SEG:
                for r in range(a.reps):
                    w.write(**run(a.n, c, s, BASE_SEED + i, cat))
                    i += 1
                    print(f"  {c}/{s} rep {r}", flush=True)


if __name__ == "__main__":
    main()
