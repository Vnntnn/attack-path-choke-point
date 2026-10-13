#!/usr/bin/env python3
"""Turn results/exp*.csv into the tables and figures the report quotes.

Every Jaccard@k is emitted with the fraction of graphs where n_inf >= k beside
it. In those graphs top-k is an arbitrary pick inside an unordered set (every
node tied at Delta(v) = infinity), so a Jaccard printed on its own is
uninterpretable.

  uv run --group report experiments/analyze.py
"""
from __future__ import annotations

import os

import matplotlib
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

RES, OUT, FIG = "results", "results/summary", "results/figures"
CELL = ["n_requested", "cross_density", "segmentation"]


def load(name):
    return pd.read_csv(os.path.join(RES, f"{name}.csv"))


def _boot_ci(df, col, n_boot=2000, seed=20260826):
    """95% CI of the mean over GRAPHS: reps inside a graph are correlated, so
    the independent unit is the graph, not the row."""
    per_graph = df.groupby("graph_id")[col].mean().dropna().to_numpy()
    if len(per_graph) < 2:
        return float("nan"), float("nan")
    rng = np.random.default_rng(seed)
    means = rng.choice(per_graph, (n_boot, len(per_graph))).mean(axis=1)
    return tuple(np.percentile(means, [2.5, 97.5]))


def _wilson(k, n, z=1.96):
    """95% Wilson interval for k successes in n GRAPHS (not rows): small counts
    like 18/216 make a bare percentage look more certain than it is."""
    if n == 0:
        return float("nan"), float("nan")
    p = k / n
    d = 1 + z * z / n
    c = (p + z * z / (2 * n)) / d
    h = z * ((p * (1 - p) / n + z * z / (4 * n * n)) ** 0.5) / d
    return c - h, c + h


def _jacc(df, by, cols=("jaccard5", "jaccard10")):
    """Mean Jaccard, 95% CI over graphs, plus tie/infinity interpretability guards."""
    g = df.groupby(by, dropna=False)
    out = g[list(cols)].mean()
    for c in cols:
        ci = g.apply(lambda d, c=c: _boot_ci(d, c), include_groups=False)
        out[f"{c}_lo"] = [v[0] for v in ci]
        out[f"{c}_hi"] = [v[1] for v in ci]
    out["n"] = g.size()
    out["n_graphs"] = g["graph_id"].nunique()
    if "n_inf" in df.columns:       # tie guards only mean something for rankings
        out["frac_n_inf_ge_5"] = g.apply(lambda d: (d["n_inf"] >= 5).mean(),
                                         include_groups=False)
        out["frac_n_inf_ge_10"] = g.apply(lambda d: (d["n_inf"] >= 10).mean(),
                                          include_groups=False)
        out["mean_n_inf"] = g["n_inf"].mean()
    return out.reset_index()


def exp1a(md):
    df = load("exp1a")
    t = (df.groupby(["capacity"] + CELL, dropna=False)
           .agg(cut_exists_rate=("cut_exists", "mean"),
                mean_n_cut=("n_cut", "mean"),
                mean_n_global=("n_global", "mean"),
                mean_disagreement=("disagreement", "mean"),
                mean_cut_in_global=("cut_in_global", "mean"),
                mean_free_in_cut=("n_cut_free", "mean"),
                n=("n_cut", "size")).reset_index())
    t.to_csv(f"{OUT}/exp1a_dominator_vs_mincut.csv", index=False)
    deg = df.groupby("capacity").apply(
        lambda d: (d["cut_value"] == 0).mean(), include_groups=False)
    md.append("## exp 1a — post-dominator set vs weighted node min-cut\n")
    md.append(f"- rows: {len(df)}, node-split min-cut across capacity scales\n")
    md.append(f"- fraction of cuts with total capacity exactly 0: "
              f"{dict(deg.round(3))} — the -log p scale is degenerate because "
              f"deterministic edges (p=1) have w=0\n")
    md.append("- disagreement / cut_in_global are reported ONLY on rows where a "
              "global dominator set exists: with an empty set, disagreement is 1.0 "
              "by definition and says nothing about the two methods\n")
    for cap, sub in df.groupby("capacity"):
        ne = sub[sub["n_global"] > 0]
        md.append(f"- capacity={cap}: mean |min-cut| "
                  f"{sub['n_cut'].mean():.2f}, mean |global dominator set| "
                  f"{sub['n_global'].mean():.2f}; non-empty-global rows "
                  f"{len(ne)}/{len(sub)} ({ne['graph_id'].nunique()} graphs): "
                  f"cut inside dominator set {ne['cut_in_global'].mean():.3f}, "
                  f"disagreement {ne['disagreement'].mean():.3f}\n")
    ne = df[df["n_global"] > 0]
    ne.groupby(["capacity", "weight_model"]).agg(
        rows=("graph_id", "size"), graphs=("graph_id", "nunique"),
        cut_in_global=("cut_in_global", "mean"),
        global_in_cut=("global_in_cut", "mean"),
        disagreement=("disagreement", "mean")).reset_index().to_csv(
        f"{OUT}/exp1a_nonempty_global_only.csv", index=False)
    return t


def exp1b(md):
    df = load("exp1b")
    t = (df.groupby(["definition"] + CELL, dropna=False)
           .agg(non_empty_rate=("non_empty", "mean"),
                mean_set_size=("set_size", "mean"),
                max_set_size=("set_size", "max"),
                n=("set_size", "size")).reset_index())
    t.to_csv(f"{OUT}/exp1b_three_definitions.csv", index=False)
    head = df.groupby("definition").agg(non_empty_rate=("non_empty", "mean"),
                                        mean_size=("set_size", "mean"))
    md.append("\n## exp 1b — three definitions of choke point\n")
    md.append("headline: how often does a guaranteed *global* choke point "
              "exist at all\n\n")
    md.append(head.round(3).to_markdown() + "\n")
    # the dominator set reads no weights, so the 4 weight-model rows of a graph
    # are identical: count each GRAPH once
    gl = df[df.definition == "global"].drop_duplicates("graph_id")
    rows = []
    for label, sub in [("all", gl)] + [
            (f"{col}={v}", x) for col in ("segmentation", "cross_density", "n_requested")
            for v, x in gl.groupby(col)]:
        k, n = int(sub["non_empty"].sum()), len(sub)
        lo, hi = _wilson(k, n)
        rows.append({"group": label, "graphs_with_global_set": k, "graphs": n,
                     "rate": k / n, "ci95_lo": lo, "ci95_hi": hi})
    w = pd.DataFrame(rows)
    w.to_csv(f"{OUT}/exp1b_global_nonempty_ci.csv", index=False)
    md.append("\nglobal choke point exists — counts of GRAPHS with 95% Wilson CI "
              "(this is exp 5; report the count, not a bare percentage):\n\n")
    md.append(w.round(3).to_markdown(index=False) + "\n")
    # exp 5: choke points vs segmentation granularity
    e5 = (df[df.definition == "global"]
          .groupby(["segmentation", "n_requested"])
          .agg(non_empty_rate=("non_empty", "mean"),
               mean_size=("set_size", "mean"), n=("set_size", "size"))
          .reset_index())
    e5.to_csv(f"{OUT}/exp5_segmentation.csv", index=False)
    return t


def exp2(md):
    df = load("exp2")
    t = _jacc(df, ["noise_model", "noise_level", "weight_model"])
    t.to_csv(f"{OUT}/exp2_weight_perturbation.csv", index=False)
    md.append("\n## exp 2 — weight perturbation\n")
    md.append("`frac_n_inf_ge_k` is the share of graphs where the top-k is an "
              "arbitrary pick inside the unordered delta=inf set; the Jaccard "
              "beside it means nothing on those graphs.\n\n")
    md.append(t.round(3).to_markdown(index=False) + "\n")
    for nm, sub in df.groupby("noise_model"):
        fig, ax = plt.subplots(figsize=(6, 4))
        for wm, s in sub.groupby("weight_model"):
            m = s.groupby("noise_level")["jaccard5"].mean()
            ax.plot(m.index, m.values, marker="o", label=wm)
        ax.set_xlabel("residual scale" if nm == "empirical" else "band (+/- fraction)")
        ax.set_ylabel("mean Jaccard@5")
        ax.set_ylim(0, 1.02)
        ax.set_title(f"rank stability under {nm} weight noise")
        ax.legend(title="weight model")
        fig.tight_layout()
        fig.savefig(f"{FIG}/exp2_{nm}.png", dpi=150)
        plt.close(fig)
    return t


def exp3(md):
    df = load("exp3")
    t = _jacc(df, ["drop_frac", "weight_model"])
    t.to_csv(f"{OUT}/exp3_edge_drop.csv", index=False)
    df["pairs_lost"] = (df.pairs_reachable_before - df.pairs_reachable_after)
    md.append("\n## exp 3 — missing edges\n\n")
    md.append(t.round(3).to_markdown(index=False) + "\n")
    md.append(f"\nmean (entry,target) pairs lost per drop level: "
              f"{dict(df.groupby('drop_frac')['pairs_lost'].mean().round(2))}\n")
    # Dropping edges also deletes (entry,target) pairs outright, so the plain
    # Jaccard mixes rank instability with pairs that stopped existing. Condition
    # on runs that keep >= 90% of the pairs; n is printed because it collapses.
    df["pairs_kept"] = df.pairs_reachable_after / df.pairs_reachable_before
    kept = df[df.pairs_kept >= 0.9]
    tk = _jacc(kept, ["drop_frac"])
    tk.to_csv(f"{OUT}/exp3_edge_drop_pairs_kept_ge_90.csv", index=False)
    md.append("\nconditioned on >= 90% of (entry,target) pairs still reachable "
              "(all weight models pooled; `n_graphs` is how many graphs survive "
              "the filter -- thin at 20%):\n\n")
    md.append(tk.round(3).to_markdown(index=False) + "\n")
    fig, ax = plt.subplots(figsize=(6, 4))
    for wm, s in df.groupby("weight_model"):
        m = s.groupby("drop_frac")["jaccard5"].mean()
        ax.plot(m.index, m.values, marker="o", label=wm)
    ax.set_xlabel("fraction of edges removed")
    ax.set_ylabel("mean Jaccard@5")
    ax.set_ylim(0, 1.02)
    ax.set_title("rank stability under missing edges")
    ax.legend(title="weight model")
    fig.tight_layout()
    fig.savefig(f"{FIG}/exp3_edge_drop.png", dpi=150)
    plt.close(fig)
    return t


def exp4(md):
    df = load("exp4")
    df["pair"] = df.model_a + " vs " + df.model_b
    t = (df.groupby("pair").agg(jaccard5=("jaccard5", "mean"),
                                jaccard10=("jaccard10", "mean"),
                                kendall_tau=("kendall_tau", "mean"),
                                mean_n_inf_a=("n_inf_a", "mean"),
                                mean_n_inf_b=("n_inf_b", "mean"),
                                n=("jaccard5", "size")).reset_index())
    t.to_csv(f"{OUT}/exp4_model_comparison.csv", index=False)
    md.append("\n## exp 4 — weight models against each other (paired, same graph)\n")
    md.append("No ground truth exists on synthetic graphs, so this is "
              "disagreement and stability only — never accuracy. `random` is the "
              "null model: a pair that agrees about as well as a pair involving "
              "`random` shows the ranking is set by structure, not by the "
              "weights. global_set_jaccard is omitted: dominators read no "
              "weights, so it is 1.0 by construction.\n\n")
    md.append(t.round(3).to_markdown(index=False) + "\n")
    # stability per model comes from exp 2, not from here
    st = load("exp2")
    stab = (st[st.noise_model == "symmetric"]
            .groupby(["weight_model", "noise_level"])["jaccard5"].mean()
            .unstack().round(3))
    md.append("\nstability per weight model (mean Jaccard@5 by symmetric band):\n\n")
    md.append(stab.to_markdown() + "\n")
    return t


def exp7(md):
    df = load("exp7")
    cols = ["cheapest_cross_share", "cross_required_share",
            "cheapest_cross_share_onprem_target", "cross_required_share_onprem_target",
            "cheapest_cross_share_cloud_target"]
    t = _jacc(df, ["weight_model"], cols=cols).drop(
        columns=["frac_n_inf_ge_5", "frac_n_inf_ge_10", "mean_n_inf"], errors="ignore")
    t.to_csv(f"{OUT}/exp7_cross_domain_share.csv", index=False)
    by = (df[df.weight_model == "epss"]
          .groupby(["cross_density", "segmentation"])[cols + ["n_cross_edges"]]
          .mean().round(3))
    by.to_csv(f"{OUT}/exp7_cross_domain_by_cell_epss.csv")
    md.append("\n## exp 7 — share of attack paths that cross on-prem <-> cloud\n")
    md.append("`cheapest_cross_share`: reachable (entry,target) pairs whose most "
              "likely (-log p) path uses a cross edge. `cross_required_share`: pairs "
              "with NO path once every cross edge is removed. Entries are on-prem, so "
              "cloud targets always require crossing: read the `_onprem_target` "
              "columns, where crossing is optional, as the informative ones. One "
              "path per pair, so this is the most likely path, not all dangerous "
              "paths.\n\n")
    md.append(t.round(3).to_markdown(index=False) + "\n")
    md.append("\nweight model `epss`, by cross-edge density x segmentation:\n\n")
    md.append(by.to_markdown() + "\n")
    return t


def main():
    os.makedirs(OUT, exist_ok=True)
    os.makedirs(FIG, exist_ok=True)
    md = ["# Results summary\n",
          "Generated by `experiments/analyze.py`. Every graph is seeded and "
          "the seed is on every row of every CSV. A seed reproduces a graph "
          "only against a fixed data snapshot, so `cve_pool_size` and "
          "`epss_snapshot` ride on every row too.\n"]
    q = load("exp1a")
    md.append(f"\n**corpus quality** — repair edges close (entry,target) pairs "
              f"the natural generation left unreachable, so a repaired graph is "
              f"not a draw from the declared distribution: mean repair fraction "
              f"{q.repair_frac.mean():.4f}, max {q.repair_frac.max():.4f}, by "
              f"segmentation "
              f"{dict(q.groupby('segmentation').repair_frac.mean().round(4))}\n")
    exp1a(md)
    exp1b(md)
    exp2(md)
    exp3(md)
    exp4(md)
    exp7(md)
    with open(f"{RES}/SUMMARY.md", "w") as fh:
        fh.write("".join(md))
    print(f"wrote {RES}/SUMMARY.md, {OUT}/*.csv, {FIG}/*.png")


if __name__ == "__main__":
    main()
