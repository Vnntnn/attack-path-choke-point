"""Generate the data-derived figures used in docs/report/chapters/*.tex.

Reads only already-committed result/fit files (results/summary/*.csv,
data/fit/residuals.csv, lab/lab_graph.json) -- never re-runs an experiment.
Writes PNGs straight into docs/report/figures/ so thai_zwsp.py picks them up
on the next report build.

Run: uv run --group report scripts/make_report_figures.py
"""
import json
import pathlib
import shutil

import matplotlib
import networkx as nx
import numpy as np
import pandas as pd

matplotlib.use("Agg")
import matplotlib.pyplot as plt  # noqa: E402

ROOT = pathlib.Path(__file__).resolve().parent.parent
FIG = ROOT / "docs" / "report" / "figures"
FIG.mkdir(parents=True, exist_ok=True)
SUM = ROOT / "results" / "summary"
FIT = ROOT / "data" / "fit"

plt.rcParams.update({"font.size": 10, "figure.dpi": 150})


def fit_scatter():
    df = pd.read_csv(FIT / "residuals.csv")
    thr = df["epss_true"].quantile(0.90)
    top = df["epss_true"] >= thr
    fig, ax = plt.subplots(figsize=(5.2, 4.6))
    ax.scatter(df.loc[~top, "epss_true"], df.loc[~top, "epss_pred"],
               s=4, alpha=0.15, color="#4472c4", label="bottom 90%", rasterized=True)
    ax.scatter(df.loc[top, "epss_true"], df.loc[top, "epss_pred"],
               s=4, alpha=0.25, color="#c00000", label="top 10% EPSS", rasterized=True)
    lims = [1e-5, 1]
    ax.plot(lims, lims, "--", color="black", linewidth=1, label="perfect prediction (y=x)")
    ax.set_xscale("log")
    ax.set_yscale("log")
    ax.set_xlim(lims)
    ax.set_ylim(lims)
    ax.set_xlabel("true EPSS")
    ax.set_ylabel("fitted EPSS prediction")
    ax.legend(loc="upper left", fontsize=8, frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "fit_scatter.png")
    plt.close(fig)


def resid_hist():
    df = pd.read_csv(FIT / "residuals.csv")
    thr = df["epss_true"].quantile(0.90)
    pooled = df["resid_log"].abs()
    tail = df.loc[df["epss_true"] >= thr, "resid_log"].abs()
    fig, ax = plt.subplots(figsize=(5.6, 4))
    bins = np.linspace(0, 6, 40)
    ax.hist(pooled, bins=bins, density=True, alpha=0.55, color="#4472c4", label="pooled (all CVEs)")
    ax.hist(tail, bins=bins, density=True, alpha=0.55, color="#c00000", label="top 10% EPSS")
    ax.axvline(pooled.median(), color="#4472c4", linestyle="--", linewidth=1)
    ax.axvline(tail.median(), color="#c00000", linestyle="--", linewidth=1)
    ax.set_xlabel(r"$|r| = |\log p_{true} - \log p_{pred}|$ (nats)")
    ax.set_ylabel("density")
    ax.legend(frameon=False)
    fig.tight_layout()
    fig.savefig(FIG / "resid_hist.png")
    plt.close(fig)


def seg_bar():
    df = pd.read_csv(SUM / "exp1b_global_nonempty_ci.csv")
    df = df[df["group"].str.startswith("segmentation=")].copy()
    order = ["flat", "3tier", "micro"]
    df["seg"] = df["group"].str.replace("segmentation=", "", regex=False)
    df = df.set_index("seg").loc[order].reset_index()
    y = df["rate"] * 100
    lo = y - df["ci95_lo"] * 100
    hi = df["ci95_hi"] * 100 - y
    fig, ax = plt.subplots(figsize=(5, 4))
    ax.bar(order, y, yerr=[lo, hi], capsize=5, color="#4472c4")
    for i, (v, n) in enumerate(zip(y, df["graphs"])):
        ax.text(i, v + 2.5, f"{int(df['graphs_with_global_set'][i])}/{int(n)}", ha="center", fontsize=9)
    ax.set_ylabel("graphs with global choke point (%)")
    ax.set_xlabel("network segmentation level")
    ax.set_ylim(0, 40)
    fig.tight_layout()
    fig.savefig(FIG / "seg_bar.png")
    plt.close(fig)


def cut_agreement_bar():
    df = pd.read_csv(SUM / "exp1a_nonempty_global_only.csv")
    caps = ["unit", "prob", "cost"]
    models = ["epss", "cvss", "uniform", "random"]
    colors = {"epss": "#4472c4", "cvss": "#ed7d31", "uniform": "#70ad47", "random": "#a6a6a6"}
    x = np.arange(len(caps))
    width = 0.2
    fig, ax = plt.subplots(figsize=(6, 4.2))
    for i, m in enumerate(models):
        vals = [df[(df.capacity == c) & (df.weight_model == m)]["cut_in_global"].iloc[0] * 100 for c in caps]
        ax.bar(x + (i - 1.5) * width, vals, width, label=m, color=colors[m])
    ax.set_xticks(x)
    ax.set_xticklabels(["unit", "prob", "cost"])
    ax.set_ylabel("min-cut nodes inside dominator set (%)")
    ax.set_xlabel("capacity scale")
    ax.legend(frameon=False, fontsize=8, ncol=4, loc="lower center")
    ax.set_ylim(0, 115)
    fig.tight_layout()
    fig.savefig(FIG / "cut_agreement_bar.png")
    plt.close(fig)


def model_jaccard_bar():
    df = pd.read_csv(SUM / "exp4_model_comparison.csv")
    df = df.sort_values("jaccard5")
    fig, ax = plt.subplots(figsize=(6, 4.2))
    colors = ["#c00000" if p in ("epss vs random", "uniform vs random") else "#4472c4" for p in df["pair"]]
    ax.barh(df["pair"], df["jaccard5"], color=colors)
    ax.set_xlabel("Jaccard@5")
    ax.set_xlim(0.85, 1.0)
    for i, v in enumerate(df["jaccard5"]):
        ax.text(v + 0.002, i, f"{v:.3f}", va="center", fontsize=8)
    fig.tight_layout()
    fig.savefig(FIG / "model_jaccard_bar.png")
    plt.close(fig)


def cross_share_bar():
    df = pd.read_csv(SUM / "exp7_cross_domain_share.csv")
    row = df[df.weight_model == "epss"].iloc[0]
    groups = ["pooled", "on-prem target", "cloud target"]
    cheapest = [row["cheapest_cross_share"] * 100, row["cheapest_cross_share_onprem_target"] * 100, row["cheapest_cross_share_cloud_target"] * 100]
    required = [row["cross_required_share"] * 100, row["cross_required_share_onprem_target"] * 100, None]
    x = np.arange(len(groups))
    width = 0.32
    fig, ax = plt.subplots(figsize=(6, 4.2))
    ax.bar(x - width / 2, cheapest, width, label="cheapest path crosses domain", color="#4472c4")
    req_vals = [v if v is not None else 0 for v in required]
    ax.bar(x + width / 2, req_vals, width, label="must cross domain", color="#ed7d31")
    ax.set_xticks(x)
    ax.set_xticklabels(groups)
    ax.set_ylabel("share (%)")
    ax.legend(frameon=False, fontsize=8)
    ax.set_ylim(0, 110)
    fig.tight_layout()
    fig.savefig(FIG / "cross_share_bar.png")
    plt.close(fig)


def attack_graph_schema():
    """Small illustrative example -- not experiment data -- mirroring the
    worked example in sec:design-model / sec:design-pe."""
    g = nx.DiGraph()
    nodes = {
        "internet": ("internet", "anon"),
        "h001_user": ("h001", "user"),
        "h001_root": ("h001", "root"),
        "s3": ("s3://bucket", "read"),
        "aws_admin": ("aws:acct", "admin"),
    }
    g.add_nodes_from(nodes)
    edges = [
        ("internet", "h001_user", "epss", "CVE-2024-xxxx"),
        ("h001_user", "h001_root", "fitted", "shared-local-admin-password"),
        ("h001_root", "s3", "fitted", "aws-key-on-host"),
        ("internet", "s3", "deterministic", "s3-public-read"),
        ("s3", "aws_admin", "fitted", "iam-passrole-excess-privilege"),
    ]
    for u, v, k, _ in edges:
        g.add_edge(u, v, kind=k)
    pos = {
        "internet": (0, 1), "h001_user": (1, 1.6), "h001_root": (2, 1.6),
        "s3": (1.3, 0.3), "aws_admin": (3, 0.8),
    }
    color = {"epss": "#4472c4", "fitted": "#ed7d31", "deterministic": "#70ad47"}
    fig, ax = plt.subplots(figsize=(6.4, 3.6))
    nx.draw_networkx_nodes(g, pos, ax=ax, node_color="#f2f2f2", edgecolors="black", node_size=2600)
    labels = {n: f"({r},\n{p})" for n, (r, p) in nodes.items()}
    nx.draw_networkx_labels(g, pos, labels, ax=ax, font_size=7.5)
    for u, v, k, ref in edges:
        nx.draw_networkx_edges(g, pos, edgelist=[(u, v)], ax=ax, edge_color=color[k],
                                connectionstyle="arc3,rad=0.08", arrowsize=14, width=1.6,
                                node_size=2600)
    handles = [plt.Line2D([0], [0], color=c, lw=2, label=k) for k, c in color.items()]
    ax.legend(handles=handles, loc="lower right", fontsize=8, frameon=False, title="p_source")
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(FIG / "attack_graph_schema.png")
    plt.close(fig)


def lab_topology():
    data = json.loads((ROOT / "lab" / "lab_graph.json").read_text())

    SHORT = {
        "internet": "internet",
        "s3://itis2026-lab-public-data": "public-data",
        "net:itis2026-lab-open-mgmt": "open-mgmt",
        "aws:999999999999": "attacker-aws-acct",
        "role:itis2026-lab-cross-account-trust-role": "cross-account-role",
        "host:lab-onprem-dmz": "dmz-host",
        "host:lab-onprem-internal": "internal-host",
        "user:itis2026-lab-leaked-key-user": "leaked-key-user",
    }

    g = nx.DiGraph()
    ids = {}
    for n in data["nodes"]:
        key = tuple(n["id"])
        label = f"{SHORT[key[0]]}\n({key[1]})"
        ids[key] = label
        g.add_node(label, entry=n.get("entry", False), target=n.get("target", False))
    for e in data["edges"]:
        g.add_edge(ids[tuple(e["source"])], ids[tuple(e["target"])], kind=e["kind"], ref=e["ref"])

    # deterministic left-to-right chain layout (clearer for a DAG this small than spring_layout)
    chain = ["internet\n(anon)", "dmz-host\n(anon)", "internal-host\n(anon)", "internal-host\n(root)", "leaked-key-user\n(admin)"]
    side = ["open-mgmt\n(reachable)", "public-data\n(read)", "attacker-aws-acct\n(root)", "cross-account-role\n(admin)"]
    pos = {}
    for i, n in enumerate(chain):
        pos[n] = (i * 2.1, 0)
    for i, n in enumerate(side):
        pos[n] = (i * 2.1 + 0.2, 1.9)

    kind_color = {"misconfig": "#ed7d31", "deterministic": "#70ad47"}
    node_color = ["#fff2cc" if g.nodes[n]["entry"] else ("#d9ead3" if g.nodes[n]["target"] else "#f2f2f2") for n in g.nodes]
    fig, ax = plt.subplots(figsize=(11, 4.6))
    nx.draw_networkx_nodes(g, pos, ax=ax, node_color=node_color, edgecolors="black", node_size=4200)
    nx.draw_networkx_labels(g, pos, ax=ax, font_size=7)
    for u, v, d in g.edges(data=True):
        nx.draw_networkx_edges(g, pos, edgelist=[(u, v)], ax=ax, edge_color=kind_color[d["kind"]],
                                connectionstyle="arc3,rad=0.12", arrowsize=14, width=1.6, node_size=4200)
        mx, my = (pos[u][0] + pos[v][0]) / 2, (pos[u][1] + pos[v][1]) / 2
        dy = 0.22 if pos[u][1] == pos[v][1] else 0
        ax.text(mx, my + dy, d["ref"], fontsize=6.5, ha="center", color="#333333")
    handles = [plt.Line2D([0], [0], color=c, lw=2, label=k) for k, c in kind_color.items()]
    handles += [plt.Line2D([0], [0], marker="s", color="w", markerfacecolor="#fff2cc", markersize=10, label="entry"),
                plt.Line2D([0], [0], marker="s", color="w", markerfacecolor="#d9ead3", markersize=10, label="target")]
    ax.legend(handles=handles, loc="upper center", bbox_to_anchor=(0.5, -0.03), ncol=4, fontsize=8, frameon=False)
    ax.set_xlim(-1, 9.5)
    ax.set_ylim(-0.8, 2.8)
    ax.axis("off")
    fig.tight_layout()
    fig.savefig(FIG / "lab_topology.png")
    plt.close(fig)


def copy_analyze_figures():
    """analyze.py (experiments/analyze.py) writes exp2/exp3 line charts to
    results/figures/ -- copy them next to the figures this script generates
    so a single `make_report_figures.py` run keeps docs/report/figures/ in sync."""
    for name in ("exp2_symmetric.png", "exp2_empirical.png", "exp3_edge_drop.png"):
        src = ROOT / "results" / "figures" / name
        if src.exists():
            shutil.copy2(src, FIG / name)
        else:
            print(f"warning: {src} missing -- run experiments/analyze.py first")


if __name__ == "__main__":
    fit_scatter()
    resid_hist()
    seg_bar()
    cut_agreement_bar()
    model_jaccard_bar()
    cross_share_bar()
    attack_graph_schema()
    lab_topology()
    copy_analyze_figures()
    print(f"wrote figures to {FIG}")
