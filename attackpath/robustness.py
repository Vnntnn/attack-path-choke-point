"""Perturb the weights, drop edges, and measure how far the ranking moves.

Two noise models, reported side by side:

  symmetric  the +-10..50% band the proposal names. Kept because comparing it
             against the measured band is itself a result.
  empirical  residuals from the CVSS->EPSS fit, resampled in LOGIT space and
             conditioned on the vector cell when data/fit/residuals.csv carries
             a `vector` column. The measured residuals are right-skewed and
             heteroscedastic, so a symmetric band misstates the uncertainty --
             this arm is the honest one.

Deterministic edges (p=1, a trust relation the attacker simply holds) are never
perturbed: their probability is not an estimate.

Metrics: Jaccard@k on the ranked node list is primary (k=5,10); Kendall's tau
over all nodes is secondary and gets flattened by ties.
"""
from __future__ import annotations

import csv
import math
import os

from scipy.stats import kendalltau

from . import chokepoints as cp
from .weights import P_MAX, P_MIN, clamp, w

RESID = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                     "data", "fit", "residuals.csv")


def logit(p: float) -> float:
    return math.log(p / (1 - p)) if p < 1 else math.inf


def sigmoid(z: float) -> float:
    return 1 / (1 + math.exp(-z)) if z > -700 else 0.0


def _norm_vector(vec: str | None) -> str:
    """Cell key. NVD writes "CVSS:3.0/AV:N/...", the rubric writes "AV:N/...";
    both must land in the same bucket or conditioning silently never matches."""
    if not vec:
        return ""
    parts = [p for p in vec.split("/") if not p.startswith("CVSS:")]
    return "/".join(parts)


class EmpiricalNoise:
    """Resamples fit residuals in logit space, by vector cell when available."""

    def __init__(self, path=RESID):
        self.pooled: list[float] = []
        self.by_cell: dict[str, list[float]] = {}
        if not os.path.exists(path):
            return
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                try:
                    e = float(r["resid_logit"])
                except (KeyError, TypeError, ValueError):
                    continue
                self.pooled.append(e)
                cell = _norm_vector(r.get("vector"))
                if cell:
                    self.by_cell.setdefault(cell, []).append(e)

    @property
    def available(self) -> bool:
        return bool(self.pooled)

    def draw(self, rng, cell: str | None = None, scale: float = 1.0) -> float:
        """One residual. Cells with <10 observations fall back to pooled, so a
        thin cell cannot fabricate a confident-looking narrow band."""
        pool = self.by_cell.get(cell or "", [])
        if len(pool) < 10:
            pool = self.pooled
        return scale * rng.choice(pool)


def perturb_weights(G, rng, *, noise_model: str, level: float,
                    noise: EmpiricalNoise | None = None):
    """Copy of G with perturbed p and w. `level` is the band fraction
    (symmetric) or the residual scale factor (empirical)."""
    H = G.copy()
    for _, _, d in H.edges(data=True):
        if d.get("p_source") == "deterministic":
            continue
        p = d["p"]
        if noise_model == "symmetric":
            p_new = clamp(p * (1 + rng.uniform(-level, level)))
        elif noise_model == "empirical":
            if noise is None or not noise.available:
                raise RuntimeError("empirical noise requested, residuals.csv absent")
            cell = _norm_vector((d.get("p_input") or "").removeprefix("cvss:"))
            p_new = clamp(sigmoid(logit(min(p, 1 - 1e-9)) +
                                  noise.draw(rng, cell, level)))
        else:
            raise ValueError(f"unknown noise_model {noise_model!r}")
        d["p"], d["w"] = p_new, w(p_new)
    return H


def drop_edges(G, rng, frac: float, entries, targets):
    """Remove a fraction of edges at random -- the 'our inventory is incomplete'
    case. Returns (H, n_dropped, n_pairs_still_reachable)."""
    H = G.copy()
    edges = sorted(H.edges())
    k = int(round(frac * len(edges)))
    for i in rng.sample(range(len(edges)), k):
        u, v = edges[i]
        if H.has_edge(u, v):
            H.remove_edge(u, v)
    reach = len(cp._pair_costs(H, [e for e in entries if e in H],
                              [t for t in targets if t in H]))
    return H, k, reach


def jaccard_at_k(rank_a: list, rank_b: list, k: int) -> float:
    a, b = set(rank_a[:k]), set(rank_b[:k])
    return len(a & b) / len(a | b) if (a or b) else 1.0


def kendall_tau(scores_a: dict, scores_b: dict) -> float:
    """Over the shared node set, on the scalar collapse of the ranking score.
    Ties dominate on most graphs -- this is the secondary metric for a reason."""
    keys = sorted(set(scores_a) & set(scores_b), key=str)
    if len(keys) < 3:
        return float("nan")
    fa = [_scalar(scores_a[k]) for k in keys]
    fb = [_scalar(scores_b[k]) for k in keys]
    return float(kendalltau(fa, fb).statistic)


def _scalar(score) -> float:
    """(n_disconnected, delta, blocked_base) -> one orderable number.
    Disconnection dominates any finite cost increase, matching rank_nodes."""
    n, delta, _ = score
    return n * 1e9 + min(delta, 1e8)


def set_jaccard(a: set, b: set) -> float:
    return len(a & b) / len(a | b) if (a or b) else 1.0
