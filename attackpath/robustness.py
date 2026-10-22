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
over all nodes is secondary -- it gets flattened by the ties that the
Delta(v) = infinity group produces across the whole graph.
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


MIN_CELL = 10        # below this a cell cannot support its own band
N_BANDS = 5          # predicted-p quintiles


class EmpiricalNoise:
    """Resamples fit residuals in logit space.

    Draw order: the edge's exact CVSS vector cell when that cell has at least
    MIN_CELL observations, else the residuals of edges with a similar PREDICTED
    p, else the pooled distribution.

    The middle step exists because pooling is biased, not merely coarse: the
    measured residual spread is |r| p50 = 0.62 nats overall but 1.76 on the top
    EPSS decile (5-fold out-of-fold residuals of the shipped OLS fit, re-measured
    2026-10-09), and most fitted misconfig classes sit in thin cells. Falling
    straight to pooled would perturb exactly the high-p edges that decide paths
    under -log p at about a third of their true spread, and exp 2 would report
    the ranking as more stable than it is.

    Known residual bias, for the limitations section: the fit's predictions are
    compressed (predicted p tops out at 0.0186 while true EPSS reaches 0.99999),
    so conditioning on predicted p recovers only part of the spread variation:
    median |r| rises 0.51 -> 0.84 across predicted-p quintiles (1.6x) but is
    3.7x larger on the true top decile than on the bottom 90%. The empirical arm
    stays optimistic in the tail; the 4x and 8x scales in exp 2 bracket that.
    """

    def __init__(self, path=RESID):
        self.pooled: list[float] = []
        self.by_cell: dict[str, list[float]] = {}
        self.bands: list[tuple[float, list[float]]] = []
        if not os.path.exists(path):
            return
        rows = []
        with open(path, newline="") as fh:
            for r in csv.DictReader(fh):
                try:
                    e = float(r["resid_logit"])
                except (KeyError, TypeError, ValueError):
                    continue
                try:
                    pred = float(r.get("epss_pred", "nan"))
                except ValueError:
                    pred = float("nan")
                rows.append((pred, e))
                self.pooled.append(e)
                cell = _norm_vector(r.get("vector"))
                if cell:
                    self.by_cell.setdefault(cell, []).append(e)
        self._build_bands(sorted((p, e) for p, e in rows if p == p))

    def _build_bands(self, known):
        """Quantile bands over predicted p, split on VALUES not on positions.

        Predicted p is discrete -- the fit maps a whole CVSS vector cell to one
        number -- so a position-based split drops rows sharing a predicted p
        into different bands and a lookup then returns whichever band happens to
        come first. Boundaries are deduplicated so every tied row lands in the
        same band.
        """
        if not known:
            return
        n = len(known)
        edges, seen = [], set()
        for i in range(N_BANDS):
            hi = known[min(n - 1, (i + 1) * n // N_BANDS - 1)][0]
            if hi not in seen:
                seen.add(hi)
                edges.append(hi)
        edges[-1] = known[-1][0]
        self.bands = [(hi, []) for hi in edges]
        for p, e in known:
            for hi, pool in self.bands:
                if p <= hi:
                    pool.append(e)
                    break
        # a band with a handful of rows is the thin-pool problem again
        while len(self.bands) > 1 and len(self.bands[-1][1]) < MIN_CELL:
            hi, tail = self.bands.pop()
            self.bands[-1] = (hi, self.bands[-1][1] + tail)
        self.bands = [(hi, pool) for hi, pool in self.bands if pool]

    @property
    def available(self) -> bool:
        return bool(self.pooled)

    def _band(self, p: float | None) -> list[float]:
        if p is None or not self.bands:
            return self.pooled
        for hi, pool in self.bands:
            if p <= hi:
                return pool
        return self.bands[-1][1]

    def draw(self, rng, cell: str | None = None, scale: float = 1.0,
             pred_p: float | None = None) -> float:
        pool = self.by_cell.get(cell or "", [])
        if len(pool) < MIN_CELL:
            pool = self._band(pred_p)
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
                                  noise.draw(rng, cell, level, pred_p=p)))
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


def jaccard_at_k_tie_aware(scores_a: dict, scores_b: dict, k: int) -> float:
    """Jaccard over top-k-plus-boundary-ties (see chokepoints.top_k_set).

    Report beside the plain Jaccard@k, never instead of it: the plain one is
    what a practitioner reading a top-5 list actually gets, this one is what
    the scores actually say.
    """
    return set_jaccard(cp.top_k_set(scores_a, k), cp.top_k_set(scores_b, k))


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
