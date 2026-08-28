"""p(e) -> w(e) = -log p(e), and the four weight models compared in exp 4.

Provenance rule: every edge leaves here with `p`, `p_source` in {epss, fitted,
deterministic, expert} and `p_input` naming the exact input used. An edge
without those is a bug, not an edge.

Reading of the result: Dijkstra over -log p gives the most-likely single
path, i.e. a LOWER BOUND on attacker cost -- not P(compromise), because
OR-semantics lets several paths compound.

Kept simple on purpose: a dict of four small functions, no strategy classes.
"""
from __future__ import annotations

import csv
import json
import math
import os

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JOINED = os.path.join(ROOT, "data", "fit", "cvss_epss_joined.csv")
FIT_COEF = os.path.join(ROOT, "data", "fit", "fit_coeffs.json")
RUBRIC = os.path.join(ROOT, "data", "fit", "misconfig_vectors.json")

# p is clamped away from 0 and 1: -log 0 is infinite (an unusable edge weight)
# and p = 1 on an exploit edge would claim certainty EPSS never expresses.
P_MIN, P_MAX = 1e-6, 1.0


def w(p: float) -> float:
    """Edge weight. p=1 -> 0 cost; p->0 -> +inf cost; strictly decreasing."""
    if not (0.0 < p <= 1.0):
        raise ValueError(f"p={p!r} outside (0, 1]")
    return -math.log(p)


def clamp(p: float) -> float:
    return min(max(p, P_MIN), P_MAX)


class Catalog:
    """Lazy holder for the EPSS/CVSS join, the fit, and the misconfig rubric.

    Every lookup is by the edge's `ref`, so the p on an edge is always
    traceable back to a named CVE or a named misconfig class.
    """

    def __init__(self, joined=JOINED, coeffs=FIT_COEF, rubric=RUBRIC):
        self._paths = (joined, coeffs, rubric)
        self._cve = None
        self._coeffs = None
        self._rubric = None

    @property
    def cve(self) -> dict[str, dict]:
        if self._cve is None:
            self._cve = {}
            path = self._paths[0]
            if os.path.exists(path):
                with open(path, newline="") as fh:
                    for r in csv.DictReader(fh):
                        self._cve[r["cve"]] = r
        return self._cve

    @property
    def coeffs(self) -> dict | None:
        if self._coeffs is None:
            path = self._paths[1]
            self._coeffs = json.load(open(path)) if os.path.exists(path) else {}
        return self._coeffs or None

    @property
    def rubric(self) -> dict[str, str]:
        """misconfig slug -> CVSS v3.1 vector string, from the rubric's vector table."""
        if self._rubric is None:
            path = self._paths[2]
            self._rubric = json.load(open(path)) if os.path.exists(path) else {}
        return self._rubric

    def epss(self, cve: str) -> float | None:
        row = self.cve.get(cve)
        return float(row["epss"]) if row else None

    def base_score(self, cve: str) -> float | None:
        row = self.cve.get(cve)
        return float(row["base_score"]) if row and row["base_score"] else None

    def fitted_p(self, vector: str) -> float | None:
        """CVSS vector -> predicted EPSS, using the OLS fit. None until fitted."""
        c = self.coeffs
        if not c or not vector:
            return None
        z = c["intercept"]
        for part in vector.split("/"):
            metric, _, value = part.partition(":")
            z += c["terms"].get(f"{metric}:{value}", 0.0)
        return clamp(1.0 / (1.0 + math.exp(-z)))


# --- the four weight models -------------------------------------------------
# Each returns (p, p_source, p_input). `ctx` is a Catalog.

def _deterministic(d, ctx, rng):
    return 1.0, "deterministic", f"trust:{d['ref']}"


def _misconfig(d, ctx, rng, fallback):
    vec = ctx.rubric.get(d["ref"])
    p = ctx.fitted_p(vec) if vec else None
    if p is not None:
        return p, "fitted", f"cvss:{vec}"
    # No fit yet or class absent from the rubric: fall back to a
    # declared expert prior, never to a silent default.
    return fallback, "expert", f"prior:{d['ref']}"


def _epss_model(d, ctx, rng):
    if d["kind"] == "deterministic":
        return _deterministic(d, ctx, rng)
    if d["kind"] == "misconfig":
        return _misconfig(d, ctx, rng, fallback=0.1)
    p = ctx.epss(d["ref"])
    if p is None:
        return 0.01, "expert", f"prior:cve-not-in-epss:{d['ref']}"
    return clamp(p), "epss", f"epss:{d['ref']}"


def _cvss_model(d, ctx, rng):
    """CVSS base score / 10 as a stand-in probability -- the practice this
    project is testing, not endorsing."""
    if d["kind"] == "deterministic":
        return _deterministic(d, ctx, rng)
    if d["kind"] == "misconfig":
        vec = ctx.rubric.get(d["ref"])
        if vec:
            return clamp(_base_from_vector(vec) / 10.0), "expert", f"cvss-base:{vec}"
        return 0.5, "expert", f"prior:{d['ref']}"
    b = ctx.base_score(d["ref"])
    if b is None:
        return 0.5, "expert", f"prior:cve-not-in-nvd:{d['ref']}"
    return clamp(b / 10.0), "expert", f"cvss-base:{d['ref']}"


def _uniform_model(d, ctx, rng):
    if d["kind"] == "deterministic":
        return _deterministic(d, ctx, rng)
    return 0.5, "expert", "uniform:0.5"


def _random_model(d, ctx, rng):
    """Null model. Any structure that survives this is structure, not signal."""
    if d["kind"] == "deterministic":
        return _deterministic(d, ctx, rng)
    return clamp(rng.random()), "expert", "random"


def _fitted_model(d, ctx, rng):
    """Every exploitable edge priced by the CVSS->EPSS fit, including CVE edges
    whose true EPSS is known. Only used by exp 6: running it against the epss
    model measures how far the fit's error moves the choke-point ranking, which
    is the one thing Spearman rho cannot tell us (path cost is a SUM of -log p,
    so a monotone per-edge map can still reorder paths)."""
    if d["kind"] == "deterministic":
        return _deterministic(d, ctx, rng)
    if d["kind"] == "misconfig":
        return _misconfig(d, ctx, rng, fallback=0.1)
    row = ctx.cve.get(d["ref"])
    vec = row.get("vector") if row else None
    p = ctx.fitted_p(vec) if vec else None
    if p is None:
        return 0.01, "expert", f"prior:no-vector:{d['ref']}"
    return p, "fitted", f"cvss:{vec}"


WEIGHT_MODELS = {
    "epss": _epss_model,
    "fitted": _fitted_model,
    "cvss": _cvss_model,
    "uniform": _uniform_model,
    "random": _random_model,
}

_CVSS_W = {  # CVSS v3.1 base metric weights, spec table 8.4
    "AV": {"N": 0.85, "A": 0.62, "L": 0.55, "P": 0.2},
    "AC": {"L": 0.77, "H": 0.44},
    "PR_U": {"N": 0.85, "L": 0.62, "H": 0.27},
    "PR_C": {"N": 0.85, "L": 0.68, "H": 0.5},
    "UI": {"N": 0.85, "R": 0.62},
    "CIA": {"H": 0.56, "L": 0.22, "N": 0.0},
}


def _base_from_vector(vec: str) -> float:
    """CVSS v3.1 base score from a vector string (spec section 8.4)."""
    m = dict(part.split(":", 1) for part in vec.split("/") if ":" in part)
    scope_c = m.get("S") == "C"
    iss = 1 - (1 - _CVSS_W["CIA"][m["C"]]) * (1 - _CVSS_W["CIA"][m["I"]]) * (
        1 - _CVSS_W["CIA"][m["A"]])
    if scope_c:
        impact = 7.52 * (iss - 0.029) - 3.25 * (iss - 0.02) ** 15
    else:
        impact = 6.42 * iss
    expl = 8.22 * _CVSS_W["AV"][m["AV"]] * _CVSS_W["AC"][m["AC"]] * \
        _CVSS_W["PR_C" if scope_c else "PR_U"][m["PR"]] * _CVSS_W["UI"][m["UI"]]
    if impact <= 0:
        return 0.0
    raw = min((1.08 if scope_c else 1.0) * (impact + expl), 10.0)
    return math.ceil(raw * 10) / 10  # spec roundup


def assign(G, model: str, rng, catalog: Catalog | None = None) -> None:
    """Set p / p_source / p_input / w on every edge, in place."""
    if model not in WEIGHT_MODELS:
        raise ValueError(f"unknown weight model {model!r}")
    fn, ctx = WEIGHT_MODELS[model], catalog or Catalog()
    for _, _, d in G.edges(data=True):
        p, src, inp = fn(d, ctx, rng)
        d["p"], d["p_source"], d["p_input"], d["w"] = p, src, inp, w(p)
    G.graph["weight_model"] = model
