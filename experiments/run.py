#!/usr/bin/env python3
"""Runs the whole factor grid and writes results/exp*.csv.

One driver instead of five scripts: every experiment consumes the SAME graph,
and exp 4 needs the four weight models applied to one structure to be a paired
comparison at all. Generating 135 structures once and re-weighting them beats
generating them five times.

  135 structures  = 3 sizes x 3 cross-densities x 3 segmentations x 5 seeds
  540 weighted    = x 4 weight models

exp 5 (segmentation vs choke points) needs no run of its own -- segmentation is
already a factor, so it is an analysis over exp1b rows.

Usage:
  uv run experiments/run.py --sizes 50            # smoke
  uv run experiments/run.py --jobs 8              # full grid
"""
from __future__ import annotations

import argparse
import itertools
import random
import time
from concurrent.futures import ProcessPoolExecutor

from attackpath import chokepoints as cp
from attackpath import gen
from attackpath import results as rs
from attackpath import robustness as rb
from attackpath import weights as wt

SIZES = [50, 200, 800]
CROSS = ["low", "med", "high"]
SEG = ["flat", "3tier", "micro"]
MODELS = ["epss", "cvss", "uniform", "random"]
REPS = 5

SYM_LEVELS = [0.1, 0.2, 0.3, 0.5]     # the band the proposal names
EMP_SCALES = [0.5, 1.0, 2.0]          # multiples of the measured residual spread
NOISE_REPS = 3
DROP_FRACS = [0.05, 0.10, 0.20]
DROP_REPS = 3
BASE_SEED = 20260826
K_VALUES = (5, 10)

# A Jaccard@k without these two numbers beside it is uninterpretable --
# n_inf >= k means top-k was an arbitrary pick inside an unordered set.
DIAG = ["n_inf", "n_tie_at_5", "n_tie_at_10"]
DIAG_P = ["n_inf_pert", "n_tie_at_5_pert", "n_tie_at_10_pert"]

EXTRA = {
    "exp1a": ["capacity", "cut_exists", "n_global", "n_cut", "cut_value",
              "n_cut_free", "set_jaccard", "disagreement", "cut_in_global",
              "global_in_cut", "runtime_s"] + DIAG,
    "exp1b": ["definition", "target", "set_size", "non_empty", "n_pairs_reachable",
              "n_pairs_total", "runtime_s"] + DIAG,
    "exp2": ["noise_model", "noise_level", "rep", "jaccard5", "jaccard10",
             "kendall_tau", "global_set_jaccard"] + DIAG + DIAG_P,
    "exp3": ["drop_frac", "rep", "n_dropped", "pairs_reachable_before",
             "pairs_reachable_after", "jaccard5", "jaccard10",
             "kendall_tau"] + DIAG + DIAG_P,
    "exp4": ["model_a", "model_b", "jaccard5", "jaccard10", "kendall_tau",
             "global_set_jaccard"] + ["n_inf_a", "n_inf_b",
             "n_tie_at_5_a", "n_tie_at_5_b", "n_tie_at_10_a", "n_tie_at_10_b"],
}


def structures(sizes, reps):
    """(n, cross, seg, rep, seed) for every structural cell. Seed is a pure
    function of the cell, so any subset of the grid reproduces exactly."""
    for i, (n, c, s, r) in enumerate(
            itertools.product(sizes, CROSS, SEG, range(reps))):
        yield n, c, s, r, BASE_SEED + i


def _weighted(G, model, seed):
    H = G.copy()
    wt.assign(H, model, random.Random(seed), _CATALOG)
    return H


_CATALOG = wt.Catalog()


def run_structure(args):
    """All experiments for one structure. Returns {exp: [rows]}."""
    n, cross, seg, rep, seed, noise_avail = args
    out = {k: [] for k in EXTRA}
    G = gen.generate(n=n, cross_density=cross, segmentation=seg, seed=seed)
    ent, tgt = [x for x, d in G.nodes(data=True) if d.get("entry")], \
               [x for x, d in G.nodes(data=True) if d.get("target")]
    graph_id = f"{n}-{cross}-{seg}-r{rep}"
    noise = rb.EmpiricalNoise() if noise_avail else None
    per_model_scores, per_model_global, per_model_diag = {}, {}, {}

    for model in MODELS:
        H = _weighted(G, model, seed + hash(model) % 1000)
        H.graph["n_requested"] = n
        base = dict(rs.graph_row(H), graph_id=graph_id)
        rng = random.Random(seed)

        t0 = time.perf_counter()
        scores = cp.delta_cost_scores(H, ent, tgt)
        rank = cp.rank_nodes(scores)
        glob = cp.global_chokepoints(H, ent, tgt)
        cuts = {name: cp.node_min_cut(H, ent, tgt, fn)
                for name, fn in cp.CAPACITIES.items()}
        pairs = cp.pairwise_dominators(H, ent, tgt)
        t_core = time.perf_counter() - t0
        per_model_scores[model], per_model_global[model] = scores, glob
        diag = cp.rank_diagnostics(scores, len(pairs))
        per_model_diag[model] = diag

        # --- exp 1a: dominator set vs node min-cut, same units.
        # Both capacity scales are reported: which one is used changes the cut,
        # so baking one in would bake the answer into objective 3's headline.
        for capname, capfn in cp.CAPACITIES.items():
            cut = cuts[capname]
            if cut is None:      # entry adjacent to target: no finite node cut
                out["exp1a"].append(dict(base, **diag, capacity=capname,
                    cut_exists=0, n_global=len(glob), n_cut=None, cut_value=None,
                    n_cut_free=None, set_jaccard=None, disagreement=None,
                    cut_in_global=None, global_in_cut=None,
                    runtime_s=round(t_core, 4)))
                continue
            val = sum(capfn(H, v) for v in cut)
            out["exp1a"].append(dict(base, **diag, capacity=capname, cut_exists=1,
                n_global=len(glob), n_cut=len(cut), cut_value=round(val, 6),
                n_cut_free=sum(1 for v in cut if capfn(H, v) == 0.0),
                set_jaccard=rb.set_jaccard(glob, cut),
                disagreement=1 - rb.set_jaccard(glob, cut),
                cut_in_global=len(cut & glob) / len(cut) if cut else None,
                global_in_cut=len(cut & glob) / len(glob) if glob else None,
                runtime_s=round(t_core, 4)))

        # --- exp 1b: three definitions of choke point
        n_total = len(ent) * len(tgt)
        out["exp1b"].append(dict(base, **diag, definition="global", target="",
            set_size=len(glob), non_empty=int(bool(glob)),
            n_pairs_reachable=len(pairs), n_pairs_total=n_total,
            runtime_s=round(t_core, 4)))
        for t, s in cp.per_target_chokepoints(H, ent, tgt).items():
            out["exp1b"].append(dict(base, **diag, definition="per_target",
                target="|".join(t), set_size=len(s), non_empty=int(bool(s)),
                n_pairs_reachable=len(pairs), n_pairs_total=n_total,
                runtime_s=round(t_core, 4)))
        for (e, t), s in cp.per_pair_chokepoints(H, ent, tgt).items():
            out["exp1b"].append(dict(base, **diag, definition="per_pair",
                target=f"{'|'.join(e)}->{'|'.join(t)}", set_size=len(s),
                non_empty=int(bool(s)), n_pairs_reachable=len(pairs),
                n_pairs_total=n_total, runtime_s=round(t_core, 4)))

        # --- exp 2: weight perturbation
        arms = [("symmetric", lv) for lv in SYM_LEVELS]
        if noise and noise.available:
            arms += [("empirical", sc) for sc in EMP_SCALES]
        for nm, lv in arms:
            for r in range(NOISE_REPS):
                P = rb.perturb_weights(H, rng, noise_model=nm, level=lv, noise=noise)
                sc = cp.delta_cost_scores(P, ent, tgt)
                rk = cp.rank_nodes(sc)
                dp = cp.rank_diagnostics(sc, len(cp.pairwise_dominators(P, ent, tgt)))
                out["exp2"].append(dict(base, **diag,
                    **{f"{k}_pert": v for k, v in dp.items()},
                    noise_model=nm, noise_level=lv, rep=r,
                    jaccard5=rb.jaccard_at_k(rank, rk, 5),
                    jaccard10=rb.jaccard_at_k(rank, rk, 10),
                    kendall_tau=rb.kendall_tau(scores, sc),
                    global_set_jaccard=rb.set_jaccard(
                        glob, cp.global_chokepoints(P, ent, tgt))))

        # --- exp 3: missing edges
        for frac in DROP_FRACS:
            for r in range(DROP_REPS):
                D, k, reach = rb.drop_edges(H, rng, frac, ent, tgt)
                ent_d = [x for x in ent if x in D]
                tgt_d = [x for x in tgt if x in D]
                sc = cp.delta_cost_scores(D, ent_d, tgt_d)
                dp = cp.rank_diagnostics(sc, reach)
                out["exp3"].append(dict(base, **diag,
                    **{f"{key}_pert": v for key, v in dp.items()},
                    drop_frac=frac, rep=r, n_dropped=k,
                    pairs_reachable_before=len(pairs),
                    pairs_reachable_after=reach,
                    jaccard5=rb.jaccard_at_k(rank, cp.rank_nodes(sc), 5),
                    jaccard10=rb.jaccard_at_k(rank, cp.rank_nodes(sc), 10),
                    kendall_tau=rb.kendall_tau(scores, sc)))

    # --- exp 4: weight models against each other, same structure (paired)
    base4 = dict(rs.graph_row(G), graph_id=graph_id, n_requested=n)
    for a, b in itertools.combinations(MODELS, 2):
        ra, rb_ = cp.rank_nodes(per_model_scores[a]), cp.rank_nodes(per_model_scores[b])
        da, db = per_model_diag[a], per_model_diag[b]
        out["exp4"].append(dict(base4, weight_model=f"{a}+{b}", model_a=a, model_b=b,
            n_inf_a=da["n_inf"], n_inf_b=db["n_inf"],
            n_tie_at_5_a=da["n_tie_at_5"], n_tie_at_5_b=db["n_tie_at_5"],
            n_tie_at_10_a=da["n_tie_at_10"], n_tie_at_10_b=db["n_tie_at_10"],
            jaccard5=rb.jaccard_at_k(ra, rb_, 5),
            jaccard10=rb.jaccard_at_k(ra, rb_, 10),
            kendall_tau=rb.kendall_tau(per_model_scores[a], per_model_scores[b]),
            global_set_jaccard=rb.set_jaccard(per_model_global[a],
                                              per_model_global[b])))
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--sizes", type=int, nargs="*", default=SIZES)
    ap.add_argument("--reps", type=int, default=REPS)
    ap.add_argument("--jobs", type=int, default=1)
    ap.add_argument("--outdir", default="results")
    a = ap.parse_args()

    noise_avail = rb.EmpiricalNoise().available
    if not noise_avail:
        print("WARNING: data/fit/residuals.csv absent -- empirical noise arm skipped")
    work = [(n, c, s, r, seed, noise_avail)
            for n, c, s, r, seed in structures(a.sizes, a.reps)]
    writers = {k: rs.Writer(k, v, a.outdir) for k, v in EXTRA.items()}
    t0, done = time.perf_counter(), 0
    try:
        if a.jobs > 1:
            with ProcessPoolExecutor(a.jobs) as ex:
                for res in ex.map(run_structure, work):
                    done += 1
                    _flush(writers, res, done, len(work), t0)
        else:
            for w in work:
                done += 1
                _flush(writers, run_structure(w), done, len(work), t0)
    finally:
        for w in writers.values():
            w.close()


def _flush(writers, res, done, total, t0):
    for exp, rows in res.items():
        for row in rows:
            writers[exp].write(**row)
    el = time.perf_counter() - t0
    print(f"[{done}/{total}] {el:6.1f}s elapsed, eta {el/done*(total-done):6.1f}s",
          flush=True)


if __name__ == "__main__":
    main()
