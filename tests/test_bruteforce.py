"""Cross-check chokepoints.py against brute force on small random graphs.

Every reference below is written from the DEFINITION, with plain networkx
reachability / Dijkstra, not by calling the code under test:

  dominators   v is on every path of a pair  <=>  deleting v disconnects the pair
  node min-cut enumerate every subset of interior nodes, keep the cheapest one that
               disconnects all (entry, target) pairs
  delta(v)     delete v, rerun Dijkstra for every pair, from scratch -- this also
               checks that the shortest-path candidate filter never skips a node
               whose removal changes a cost
"""
import itertools
import math
import random

import networkx as nx
import pytest

from attackpath import chokepoints as cp

N_GRAPHS = 300
TOL = 1e-9


def rand_graph(seed):
    rng = random.Random(seed)
    n = rng.randint(6, 11)
    nodes = [(f"n{i}", "u") for i in range(n)]
    G = nx.DiGraph()
    G.add_nodes_from(nodes)
    dens = rng.choice([0.15, 0.25, 0.35])
    for u, v in itertools.permutations(nodes, 2):
        if rng.random() < dens:
            # p=1 edges (w=0) are common in the real graphs and create ties
            p = 1.0 if rng.random() < 0.3 else rng.uniform(0.02, 0.98)
            G.add_edge(u, v, p=p, w=-math.log(p))
    k_e, k_t = rng.randint(1, 2), rng.randint(1, 2)
    picks = rng.sample(nodes, k_e + k_t)
    return G, picks[:k_e], picks[k_e:]


def reachable_pairs(G, ent, tgt):
    return [(e, t) for e in ent for t in tgt if nx.has_path(G, e, t)]


def without(G, drop):
    H = G.copy()
    H.remove_nodes_from(drop)
    return H


def on_every_path(G, v, pair):
    return not nx.has_path(without(G, [v]), *pair)


@pytest.fixture(scope="module", params=range(N_GRAPHS))
def case(request):
    return (request.param, *rand_graph(request.param))


def test_global_dominators_match_brute_force(case):
    seed, G, ent, tgt = case
    pairs = reachable_pairs(G, ent, tgt)
    interior = [v for v in G if v not in set(ent) | set(tgt)]
    want = {v for v in interior if pairs and all(on_every_path(G, v, p) for p in pairs)}
    assert cp.global_chokepoints(G, ent, tgt) == want, f"seed {seed}"
    assert cp.post_dominators(G, ent, tgt) == want, f"seed {seed}"


def test_per_target_and_per_pair_match_brute_force(case):
    seed, G, ent, tgt = case
    pairs = reachable_pairs(G, ent, tgt)
    interior = [v for v in G if v not in set(ent) | set(tgt)]
    got_pair = cp.per_pair_chokepoints(G, ent, tgt)
    assert set(got_pair) == set(pairs), f"seed {seed}: unreachable pairs must be absent"
    for p in pairs:
        assert got_pair[p] == {v for v in interior if on_every_path(G, v, p)}, f"seed {seed} {p}"
    got_t = cp.per_target_chokepoints(G, ent, tgt)
    for t in tgt:
        ps = [p for p in pairs if p[1] == t]
        if not ps:
            assert t not in got_t
        else:
            assert got_t[t] == {v for v in interior if all(on_every_path(G, v, p) for p in ps)}, \
                f"seed {seed} target {t}"


def brute_min_cut_value(G, ent, tgt, cap):
    """Cheapest interior node set whose removal leaves no entry->target path."""
    protected = set(ent) | set(tgt)
    interior = [v for v in G if v not in protected and cap(G, v) != math.inf]
    best = math.inf
    for r in range(len(interior) + 1):
        for S in itertools.combinations(interior, r):
            H = without(G, S)
            if not any(nx.has_path(H, e, t) for e in ent for t in tgt):
                best = min(best, sum(cap(G, v) for v in S))
    return best


@pytest.mark.parametrize("capname", ["unit", "prob", "cost"])
def test_node_min_cut_is_optimal_and_valid(case, capname):
    seed, G, ent, tgt = case
    cap = cp.CAPACITIES[capname]
    cut = cp.node_min_cut(G, ent, tgt, cap)
    if any(G.has_edge(e, t) for e in ent for t in tgt):
        assert cut is None, f"seed {seed}: no finite node cut exists"
        return
    assert cut is not None
    assert not (cut & (set(ent) | set(tgt))), f"seed {seed}: endpoints are uncuttable"
    H = without(G, cut)
    assert not any(nx.has_path(H, e, t) for e in ent for t in tgt), f"seed {seed}: not a cut"
    got = sum(cap(G, v) for v in cut)
    want = brute_min_cut_value(G, ent, tgt, cap)
    assert math.isclose(got, want, abs_tol=TOL, rel_tol=1e-9), f"seed {seed} {capname}: {got} != {want}"


def brute_scores(G, ent, tgt):
    """{v: (n_disconnected, summed cost increase, blocked base cost)} from scratch."""
    def costs(H):
        out = {}
        for e in ent:
            if e not in H:
                continue
            for t in tgt:
                if t in H and nx.has_path(H, e, t):
                    out[(e, t)] = nx.dijkstra_path_length(H, e, t, weight="w")
        return out

    base = costs(G)
    protected = set(ent) | set(tgt)
    res = {}
    for v in G:
        if v in protected or not base:
            res[v] = (0, 0.0, 0.0)
            continue
        after = costs(without(G, [v]))
        n = delta = blocked = 0.0
        for pair, c in base.items():
            if pair in after:
                delta += after[pair] - c
            else:
                n += 1
                blocked += c
        res[v] = (int(n), delta, blocked)
    return res


def test_delta_scores_match_brute_force(case):
    seed, G, ent, tgt = case
    got, want = cp.delta_cost_scores(G, ent, tgt), brute_scores(G, ent, tgt)
    assert set(got) == set(want)
    for v in want:
        g, w = got[v], want[v]
        assert g[0] == w[0], f"seed {seed} {v}: n_disconnected {g[0]} != {w[0]}"
        assert math.isclose(g[1], w[1], abs_tol=1e-7), f"seed {seed} {v}: delta {g[1]} != {w[1]}"
        assert math.isclose(g[2], w[2], abs_tol=1e-7), f"seed {seed} {v}: blocked {g[2]} != {w[2]}"


def test_n_inf_equals_global_dominator_count(case):
    """The delta=inf group IS the global dominator set (endpoints excluded)."""
    seed, G, ent, tgt = case
    pairs = reachable_pairs(G, ent, tgt)
    sc = cp.delta_cost_scores(G, ent, tgt)
    n_inf = cp.rank_diagnostics(sc, len(pairs))["n_inf"]
    assert n_inf == len(cp.global_chokepoints(G, ent, tgt)), f"seed {seed}"
