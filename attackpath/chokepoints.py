"""Choke points: dominator-based sets, weighted node min-cut, and node scores.

Three definitions of "choke point" are computed, because they are not the same
set and published tools rarely say which one they mean:

  global      v lies on EVERY path from ANY entry to ANY target   -- strictest
  per-target  v lies on every path reaching target t              -- what SOC teams act on
  per-pair    v lies on every path of one (entry, target) pair     -- finest, largest sets

`post_dominators` (super-source/super-sink + Lengauer-Tarjan) and
`pairwise_dominators` intersected over REACHABLE pairs are provably the same
set. That identity is a correctness test, never a reported finding.

Convention that must not drift: an (entry, target) pair where the target is
unreachable is SKIPPED. Treating it as the empty set breaks the identity
above instantly, since "every path" over an empty path set is vacuously true.

Endpoints (entries and targets) are excluded from every returned set by
default: a target trivially lies on every path to itself, and counting it would
make the global set look non-empty when it is structurally empty -- which is
precisely the headline number of exp 1b.
"""
from __future__ import annotations

import math
from itertools import product

import networkx as nx

SUPER_SOURCE = ("__source__", "__virtual__")
SUPER_SINK = ("__sink__", "__virtual__")
INF = float("inf")


def _dom_chain(idom: dict, node):
    """Walk a dominator tree from `node` to the root; yields node..root."""
    seen = set()
    cur = node
    while cur is not None and cur not in seen:
        seen.add(cur)
        yield cur
        nxt = idom.get(cur)
        cur = None if nxt == cur else nxt


def nodes_on_every_path(G: nx.DiGraph, s, t) -> set | None:
    """Nodes present on every s->t path. None if t is unreachable from s.

    Uses dominators rooted at s: v dominates t iff every s->t path visits v.
    """
    if s not in G or t not in G or not nx.has_path(G, s, t):
        return None
    idom = nx.immediate_dominators(G, s)
    if t not in idom:
        return None
    return set(_dom_chain(idom, t))


def post_dominators(G: nx.DiGraph, entries, targets,
                    include_endpoints: bool = False) -> set:
    """Global choke points via one virtual source and one virtual sink.

    Built on the reversed graph rooted at the sink, i.e. post-dominators of
    the virtual source.
    """
    entries, targets = list(entries), list(targets)
    H = G.copy()
    H.add_edges_from((SUPER_SOURCE, e) for e in entries)
    H.add_edges_from((t, SUPER_SINK) for t in targets)
    idom = nx.immediate_dominators(H.reverse(copy=True), SUPER_SINK)
    if SUPER_SOURCE not in idom:
        return set()
    dom = set(_dom_chain(idom, SUPER_SOURCE)) - {SUPER_SOURCE, SUPER_SINK}
    return dom if include_endpoints else dom - set(entries) - set(targets)


def pairwise_dominators(G: nx.DiGraph, entries, targets) -> dict:
    """{(entry, target): set of nodes on every path} for REACHABLE pairs only.

    Unreachable pairs are absent from the dict -- never present as an empty set.
    """
    entries, targets = list(entries), list(targets)
    out = {}
    for e, t in product(entries, targets):
        s = nodes_on_every_path(G, e, t)
        if s is not None:
            out[(e, t)] = s
    return out


def _strip_endpoints(s: set, entries, targets, include_endpoints: bool) -> set:
    return s if include_endpoints else s - set(entries) - set(targets)


def global_chokepoints(G, entries, targets, include_endpoints=False) -> set:
    """Intersection over reachable pairs. Equals post_dominators() by proof."""
    per_pair = pairwise_dominators(G, entries, targets)
    if not per_pair:
        return set()
    inter = set.intersection(*per_pair.values())
    return _strip_endpoints(inter, entries, targets, include_endpoints)


def per_target_chokepoints(G, entries, targets, include_endpoints=False) -> dict:
    """{target: nodes on every path reaching it from ANY entry}."""
    per_pair = pairwise_dominators(G, entries, targets)
    out = {}
    for t in targets:
        sets = [s for (e, tt), s in per_pair.items() if tt == t]
        if sets:
            out[t] = _strip_endpoints(set.intersection(*sets), entries, targets,
                                      include_endpoints)
    return out


def per_pair_chokepoints(G, entries, targets, include_endpoints=False) -> dict:
    return {k: _strip_endpoints(v, entries, targets, include_endpoints)
            for k, v in pairwise_dominators(G, entries, targets).items()}


# --- weighted min-cut over split nodes --------------------------------------

def prob_node_capacity(G: nx.DiGraph, v) -> float:
    """max p over incoming edges -- the node's easiest way in, on the
    probability scale. The cut is then the set through which the least attack
    probability flows."""
    ps = [d.get("p", 0.0) for _, _, d in G.in_edges(v, data=True)]
    return max(ps) if ps else INF


def cost_node_capacity(G: nx.DiGraph, v) -> float:
    """The same quantity on the -log p scale used everywhere else: the cheapest
    way in, in attacker-cost units.

    WARNING, and the reason this is not the default: a deterministic edge has
    p=1 and therefore w=0, so any node the attacker reaches for free has
    capacity 0 and can be cut for free. On graphs with structural edges the
    minimum cut collapses to a zero-capacity set that is chosen arbitrarily
    among the free nodes. Kept because comparing the two scales is a real
    sensitivity, exp 1a reports both.
    """
    ws = [d.get("w", INF) for _, _, d in G.in_edges(v, data=True)]
    return min(ws) if ws else INF


def unit_node_capacity(G: nx.DiGraph, v) -> float:
    """1 per node: the minimum NUMBER of nodes that must be removed.

    The control for objective 3. A dominator set reads no weights at all,
    so comparing it against a weighted cut mixes two differences -- different
    method and different weights -- into one disagreement number. The
    unit-capacity cut is the only one whose units match the dominator set's.
    """
    return 1.0


CAPACITIES = {"prob": prob_node_capacity, "cost": cost_node_capacity,
              "unit": unit_node_capacity}
default_node_capacity = prob_node_capacity


def node_min_cut(G: nx.DiGraph, entries, targets, capacity=None) -> set | None:
    """Minimum-weight NODE cut, via node splitting (v_in -> v_out).

    Node weight rides the internal edge; original edges get infinite capacity,
    so the cut can only ever contain internal edges and therefore maps back to a
    set of NODES -- the only form comparable with a dominator set. Entries and
    targets are uncuttable (infinite internal capacity): a "fix" that deletes
    the crown jewel is not a defence.
    """
    entries, targets = list(entries), list(targets)
    cap = capacity or default_node_capacity
    protected = set(entries) | set(targets)
    # An entry wired straight to a target has no intermediate node to remove,
    # so every source-sink path is all-infinite and no finite node cut exists.
    # That is a different statement from "the cut is empty" and must not be
    # merged with it -- exp 1a would read one as the other.
    if any(G.has_edge(e, t) for e in entries for t in targets):
        return None
    S = nx.DiGraph()
    for v in G.nodes:
        c = INF if v in protected else float(cap(G, v))
        S.add_edge((v, "in"), (v, "out"), capacity=c)
    for u, v in G.edges:
        S.add_edge((u, "out"), (v, "in"), capacity=INF)
    src, snk = ("__src__", "in"), ("__snk__", "out")
    for e in entries:
        S.add_edge(src, (e, "in"), capacity=INF)
    for t in targets:
        S.add_edge((t, "out"), snk, capacity=INF)
    _, (reach, _) = nx.minimum_cut(S, src, snk)
    cut = set()
    for v in G.nodes:
        if (v, "in") in reach and (v, "out") not in reach:
            cut.add(v)
    return cut


# --- how much of the danger crosses a domain boundary (PDF expected result 4) ---

def cross_domain_share(G: nx.DiGraph, entries, targets, weight="w") -> dict:
    """Two shares over the REACHABLE (entry, target) pairs.

    cheapest_cross_share  pairs whose cheapest (-log p) path uses >= 1 edge with
                          domain == "cross" -- "the most likely attack crosses".
    cross_required_share  pairs that become unreachable once every cross edge is
                          removed -- "no attack avoids crossing".

    Entries sit on-prem, so a CLOUD target is unreachable without a cross edge
    by construction: pooled over targets, the share mostly measures the target
    mix. The per-target-domain split below is the informative number -- in
    particular the share for ON-PREM targets, where crossing is optional.

    Cheapest path only, not k-shortest (Yen is ~minutes per n=800 graph); ties
    among equal-cost paths are broken by insertion order, which the seed
    fixes. Upgrade to a k-path share if one path per pair proves too coarse.
    """
    entries, targets = list(entries), list(targets)
    no_cross = G.copy()
    no_cross.remove_edges_from([(u, v) for u, v, d in G.edges(data=True)
                                if d.get("domain") == "cross"])
    def tdom(t):    # a target none of whose in-edges is on-prem lives in the cloud
        return ("cloud" if all(d.get("domain") != "onprem"
                               for *_, d in G.in_edges(t, data=True)) else "onprem")

    n = n_cheap = n_req = 0
    by = {"onprem": [0, 0, 0], "cloud": [0, 0, 0]}      # pairs, cheapest, required
    for e in entries:
        dist, paths = nx.single_source_dijkstra(G, e, weight=weight)
        for t in targets:
            if t not in dist:
                continue
            p = paths[t]
            cheap = any(G[u][v].get("domain") == "cross" for u, v in zip(p, p[1:]))
            req = not nx.has_path(no_cross, e, t)
            for acc in (by[tdom(t)], None):
                if acc is not None:
                    acc[0] += 1; acc[1] += cheap; acc[2] += req
            n += 1; n_cheap += cheap; n_req += req

    def share(a, b):
        return a / b if b else None
    out = {"n_pairs": n,
           "cheapest_cross_share": share(n_cheap, n),
           "cross_required_share": share(n_req, n)}
    for k, (m, c, r) in by.items():
        out[f"n_pairs_{k}_target"] = m
        out[f"cheapest_cross_share_{k}_target"] = share(c, m)
        out[f"cross_required_share_{k}_target"] = share(r, m)
    return out


# --- node ranking score ------------------------------------------------------

def _pair_costs(G, entries, targets, weight="w"):
    """{(e,t): cheapest -log p cost} over reachable pairs."""
    costs = {}
    for e in entries:
        dist = nx.single_source_dijkstra_path_length(G, e, weight=weight)
        for t in targets:
            if t in dist:
                costs[(e, t)] = dist[t]
    return costs


def _shortest_path_nodes(G, entries, targets, base, weight="w"):
    """Nodes lying on at least one cheapest path of some reachable pair.

    Exact candidate filter for delta_cost: a node off every cheapest path
    cannot change any cheapest cost, and cannot disconnect a pair either
    (a node that disconnects a pair lies on ALL of its paths, cheapest included).
    Costs |entries| + |targets| Dijkstra runs instead of |V| * |entries|.
    """
    fwd = {e: nx.single_source_dijkstra_path_length(G, e, weight=weight)
           for e in entries}
    R = G.reverse(copy=True)
    bwd = {t: nx.single_source_dijkstra_path_length(R, t, weight=weight)
           for t in targets}
    cand = set()
    for (e, t), c in base.items():
        de, dt = fwd[e], bwd[t]
        for v in G.nodes:
            if v in de and v in dt and math.isclose(de[v] + dt[v], c, rel_tol=1e-9,
                                                    abs_tol=1e-12):
                cand.add(v)
    return cand


def delta_cost_scores(G: nx.DiGraph, entries, targets, weight="w") -> dict:
    """Per-node ranking score. {node: (n_disconnected, delta, blocked_base)}.

    delta        summed increase in cheapest attacker cost over pairs that
                 remain reachable after removing the node
    n_disconnected  pairs the removal cuts outright
    blocked_base    total pre-removal cost of the pairs it cuts -- the
                 tie-break, ascending (cutting the attacker's CHEAPEST route
                 is worth more than cutting an expensive one)

    Entries and targets score zero: removing them is not a defensive option.
    """
    base = _pair_costs(G, entries, targets, weight)
    entries, targets = list(entries), list(targets)
    scores = {v: (0, 0.0, 0.0) for v in G.nodes}
    if not base:
        return scores
    protected = set(entries) | set(targets)
    for v in _shortest_path_nodes(G, entries, targets, base, weight) - protected:
        H = G.copy()
        H.remove_node(v)
        after = _pair_costs(H, entries, targets, weight)
        cut_n = delta = blocked = 0.0
        for pair, c in base.items():
            if pair in after:
                delta += after[pair] - c
            else:
                cut_n += 1
                blocked += c
        scores[v] = (int(cut_n), delta, blocked)
    return scores


def rank_nodes(scores: dict) -> list:
    """Lexicographic ordering: disconnecting nodes first (more pairs cut = higher),
    then by cheapest blocked route, then by summed cost increase. Ties broken by
    node id so the ranking is deterministic and Jaccard@k is reproducible."""
    return [v for v, _ in sorted(
        scores.items(),
        key=lambda kv: (-kv[1][0], kv[1][2] if kv[1][0] else 0.0,
                        -kv[1][1], str(kv[0])))]


def top_k(scores: dict, k: int) -> list:
    return rank_nodes(scores)[:k]


def top_k_set(scores: dict, k: int) -> set:
    """Top-k plus everyone tied with the k-th node's score.

    Serial structure makes exact ties routine, not exceptional: every node on a
    chain that all attack paths traverse cuts the same pairs at the same cost,
    so an assume-role chain of four is four identical scores. Plain top-k then
    slices that group by node id, and a Jaccard@k computed on it compares two
    arbitrary picks -- it comes out 1.0 whenever the tie-break is deterministic,
    which reads as stability and is not. This set is the honest comparison
    unit: it changes only when the SCORES change.
    """
    order = rank_nodes(scores)
    if len(order) <= k:
        return set(order)
    boundary = scores[order[k - 1]]
    return set(order[:k]) | {v for v, sc in scores.items() if sc == boundary}


def rank_diagnostics(scores: dict, n_pairs_reachable: int, ks=(5, 10)) -> dict:
    """Numbers that must accompany every Jaccard@k.

    n_inf        nodes whose removal cuts EVERY reachable pair. Delta is
                 infinite for all of them and identical, so the group has no
                 internal order -- it is a set, not a ranking. When
                 n_inf >= k, top-k is an arbitrary pick inside that set and
                 Jaccard@k measures nothing for that graph.
    n_tie_at_k   how many nodes share the score of the k-th ranked node, i.e.
                 how much of the top-k boundary is decided by the node-id
                 fallback rather than by the score.
    """
    out = {"n_inf": sum(1 for s in scores.values()
                        if n_pairs_reachable and s[0] == n_pairs_reachable)}
    order = rank_nodes(scores)
    for k in ks:
        if len(order) < k:
            out[f"n_tie_at_{k}"] = None      # top-k does not exist; not "no ties"
            continue
        edge_score = scores[order[k - 1]]
        out[f"n_tie_at_{k}"] = sum(1 for s in scores.values() if s == edge_score)
    return out
