"""Choke points: dominator-based sets, weighted node min-cut, and node scores.

Three definitions of "choke point" are computed, because they are not the same
set and published tools rarely say which one they mean:

  global      v lies on EVERY path from ANY entry to ANY target   -- strictest
  per-target  v lies on every path reaching target t              -- what SOC teams act on
  per-pair    v lies on every path of one (entry, target) pair     -- finest, largest sets

`post_dominators` (super-source/super-sink + Lengauer-Tarjan) and
`pairwise_dominators` intersected over REACHABLE pairs are provably the same
set. That identity is a correctness test, never a reported finding.

Convention that must not drift: an (entry, target) pair where the
target is unreachable is SKIPPED. Treating it as the empty set breaks the
identity above instantly, since "every path" over an empty path set is
vacuously true.

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

    Built on the reversed graph rooted at the sink, i.e. post-dominators of the
    virtual source.
    """
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

def default_node_capacity(G: nx.DiGraph, v) -> float:
    """How much attack flow a node can carry = its easiest way in.

    max p over incoming edges. Interpreting the cut: the returned node set is
    the bottleneck through which the LEAST attack probability flows. Entries
    have no incoming edge and are made uncuttable by node_min_cut anyway.
    """
    ps = [d.get("p", 0.0) for _, _, d in G.in_edges(v, data=True)]
    return max(ps) if ps else INF


def node_min_cut(G: nx.DiGraph, entries, targets, capacity=None) -> set:
    """Minimum-weight NODE cut, via node splitting (v_in -> v_out).

    Node weight rides the internal edge; original edges get infinite capacity,
    so the cut can only ever contain internal edges and therefore maps back to a
    set of NODES -- the only form comparable with a dominator set. Entries and
    targets are uncuttable (infinite internal capacity): a "fix" that deletes
    the crown jewel is not a defence.
    """
    cap = capacity or default_node_capacity
    protected = set(entries) | set(targets)
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
    """Lexicographic ordering: disconnecting nodes first (more pairs cut = higher), then by
    cheapest blocked route, then by summed cost increase. Ties broken by node id
    so the ranking is deterministic and Jaccard@k is reproducible."""
    return [v for v, _ in sorted(
        scores.items(),
        key=lambda kv: (-kv[1][0], kv[1][2] if kv[1][0] else 0.0,
                        -kv[1][1], str(kv[0])))]


def top_k(scores: dict, k: int) -> list:
    return rank_nodes(scores)[:k]
