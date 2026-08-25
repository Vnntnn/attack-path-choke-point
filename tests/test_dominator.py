"""Choke-point definitions on a hand-checked graph.

        e1 ---\\                b
                a  <           X   > d --> t1, t2
        e2 ---/                c

        z --> t3        (t3 reachable from NO entry)

Every path from either entry to t1/t2 goes e -> a -> {b|c} -> d -> t.
So the global choke set is exactly {a, d}. t3 exists only to create
unreachable (entry, target) pairs.
"""
import networkx as nx
import pytest

from attackpath import chokepoints as cp

E1, E2 = ("e1", "user"), ("e2", "user")
A, B, C, D = ("a", "root"), ("b", "root"), ("c", "root"), ("d", "root")
T1, T2, T3 = ("t1", "read"), ("t2", "read"), ("t3", "read")
Z = ("z", "root")
ENTRIES, TARGETS = [E1, E2], [T1, T2, T3]


def g6():
    G = nx.DiGraph()
    edges = [(E1, A, 0.5), (E2, A, 0.4), (A, B, 0.9), (A, C, 0.9),
             (B, D, 0.9), (C, D, 0.9), (D, T1, 0.9), (D, T2, 0.9),
             (Z, T3, 0.9)]
    for u, v, p in edges:
        G.add_edge(u, v, p=p, w=-__import__("math").log(p))
    return G


def test_global_set_is_a_and_d():
    G = g6()
    assert cp.global_chokepoints(G, ENTRIES, TARGETS) == {A, D}


def test_post_dominator_equals_pairwise_intersection():
    """Super-source/super-sink dominators must equal pairwise intersection
    by construction -- this checks the implementation, it is not an
    experimental finding about the graphs themselves."""
    G = g6()
    assert cp.post_dominators(G, ENTRIES, TARGETS) == \
        cp.global_chokepoints(G, ENTRIES, TARGETS)


def test_unreachable_pairs_are_skipped_not_empty():
    """If (e, t3) were counted as the empty set the intersection would collapse
    to {} and the identity above would break."""
    G = g6()
    pairs = cp.pairwise_dominators(G, ENTRIES, TARGETS)
    assert set(pairs) == {(E1, T1), (E1, T2), (E2, T1), (E2, T2)}
    assert (E1, T3) not in pairs and (E2, T3) not in pairs


def test_three_definitions_differ_in_size():
    G = g6()
    G.add_edge(E1, D, p=0.1, w=2.3)  # a bypass that only entry e1 has
    glob = cp.global_chokepoints(G, ENTRIES, TARGETS)
    per_t = cp.per_target_chokepoints(G, ENTRIES, TARGETS)
    per_p = cp.per_pair_chokepoints(G, ENTRIES, TARGETS)
    assert glob == {D}                      # a is bypassable from e1 now
    assert per_t[T1] == {D} and T3 not in per_t
    assert per_p[(E2, T1)] == {A, D}        # e2 still has no bypass
    assert glob <= per_t[T1] <= per_p[(E2, T1)]


def test_empty_global_set_is_possible():
    """The headline of exp 1b: how often is the global set empty."""
    G = g6()
    G.add_edge(E1, T1, p=0.5, w=0.7)
    assert cp.global_chokepoints(G, ENTRIES, TARGETS) == set()


def test_endpoints_excluded_by_default():
    G = g6()
    assert not (cp.global_chokepoints(G, ENTRIES, TARGETS) & set(ENTRIES + TARGETS))
    with_ends = cp.post_dominators(G, ENTRIES, TARGETS, include_endpoints=True)
    assert with_ends >= cp.post_dominators(G, ENTRIES, TARGETS)
    # nodes_on_every_path is the raw primitive: it always keeps its endpoints
    assert cp.nodes_on_every_path(G, E1, T1) == {E1, A, D, T1}


def test_unreachable_returns_none():
    assert cp.nodes_on_every_path(g6(), E1, T3) is None
