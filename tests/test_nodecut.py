"""Min-cut must come back as a NODE set (via node splitting).

An edge cut
compared against a dominator set gives a number that looks fine and means
nothing.
"""
from attackpath import chokepoints as cp
from tests.test_dominator import A, D, E1, E2, ENTRIES, TARGETS, T1, g6


def test_cut_elements_are_graph_nodes_not_edges():
    G = g6()
    cut = cp.node_min_cut(G, ENTRIES, TARGETS)
    assert cut, "empty cut on a connected graph"
    for v in cut:
        assert v in G.nodes, f"{v!r} is not a node of G -- edge cut leaked through"
        assert isinstance(v, tuple) and len(v) == 2 and v[1] != "in"


def test_cut_picks_the_cheapest_bottleneck():
    """cap(a) = max incoming p = 0.5, cap(d) = 0.9, cap({b,c}) = 1.8."""
    G = g6()
    assert cp.node_min_cut(G, ENTRIES, TARGETS) == {A}


def test_cut_never_contains_entries_or_targets():
    G = g6()
    cut = cp.node_min_cut(G, ENTRIES, TARGETS)
    assert not (cut & (set(ENTRIES) | set(TARGETS)))


def test_cut_actually_disconnects():
    G = g6()
    cut = cp.node_min_cut(G, ENTRIES, TARGETS)
    H = G.copy()
    H.remove_nodes_from(cut)
    import networkx as nx
    for e in ENTRIES:
        for t in TARGETS:
            if e in H and t in H:
                assert not nx.has_path(H, e, t)


def test_delta_cost_ranks_the_choke_points_first():
    G = g6()
    scores = cp.delta_cost_scores(G, ENTRIES, TARGETS)
    assert scores[A][0] == 4 and scores[D][0] == 4   # both cut all 4 pairs
    assert scores[E1] == (0, 0.0, 0.0)               # entries are not options
    assert set(cp.top_k(scores, 2)) == {A, D}
