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


# --- edge-case and regression tests ----------------------------------------

def test_entry_adjacent_to_target_has_no_finite_cut():
    """Every source-sink path is then all-infinite. 'No cut exists' must not be
    reported as 'the cut is empty' -- exp 1a would read one as the other."""
    import math

    import networkx as nx
    G = nx.DiGraph()
    G.add_edge(("e", "user"), ("t", "read"), p=0.5, w=-math.log(0.5))
    assert cp.node_min_cut(G, [("e", "user")], [("t", "read")]) is None


def test_generator_arguments_are_not_exhausted():
    G = g6()
    a = cp.post_dominators(G, (x for x in ENTRIES), (x for x in TARGETS))
    assert a == cp.post_dominators(G, ENTRIES, TARGETS)
    assert not (a & set(ENTRIES))


def test_tie_count_is_none_when_top_k_does_not_exist():
    import networkx as nx
    G = nx.DiGraph()
    G.add_edge(("e", "u"), ("c", "r"), p=0.5, w=0.69)
    G.add_edge(("c", "r"), ("t", "read"), p=0.5, w=0.69)
    d = cp.rank_diagnostics(cp.delta_cost_scores(G, [("e", "u")], [("t", "read")]), 1)
    assert d["n_tie_at_5"] is None and d["n_inf"] == 1


def test_capacity_scale_changes_the_cut():
    """Documented sensitivity, not a bug: the two scales disagree, so exp 1a
    reports both rather than baking one into objective 3's headline."""
    import math

    import networkx as nx
    G = nx.DiGraph()
    for i in range(4):
        G.add_edge(("e", "u"), (f"b{i}", "r"), p=0.2, w=-math.log(0.2))
        G.add_edge((f"b{i}", "r"), ("c", "r"), p=0.9, w=-math.log(0.9))
    G.add_edge(("c", "r"), ("t", "read"), p=0.9, w=-math.log(0.9))
    e, t = [("e", "u")], [("t", "read")]
    assert cp.node_min_cut(G, e, t, cp.prob_node_capacity) == {
        (f"b{i}", "r") for i in range(4)}
    assert cp.node_min_cut(G, e, t, cp.cost_node_capacity) == {("c", "r")}
    assert cp.global_chokepoints(G, e, t) == {("c", "r")}


def test_free_edges_make_the_cost_scale_degenerate():
    """Why prob is the default: p=1 structural edges have w=0, so on the cost
    scale a node reached for free can be cut for free and the minimum cut
    collapses to an arbitrary zero-capacity set."""
    import math

    import networkx as nx
    G = nx.DiGraph()
    G.add_edge(("e", "u"), ("free", "r"), p=1.0, w=0.0)
    G.add_edge(("free", "r"), ("c", "r"), p=0.3, w=-math.log(0.3))
    G.add_edge(("c", "r"), ("t", "read"), p=0.3, w=-math.log(0.3))
    e, t = [("e", "u")], [("t", "read")]
    cut = cp.node_min_cut(G, e, t, cp.cost_node_capacity)
    assert sum(cp.cost_node_capacity(G, v) for v in cut) == 0.0
    assert cut == {("free", "r")}
