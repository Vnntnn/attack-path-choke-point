from attackpath.chokepoints import cross_domain_share
from attackpath.graph import add_edge, new_graph


def _g(p_cross=0.5):
    # entry -> a -> t (on-prem, cheap, w=0.1+0.1); entry -> b ==cross==> t2 (w=0.7)
    G = new_graph(1)
    add_edge(G, ("e", "u"), ("a", "u"), kind="deterministic", ref="r", domain="onprem", w=0.1)
    add_edge(G, ("a", "u"), ("t1", "r"), kind="deterministic", ref="r", domain="onprem", w=0.1)
    add_edge(G, ("e", "u"), ("b", "u"), kind="deterministic", ref="r", domain="onprem", w=0.1)
    add_edge(G, ("b", "u"), ("t2", "r"), kind="misconfig", ref="r", domain="cross", w=0.6)
    return G


def test_cross_share_counts_cheapest_path_and_required_crossing():
    s = cross_domain_share(_g(), [("e", "u")], [("t1", "r"), ("t2", "r")])
    assert s["n_pairs"] == 2
    assert s["cheapest_cross_share"] == 0.5   # only the t2 pair crosses
    assert s["cross_required_share"] == 0.5   # t2 unreachable without the cross edge


def test_cheapest_path_can_avoid_a_cross_edge_that_exists():
    G = _g()
    add_edge(G, ("a", "u"), ("t2", "r"), kind="deterministic", ref="r", domain="onprem", w=0.05)
    s = cross_domain_share(G, [("e", "u")], [("t2", "r")])
    assert s["cheapest_cross_share"] == 0.0   # cheaper on-prem route exists
    assert s["cross_required_share"] == 0.0   # and crossing is not required


def test_share_is_split_by_target_domain():
    s = cross_domain_share(_g(), [("e", "u")], [("t1", "r"), ("t2", "r")])
    assert s["n_pairs_onprem_target"] == 1 and s["n_pairs_cloud_target"] == 1
    assert s["cheapest_cross_share_onprem_target"] == 0.0   # t1: on-prem only route
    assert s["cheapest_cross_share_cloud_target"] == 1.0    # t2 (in-edge is cross)
    assert s["cross_required_share_onprem_target"] == 0.0
