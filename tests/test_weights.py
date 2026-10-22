"""w = -log p, the four models, and the provenance rule."""
import math
import random

import networkx as nx
import pytest

from attackpath import graph as ag
from attackpath import weights as wt


def test_w_is_monotone_and_zero_at_one():
    assert wt.w(1.0) == 0.0
    assert wt.w(0.5) > 0
    assert wt.w(1e-6) > wt.w(1e-3) > wt.w(0.5)
    with pytest.raises(ValueError):
        wt.w(0.0)
    with pytest.raises(ValueError):
        wt.w(1.5)


def test_w_matches_negative_log():
    assert math.isclose(wt.w(0.3), -math.log(0.3))


def test_cvss_base_score_matches_published_examples():
    cases = {"AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H": 9.8,
             "AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H": 10.0,
             "AV:L/AC:L/PR:L/UI:N/S:U/C:H/I:N/A:N": 5.5,
             "AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N": 6.1}
    for vec, want in cases.items():
        assert wt._base_from_vector(vec) == want


def _tiny():
    G = ag.new_graph(1)
    ag.add_edge(G, ("h1", "user"), ("h1", "root"), kind="cve",
                ref="CVE-2021-4034", domain="onprem")
    ag.add_edge(G, ("h1", "root"), ("role/app", "assume"), kind="misconfig",
                ref="aws-key-on-host", domain="cross")
    ag.add_edge(G, ("role/app", "assume"), ("s3://data", "read"),
                kind="deterministic", ref="iam-assume-role", domain="cloud")
    G.nodes[("h1", "user")]["entry"] = True
    G.nodes[("s3://data", "read")]["target"] = True
    return G


@pytest.mark.parametrize("model", sorted(wt.WEIGHT_MODELS))
def test_every_model_leaves_provenance_on_every_edge(model):
    G = _tiny()
    wt.assign(G, model, random.Random(7))
    ag.validate_weights(G)  # raises if p, p_source or p_input is missing
    for _, _, d in G.edges(data=True):
        assert d["p_source"] in ag.P_SOURCES
        assert math.isclose(d["w"], -math.log(d["p"]))


def test_trust_edges_are_deterministic_p_one():
    G = _tiny()
    wt.assign(G, "epss", random.Random(7))
    d = G.edges[("role/app", "assume"), ("s3://data", "read")]
    assert d["p"] == 1.0 and d["p_source"] == "deterministic" and d["w"] == 0.0


def test_random_model_is_seeded():
    a, b = _tiny(), _tiny()
    wt.assign(a, "random", random.Random(11))
    wt.assign(b, "random", random.Random(11))
    assert [d["p"] for *_, d in a.edges(data=True)] == \
           [d["p"] for *_, d in b.edges(data=True)]


def test_missing_fit_falls_back_to_expert_not_silently():
    """Until data/fit/ lands, a misconfig edge must say p_source='expert',
    never claim 'fitted'."""
    G = _tiny()
    cat = wt.Catalog(joined="/nonexistent", coeffs="/nonexistent",
                     rubric="/nonexistent")
    wt.assign(G, "epss", random.Random(3), cat)
    d = G.edges[("h1", "root"), ("role/app", "assume")]
    assert d["p_source"] == "expert" and d["p_input"].startswith("prior:")
