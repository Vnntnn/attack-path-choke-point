"""Perturbation, edge dropping, and the rank-stability metrics.

Residual fixtures are written inline: data/ is gitignored, so a test that reads
the real residuals.csv passes here and fails on a fresh clone.
"""
import csv
import math
import random

import pytest

from attackpath import robustness as rb
from attackpath import weights as wt
from tests.test_dominator import ENTRIES, TARGETS, g6


def _residuals(tmp_path, rows):
    p = tmp_path / "residuals.csv"
    with open(p, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=["cve", "vector", "epss_pred",
                                           "resid_logit"])
        w.writeheader()
        w.writerows(rows)
    return str(p)


def test_deterministic_edges_are_never_perturbed():
    G = g6()
    for _, _, d in G.edges(data=True):
        d["p_source"] = "deterministic" if d["p"] == 0.9 else "epss"
    H = rb.perturb_weights(G, random.Random(0), noise_model="symmetric", level=0.5)
    for u, v, d in H.edges(data=True):
        if d["p_source"] == "deterministic":
            assert d["p"] == G.edges[u, v]["p"]


def test_symmetric_noise_stays_inside_its_band():
    G = g6()
    for _, _, d in G.edges(data=True):
        d["p_source"] = "epss"
    H = rb.perturb_weights(G, random.Random(1), noise_model="symmetric", level=0.2)
    for u, v, d in H.edges(data=True):
        base = G.edges[u, v]["p"]
        assert 0.8 * base - 1e-9 <= d["p"] <= min(1.0, 1.2 * base) + 1e-9
        assert math.isclose(d["w"], -math.log(d["p"]))


def test_vector_prefix_is_normalised_to_one_cell_key():
    assert rb._norm_vector("CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N") == \
        "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"


def test_dense_cell_is_preferred_over_the_band(tmp_path):
    vec = "AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
    rows = [{"cve": f"CVE-0-{i}", "vector": vec, "epss_pred": 0.01,
             "resid_logit": 7.0} for i in range(rb.MIN_CELL)]
    rows += [{"cve": f"CVE-1-{i}", "vector": "AV:L/AC:H/PR:H/UI:R/S:U/C:L/I:L/A:L",
              "epss_pred": 0.02, "resid_logit": -3.0} for i in range(50)]
    n = rb.EmpiricalNoise(_residuals(tmp_path, rows))
    rng = random.Random(0)
    assert all(n.draw(rng, vec) == 7.0 for _ in range(5))


def test_thin_cell_falls_back_to_the_predicted_p_band_not_the_pool(tmp_path):
    """The pooled fallback under-perturbs high-p edges, which is a bias toward
    reporting the ranking as more stable than it is."""
    rows = [{"cve": f"CVE-lo-{i}", "vector": f"AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:N/A:{i}",
             "epss_pred": 0.001, "resid_logit": 0.1} for i in range(100)]
    rows += [{"cve": f"CVE-hi-{i}", "vector": f"AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:{i}",
              "epss_pred": 0.9, "resid_logit": 5.0} for i in range(100)]
    n = rb.EmpiricalNoise(_residuals(tmp_path, rows))
    rng = random.Random(0)
    thin_high = "AV:A/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"      # absent from the file
    draws = [n.draw(rng, thin_high, pred_p=0.9) for _ in range(20)]
    assert all(d == 5.0 for d in draws), "high-p edge drew from the low-p band"
    assert all(n.draw(rng, thin_high, pred_p=0.001) == 0.1 for _ in range(20))


def test_no_band_holds_fewer_than_min_cell_rows(tmp_path):
    rows = [{"cve": f"CVE-{i}", "vector": "", "epss_pred": i / 1000,
             "resid_logit": i / 100} for i in range(1003)]   # deliberate remainder
    n = rb.EmpiricalNoise(_residuals(tmp_path, rows))
    assert n.bands and all(len(pool) >= rb.MIN_CELL for _, pool in n.bands)


def test_empirical_noise_without_residuals_refuses_loudly(tmp_path):
    n = rb.EmpiricalNoise(str(tmp_path / "absent.csv"))
    assert not n.available
    with pytest.raises(RuntimeError):
        rb.perturb_weights(g6(), random.Random(0), noise_model="empirical",
                           level=1.0, noise=n)


def test_drop_edges_is_seeded_and_removes_the_right_count():
    G = g6()
    a, ka, _ = rb.drop_edges(G, random.Random(4), 0.25, ENTRIES, TARGETS)
    b, kb, _ = rb.drop_edges(G, random.Random(4), 0.25, ENTRIES, TARGETS)
    assert ka == kb == round(0.25 * G.number_of_edges())
    assert sorted(a.edges()) == sorted(b.edges())
    assert G.number_of_edges() - a.number_of_edges() == ka


def test_jaccard_at_k_edges():
    assert rb.jaccard_at_k([1, 2, 3], [1, 2, 3], 3) == 1.0
    assert rb.jaccard_at_k([1, 2], [3, 4], 2) == 0.0
    assert rb.jaccard_at_k([], [], 5) == 1.0
    assert rb.jaccard_at_k([1, 2, 3], [3, 2, 1], 2) == pytest.approx(1 / 3)


def test_tie_aware_jaccard_ignores_the_node_id_tie_break():
    """Four nodes with identical scores: plain top-2 by node-id order is
    identical before and after, even though the underlying scores changed.
    The tie-aware set is not."""
    from attackpath import chokepoints as cp
    a = {("n", str(i)): (1, 3.0, 5.0) for i in range(4)}
    a[("x", "0")] = (2, 0.0, 9.0)
    b = dict(a)
    b[("n", "3")] = (1, 0.0, 5.0)          # drops out of the tie, id-sort keeps it last either way
    assert rb.jaccard_at_k(cp.rank_nodes(a), cp.rank_nodes(b), 2) == 1.0
    assert rb.jaccard_at_k_tie_aware(a, b, 2) < 1.0
