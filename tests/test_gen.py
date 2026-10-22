"""Generator invariants. The graphs are the experiment's input data, so a
silent drift here invalidates every result CSV downstream."""
import pytest

from attackpath import gen
from attackpath.graph import validate_structure

GRID = [(n, c, s) for n in (50, 200) for c in ("low", "med", "high")
        for s in ("flat", "3tier", "micro")]


def _edges(G):
    return sorted((u, v, d["ref"]) for u, v, d in G.edges(data=True))


def test_same_seed_is_identical():
    a = gen.generate(200, "med", "3tier", 42)
    b = gen.generate(200, "med", "3tier", 42)
    assert _edges(a) == _edges(b)
    assert sorted(map(str, a.nodes)) == sorted(map(str, b.nodes))
    assert a.graph == b.graph


def test_different_seeds_differ():
    assert _edges(gen.generate(200, "med", "3tier", 1)) != \
           _edges(gen.generate(200, "med", "3tier", 2))


@pytest.mark.parametrize("n,c,s", GRID)
def test_grid_is_structurally_valid(n, c, s):
    G = gen.generate(n, c, s, 11)
    validate_structure(G)                       # entries, targets, refs, cross, reachability
    assert abs(G.number_of_nodes() - n) <= 0.1 * n
    assert G.graph["n_repair_edges"] <= 0.05 * G.number_of_edges()


@pytest.mark.parametrize("c", ["low", "med", "high"])
def test_cross_edges_span_several_classes(c):
    G = gen.generate(200, c, "3tier", 5)
    refs = {d["ref"] for _, _, d in G.edges(data=True) if d["domain"] == "cross"}
    assert len(refs) >= 2


def test_entry_target_counts_are_locked():
    for n, (ne, nt) in gen.ENTRY_TARGET.items():
        if n == 800:
            continue
        G = gen.generate(n, "med", "flat", 3)
        assert G.graph["n_entries"] == ne and G.graph["n_targets"] == nt


def test_segmentation_actually_restricts_movement():
    def lateral(seg):
        G = gen.generate(200, "med", seg, 9)
        return sum(1 for _, _, d in G.edges(data=True) if d["domain"] == "onprem")
    assert lateral("micro") < lateral("3tier") < lateral("flat")


def test_structural_edges_are_deterministic_kind():
    G = gen.generate(200, "high", "flat", 4)
    for _, _, d in G.edges(data=True):
        if d["ref"] in ("vpn-dx-to-private-subnet", "federated-identity-trust",
                        "iam-assume-role", "flat-vlan", "sg-open-mgmt-port"):
            assert d["kind"] == "deterministic", d


def test_targets_span_both_domains():
    G = gen.generate(200, "med", "3tier", 6)
    tg = [t for t, d in G.nodes(data=True) if d.get("target")]
    assert any(t[0].startswith("s3://") for t in tg) and ("dc01", "root") in tg


def test_single_domain_graph_needs_require_cross_false():
    import pytest
    from attackpath.graph import add_edge, new_graph
    G = new_graph(1)
    add_edge(G, ("a", "x"), ("b", "y"), kind="deterministic", ref="r", domain="cloud")
    G.nodes[("a", "x")]["entry"] = True
    G.nodes[("b", "y")]["target"] = True
    with pytest.raises(ValueError, match="no cross-domain edge"):
        validate_structure(G)
    validate_structure(G, require_cross=False)


def test_git_rev_flags_uncommitted_code(tmp_path, monkeypatch):
    import subprocess
    from attackpath import results
    run = lambda *a: subprocess.run(a, cwd=tmp_path, check=True, capture_output=True)
    run("git", "init", "-q"); run("git", "config", "user.email", "t@t"); run("git", "config", "user.name", "t")
    (tmp_path / "attackpath").mkdir(); (tmp_path / "attackpath" / "x.py").write_text("a=1\n")
    run("git", "add", "."); run("git", "commit", "-qm", "c")
    monkeypatch.chdir(tmp_path)
    assert not results.git_rev().endswith("+dirty")
    (tmp_path / "attackpath" / "x.py").write_text("a=2\n")
    assert results.git_rev().endswith("+dirty")
