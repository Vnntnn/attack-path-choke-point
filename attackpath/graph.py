"""Attack graph model: node = (resource, privilege), edge = one attacker action.

Declared semantics (non-negotiable):
  * OR-semantics -- v is reachable if ANY predecessor is reached. No AND-nodes.
  * Monotonic -- the attacker never loses a privilege already gained.
  * Every edge carries `p_source` in {epss, fitted, deterministic, expert}
    plus the input that produced it (`ref`), or it is not a valid edge.

The analyzer never touches Neo4j. Native format is JSON (node-link, keeps node
and graph attributes); `to_csv` exists for the lab exporter to write into.

Kept simple on purpose: plain nx.DiGraph + module functions, no wrapper class
-- nothing here needs state that the graph itself does not already hold.
"""
from __future__ import annotations

import csv
import json

import networkx as nx

Node = tuple[str, str]  # (resource, privilege)

P_SOURCES = frozenset({"epss", "fitted", "deterministic", "expert"})
KINDS = frozenset({"cve", "misconfig", "deterministic"})
DOMAINS = frozenset({"onprem", "cloud", "cross"})

EDGE_COLS = ["src_resource", "src_priv", "dst_resource", "dst_priv",
             "kind", "ref", "domain", "p", "p_source", "p_input"]


def new_graph(seed: int, **params) -> nx.DiGraph:
    G = nx.DiGraph(seed=seed, **params)
    return G


def add_edge(G: nx.DiGraph, u: Node, v: Node, *, kind: str, ref: str,
             domain: str, **attrs) -> None:
    """Add u->v. `p` is assigned later by weights.py, per weight model."""
    if kind not in KINDS:
        raise ValueError(f"bad kind {kind!r}")
    if domain not in DOMAINS:
        raise ValueError(f"bad domain {domain!r}")
    if u == v:
        raise ValueError(f"self-loop at {u}")
    G.add_edge(u, v, kind=kind, ref=ref, domain=domain, **attrs)


def entries(G: nx.DiGraph) -> list[Node]:
    return [n for n, d in G.nodes(data=True) if d.get("entry")]


def targets(G: nx.DiGraph) -> list[Node]:
    return [n for n, d in G.nodes(data=True) if d.get("target")]


def validate_structure(G: nx.DiGraph, require_cross: bool = True) -> None:
    """Structural invariants. Raises ValueError on the first violation.

    require_cross=False is for a deliberately single-domain graph (the lab's
    cloud-only export); every hybrid graph must keep the default."""
    if not entries(G):
        raise ValueError("graph has no entry node")
    if not targets(G):
        raise ValueError("graph has no target node")
    for n in G.nodes:
        if not (isinstance(n, tuple) and len(n) == 2):
            raise ValueError(f"node {n!r} is not a (resource, privilege) pair")
    for u, v, d in G.edges(data=True):
        if d.get("kind") not in KINDS:
            raise ValueError(f"edge {u}->{v} has kind={d.get('kind')!r}")
        if d.get("domain") not in DOMAINS:
            raise ValueError(f"edge {u}->{v} has domain={d.get('domain')!r}")
        if not d.get("ref"):
            raise ValueError(f"edge {u}->{v} has no provenance ref")
    if require_cross and not any(d["domain"] == "cross"
                                 for _, _, d in G.edges(data=True)):
        raise ValueError("hybrid graph with no cross-domain edge")
    for e in entries(G):
        for t in targets(G):
            if not nx.has_path(G, e, t):
                raise ValueError(f"target {t} unreachable from entry {e}")


def validate_weights(G: nx.DiGraph) -> None:
    """Objective 2: no edge may exist without an explainable p."""
    for u, v, d in G.edges(data=True):
        p, src = d.get("p"), d.get("p_source")
        if src not in P_SOURCES:
            raise ValueError(f"edge {u}->{v} has p_source={src!r}")
        if p is None or not (0.0 < p <= 1.0):
            raise ValueError(f"edge {u}->{v} has p={p!r}, need 0 < p <= 1")
        if d.get("p_input") in (None, ""):
            raise ValueError(f"edge {u}->{v} records no p_input")


def save_json(G: nx.DiGraph, path) -> None:
    data = nx.node_link_data(G, edges="edges")
    for node in data["nodes"]:
        node["id"] = list(node["id"])
    for e in data["edges"]:
        e["source"], e["target"] = list(e["source"]), list(e["target"])
    with open(path, "w") as fh:
        json.dump(data, fh)


def load_json(path) -> nx.DiGraph:
    with open(path) as fh:
        data = json.load(fh)
    for node in data["nodes"]:
        node["id"] = tuple(node["id"])
    for e in data["edges"]:
        e["source"], e["target"] = tuple(e["source"]), tuple(e["target"])
    return nx.node_link_graph(data, directed=True, edges="edges")


def to_csv(G: nx.DiGraph, path) -> None:
    """Flat edge list -- the format the lab exporter must produce."""
    with open(path, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=EDGE_COLS)
        w.writeheader()
        for (ur, up), (vr, vp), d in G.edges(data=True):
            w.writerow({"src_resource": ur, "src_priv": up,
                        "dst_resource": vr, "dst_priv": vp,
                        "kind": d.get("kind"), "ref": d.get("ref"),
                        "domain": d.get("domain"), "p": d.get("p"),
                        "p_source": d.get("p_source"),
                        "p_input": d.get("p_input")})


def from_csv(path, entry_nodes: list[Node], target_nodes: list[Node]) -> nx.DiGraph:
    G = nx.DiGraph()
    with open(path, newline="") as fh:
        for r in csv.DictReader(fh):
            u = (r["src_resource"], r["src_priv"])
            v = (r["dst_resource"], r["dst_priv"])
            attrs = {k: r[k] for k in ("kind", "ref", "domain", "p_source", "p_input")}
            attrs["p"] = float(r["p"]) if r["p"] else None
            G.add_edge(u, v, **attrs)
    for n in entry_nodes:
        G.nodes[n]["entry"] = True
    for n in target_nodes:
        G.nodes[n]["target"] = True
    return G
