"""Seeded generator for hybrid on-prem + cloud attack graphs.

Sampling model (documented because the generator ships as part of the artifact):

  node budget      ~60% on-prem, ~40% cloud
  on-prem host     two nodes, (h, "user") and (h, "root"), joined by a
                   local-privesc edge carrying a real CVE id
  lateral degree   out-degree per host is fixed by segmentation, so
                   micro < 3tier < flat by construction, not by chance
  cloud            roles / storage+secret resources / instances in 4:4:2
  edge mix         on-prem lateral ~50% cve, ~30% misconfig, ~20% structural;
                   cloud role->role and instance->role are structural
  cross-domain     five named classes, count scales with cross_density and n

Structural edges (flat VLAN, security group 0.0.0.0/0, VPC peering, role
assume, forest trust) are kind="deterministic": they decide whether the edge
EXISTS, they are not exploited. weights.py gives them p=1.0.

This module assigns no p -- only structure and the provenance `ref` that
weights.py resolves per weight model.
"""
from __future__ import annotations

import csv
import math
import os
import random

import networkx as nx

from .graph import add_edge, new_graph

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
JOINED = os.path.join(ROOT, "data", "fit", "cvss_epss_joined.csv")
PARTIAL = os.path.join(ROOT, "data", "fit", "cvss_epss_partial.csv")
RAW = os.path.join(ROOT, "data", "raw")

# Locked counts, so pairwise_dominators cost cannot drift between runs
ENTRY_TARGET = {50: (3, 2), 200: (5, 3), 800: (8, 4)}
LATERAL_DEGREE = {"flat": 3, "3tier": 2, "micro": 1}
CROSS_BASE = {"low": 1, "med": 2, "high": 4}
ONPREM_SHARE = 0.6

# slugs must match the misconfig rubric's exactly; misconfig slugs resolve
# through data/fit/misconfig_vectors.json, structural ones never do
MISCONFIG_LATERAL = ["smb-signing-disabled", "shared-local-admin-password",
                     "unauth-internal-service"]
MISCONFIG_CLOUD = ["s3-public-read", "s3-public-write",
                   "iam-trust-wildcard-principal",
                   "iam-trust-missing-external-id",
                   "iam-passrole-excess-privilege",
                   "stale-service-account-cred",
                   "federated-group-overbroad-role"]
STRUCTURAL_LATERAL = ["flat-vlan", "sg-open-mgmt-port"]
CROSS_CLASSES = [
    ("aws-key-on-host", "misconfig"),
    ("ssrf-imdsv1-token", "misconfig"),
    ("cicd-oidc-broad-sub", "misconfig"),
    ("vpn-dx-to-private-subnet", "deterministic"),
    ("federated-identity-trust", "deterministic"),
]

_CVES: list[str] | None = None
_SNAPSHOT: str | None = None


def _snapshot() -> str:
    """Which EPSS snapshot the pool was drawn against. A re-scored snapshot
    changes p(e) without changing the pool size, so the seed alone does not
    reproduce a weighted graph -- the snapshot has to ride along with it."""
    global _SNAPSHOT
    if _SNAPSHOT is None:
        files = (sorted(f for f in os.listdir(RAW) if f.startswith("epss_scores-"))
                 if os.path.isdir(RAW) else [])
        _SNAPSHOT = files[-1] if files else "none"
    return _SNAPSHOT


def _cve_pool() -> list[str]:
    """Real CVE ids, so an edge has BOTH an EPSS score and a CVSS vector and the
    weight-model comparison is paired. Falls back to synthetic ids, loudly."""
    global _CVES
    if _CVES is None:
        _CVES = []
        for path in (JOINED, PARTIAL):
            if os.path.exists(path):
                with open(path, newline="") as fh:
                    _CVES = [r["cve"] for r in csv.DictReader(fh) if r.get("cve")]
                if _CVES:
                    break
    return _CVES


def _zones(hosts: list[str], segmentation: str, rng) -> tuple[dict, dict]:
    """host -> zone, and zone -> zones it may reach directly."""
    if segmentation == "flat":
        zmap = {h: "flat" for h in hosts}
        return zmap, {"flat": ["flat"]}
    if segmentation == "3tier":
        names = ["dmz", "app", "db"]
        zmap = {h: names[min(i * 3 // len(hosts), 2)] for i, h in enumerate(hosts)}
        return zmap, {"dmz": ["dmz", "app"], "app": ["app", "db"], "db": ["db"]}
    n_z = max(3, math.ceil(len(hosts) / 3))
    names = [f"z{i}" for i in range(n_z)]
    zmap = {h: names[i % n_z] for i, h in enumerate(hosts)}
    # a chain of allow-list exceptions: each zone reaches itself and the next
    allow = {z: [z, names[(i + 1) % n_z]] for i, z in enumerate(names)}
    return zmap, allow


def generate(n: int, cross_density: str, segmentation: str, seed: int) -> nx.DiGraph:
    if cross_density not in CROSS_BASE or segmentation not in LATERAL_DEGREE:
        raise ValueError(f"bad factor: {cross_density!r} / {segmentation!r}")
    rng = random.Random(seed)
    cves = _cve_pool()
    synthetic = not cves

    def cve() -> str:
        return rng.choice(cves) if cves else f"CVE-0000-{rng.randrange(10**5)}"

    n_entries, n_targets = ENTRY_TARGET.get(n, (max(2, n // 100), max(2, n // 200)))
    n_onprem = int(round(n * ONPREM_SHARE))
    n_hosts = max(n_entries + 3, n_onprem // 2)
    n_cloud = max(6, n - 2 * n_hosts)
    n_roles, n_res = max(2, int(n_cloud * 0.4)), max(2, int(n_cloud * 0.4))
    n_inst = max(1, n_cloud - n_roles - n_res)

    hosts = [f"h{i:03d}" for i in range(n_hosts - 1)] + ["dc01"]
    zmap, allow = _zones(hosts, segmentation, rng)
    roles = [(f"role/r{i:02d}", "assume") for i in range(n_roles)]
    res = [(f"s3://d{i:02d}", "read") for i in range(n_res)]
    inst = [(f"i-{i:02d}", "instance") for i in range(n_inst)]

    G = new_graph(seed, n_requested=n, cross_density=cross_density,
                  segmentation=segmentation, synthetic_cves=synthetic,
                  onprem_share=ONPREM_SHARE, cve_pool_size=len(cves),
                  epss_snapshot=_snapshot())

    # --- on-prem: privilege escalation, then lateral movement
    for h in hosts:
        add_edge(G, (h, "user"), (h, "root"), kind="cve", ref=cve(), domain="onprem")

    deg = LATERAL_DEGREE[segmentation]
    by_zone: dict[str, list[str]] = {}
    for h, z in zmap.items():
        by_zone.setdefault(z, []).append(h)
    for h in hosts:
        pool = [o for z in allow[zmap[h]] for o in by_zone.get(z, []) if o != h]
        for tgt in rng.sample(pool, min(deg, len(pool))):
            roll = rng.random()
            if roll < 0.5:
                k, ref = "cve", cve()
            elif roll < 0.8:
                k, ref = "misconfig", rng.choice(MISCONFIG_LATERAL)
            else:  # same-zone reachability is a fact, not an exploit
                k, ref = "deterministic", rng.choice(STRUCTURAL_LATERAL)
            add_edge(G, (h, "root"), (tgt, "user"), kind=k, ref=ref, domain="onprem")

    # Segmented networks are not disconnected networks: each zone has one host
    # allowed to reach the next zone (a jump host / management path). Without
    # it, micro-segmentation only becomes reachable through repair edges, which
    # is the repair covering for a generator that models segmentation wrongly.
    for z, allowed in allow.items():
        src_hosts = by_zone.get(z, [])
        for z2 in allowed:
            if z2 == z or not src_hosts or not by_zone.get(z2):
                continue
            jump, land = src_hosts[0], by_zone[z2][0]
            if jump != land and not G.has_edge((jump, "root"), (land, "user")):
                add_edge(G, (jump, "root"), (land, "user"), kind="deterministic",
                         ref="sg-open-mgmt-port", domain="onprem")

    # --- cloud: assume-role chain, instance credentials, resource access
    for i, r in enumerate(roles):
        if i:
            add_edge(G, roles[i - 1], r, kind="deterministic",
                     ref="iam-assume-role", domain="cloud")
    for i in inst:
        add_edge(G, i, rng.choice(roles), kind="deterministic",
                 ref="imds-instance-role", domain="cloud")
    for r_ in res:
        src = rng.choice(roles)
        roll = rng.random()
        if roll < 0.6:
            add_edge(G, src, r_, kind="deterministic", ref="iam-policy-allows",
                     domain="cloud")
        else:
            add_edge(G, src, r_, kind="misconfig", ref=rng.choice(MISCONFIG_CLOUD),
                     domain="cloud")
    for r in roles:  # a few lateral role hops beyond the chain
        if rng.random() < 0.3:
            other = rng.choice(roles)
            if other != r and not G.has_edge(r, other):
                add_edge(G, r, other, kind="misconfig",
                         ref=rng.choice(MISCONFIG_CLOUD), domain="cloud")

    # --- cross-domain: the point of the whole model
    n_cross = max(2, CROSS_BASE[cross_density] * math.ceil(n / 100))
    for i in range(n_cross):
        ref, kind = CROSS_CLASSES[i % len(CROSS_CLASSES)]
        h = rng.choice(hosts)
        if ref == "ssrf-imdsv1-token":
            u, v = (h, "user"), rng.choice(inst)
        elif ref == "vpn-dx-to-private-subnet":
            u, v = (h, "root"), (rng.choice(hosts), "user")
            if u == v:
                continue
        else:
            u, v = (h, "root"), rng.choice(roles)
        add_edge(G, u, v, kind=kind, ref=ref, domain="cross")

    # --- entries and targets (counts locked above, see ENTRY_TARGET)
    entry_zone = "dmz" if segmentation == "3tier" else zmap[hosts[0]]
    cand = [h for h in hosts if zmap[h] == entry_zone and h != "dc01"] or hosts[:-1]
    entries = [(h, "user") for h in cand[:n_entries]]
    while len(entries) < n_entries:                      # small graphs
        entries.append((hosts[len(entries)], "user"))
    targets = [("dc01", "root")] + res[-(n_targets - 1):]
    for e in entries:
        G.nodes[e]["entry"] = True
    for t in targets:
        G.nodes[t]["target"] = True
    G.graph.update(n_entries=len(entries), n_targets=len(targets))

    _repair(G, entries, targets, hosts, roles, zmap, allow, rng, cve)
    return G


def _repair(G, entries, targets, hosts, roles, zmap, allow, rng, cve):
    """Add the fewest policy-legal edges that make every target reachable from
    every entry. Repair edges carry a real kind/ref like any other edge -- a
    ref='repair' would leak a synthetic class into the provenance table."""
    added = 0
    for t in targets:
        for e in entries:
            while not nx.has_path(G, e, t):
                reach = nx.descendants(G, e) | {e}
                co = nx.ancestors(G, t) | {t}
                src = _pick_root(reach, rng)
                if t[0].startswith("s3://") or t in roles:
                    dst = next((r for r in roles if r in co), None)
                    if src and dst:
                        add_edge(G, src, dst, kind="misconfig",
                                 ref="aws-key-on-host", domain="cross")
                        added += 1
                        continue
                dst_hosts = [h for h in hosts if (h, "user") in co
                             and zmap[h] in allow.get(zmap[src[0]], [])] if src else []
                if src and dst_hosts:
                    add_edge(G, src, (rng.choice(dst_hosts), "user"), kind="cve",
                             ref=cve(), domain="onprem")
                    added += 1
                    continue
                # last resort: a VPN/Direct Connect link, which is legal
                # regardless of on-prem segmentation
                dst2 = next((x for x in sorted(co) if x != e), None)
                if src is None or dst2 is None:
                    raise RuntimeError(f"cannot repair {e} -> {t}")
                add_edge(G, src, dst2, kind="deterministic",
                         ref="vpn-dx-to-private-subnet", domain="cross")
                added += 1
    G.graph["n_repair_edges"] = added


def _pick_root(reach, rng):
    """A node the attacker can already reach, preferring host root (the state
    from which lateral and cross-domain moves are legal)."""
    roots = sorted(x for x in reach if x[1] == "root")
    if roots:
        return rng.choice(roots)
    other = sorted(reach)
    return rng.choice(other) if other else None
