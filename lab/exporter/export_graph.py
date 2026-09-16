"""Cartography's Neo4j graph -> attackpath's edge-list schema (strict
rule: the analyzer never touches Neo4j, so this is the one place in the lab
phase that's allowed to import a Neo4j driver).

Every edge below is backed by a Cypher read against data Cartography actually
synced from LocalStack (see lab/README.md for the queries and what each one
returns) -- nothing here is invented structure. `p` / `p_source` / `p_input`
are deliberately left unset: attackpath.weights.assign() fills those in
exactly as it does for gen.py's synthetic graphs, so this graph goes through
the *same* pipeline.
"""
from __future__ import annotations

import argparse
import sys
from pathlib import Path

from neo4j import GraphDatabase

sys.path.insert(0, str(Path(__file__).resolve().parents[2]))
sys.path.insert(0, str(Path(__file__).resolve().parent))
from attackpath import graph as G  # noqa: E402
import onprem  # noqa: E402


def _fetch_s3_public_read(session) -> list[str]:
    q = """
    MATCH (b:AWSS3Bucket)-[:POLICY_STATEMENT]->(s:AWSS3PolicyStatement)
    WHERE s.effect = "Allow" AND s.principal = '"*"'
      AND any(a IN s.action WHERE a STARTS WITH "s3:Get")
    RETURN DISTINCT b.name AS bucket
    """
    return [r["bucket"] for r in session.run(q)]


def _fetch_open_mgmt_sgs(session) -> list[str]:
    q = """
    MATCH (sg:AWSEC2SecurityGroup)-[:MEMBER_OF_EC2_SECURITY_GROUP]-(rule:AWSIpRule)
          -[:MEMBER_OF_IP_RULE]-(rng:AWSIpRange)
    WHERE rng.range = "0.0.0.0/0"
      AND rule.fromport <= 22 AND rule.toport >= 22
      AND sg.name <> "default"
    RETURN DISTINCT sg.name AS sg_name
    """
    return [r["sg_name"] for r in session.run(q)]


def _fetch_cross_account_trusts(session) -> list[tuple[str, str, str]]:
    q = """
    MATCH (role:AWSRole)-[:TRUSTS_AWS_PRINCIPAL]->(src:AWSPrincipal)
    WHERE NOT src.arn CONTAINS $account_id
    OPTIONAL MATCH (role)-[:POLICY]-(pol:AWSPolicy)
    RETURN role.name AS role_name, src.arn AS trusted_arn,
           collect(pol.name) AS policies
    """
    return [(r["role_name"], r["trusted_arn"], r["policies"])
            for r in session.run(q, account_id="000000000000")]


def _fetch_access_key_owners(session) -> dict[str, str]:
    """accesskeyid -> IAM user name, for every access key Cartography's
    sync_user_access_keys independently discovered on the cloud side."""
    q = """
    MATCH (u:AWSUser)-[:AWS_ACCESS_KEY]-(k:AccountAccessKey)
    WHERE k.status = "Active"
    RETURN k.accesskeyid AS key_id, u.name AS user_name
    """
    return {r["key_id"]: r["user_name"] for r in session.run(q)}


def _add_onprem_chain(g: "G.nx.DiGraph", entry, session) -> None:
    """On-prem chain: internet -> dmz-host -> internal-host (flat network, no
    segmentation) -> cloud identity, added only if nmap confirms both hosts
    are actually reachable AND the access key id read off internal-host's
    filesystem matches one Cartography discovered independently on the
    cloud side. Two sources agreeing is the correlation; either one alone
    is not."""
    dmz_ip = onprem.docker_ip(onprem.DMZ_CONTAINER)
    internal_ip = onprem.docker_ip(onprem.INTERNAL_CONTAINER)
    open_ports = onprem.nmap_open_ports([dmz_ip, internal_ip])
    if 22 not in open_ports.get(dmz_ip, set()) or 22 not in open_ports.get(internal_ip, set()):
        raise RuntimeError(f"nmap did not find ssh open on both on-prem hosts: {open_ports}")

    leaked_key_id = onprem.read_leaked_access_key_id()
    cloud_keys = _fetch_access_key_owners(session)
    owner = cloud_keys.get(leaked_key_id)
    if owner is None:
        raise RuntimeError(
            f"key {leaked_key_id!r} read off {onprem.INTERNAL_CONTAINER} does not match any "
            f"AccountAccessKey Cartography discovered ({sorted(cloud_keys)}) -- no correlation, no edge"
        )

    dmz_node = (f"host:{onprem.DMZ_CONTAINER}", "anon")
    internal_node = (f"host:{onprem.INTERNAL_CONTAINER}", "anon")
    user_node = (f"user:{owner}", "admin")

    G.add_edge(g, entry, dmz_node,
                kind="deterministic", ref="internet-facing-host", domain="onprem")
    G.add_edge(g, dmz_node, internal_node,
                kind="deterministic", ref="flat-vlan-no-segmentation", domain="onprem")
    G.add_edge(g, internal_node, user_node,
                kind="misconfig", ref="aws-key-on-host", domain="cross")
    g.nodes[user_node]["target"] = True


def build_graph(session, seed: int, include_onprem: bool = True) -> "G.nx.DiGraph":
    g = G.new_graph(seed=seed, source="lab-localstack")
    entry = ("internet", "anon")

    for bucket in _fetch_s3_public_read(session):
        G.add_edge(g, entry, (f"s3://{bucket}", "read"),
                    kind="misconfig", ref="s3-public-read", domain="cloud")

    for sg_name in _fetch_open_mgmt_sgs(session):
        G.add_edge(g, entry, (f"net:{sg_name}", "reachable"),
                    kind="deterministic", ref="sg-open-mgmt-port", domain="cloud")

    target = None
    for role_name, trusted_arn, policies in _fetch_cross_account_trusts(session):
        attacker_seat = (f"aws:{trusted_arn.split(':')[4]}", "root")
        role_node = (f"role:{role_name}", "admin" if policies else "assumed")
        G.add_edge(g, entry, attacker_seat,
                    kind="deterministic", ref="attacker-controlled-account", domain="cloud")
        G.add_edge(g, attacker_seat, role_node,
                    kind="misconfig", ref="iam-trust-missing-external-id", domain="cross")
        target = role_node

    if target is None:
        raise RuntimeError("no cross-account trust edge found -- nothing to reach; "
                            "check terraform apply and cartography sync both ran")

    g.nodes[entry]["entry"] = True
    g.nodes[target]["target"] = True

    if include_onprem:
        _add_onprem_chain(g, entry, session)  # adds its own target node

    return g


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    ap.add_argument("--neo4j-user", default="neo4j")
    ap.add_argument("--neo4j-password", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out-json", default="lab/lab_graph.json")
    ap.add_argument("--out-csv", default="lab/lab_graph.csv")
    ap.add_argument("--skip-onprem", action="store_true",
                     help="cloud side alone, no lab/onprem containers required")
    args = ap.parse_args()

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    with driver.session() as session:
        g = build_graph(session, args.seed, include_onprem=not args.skip_onprem)
    driver.close()

    G.validate_structure(g)
    G.save_json(g, args.out_json)
    G.to_csv(g, args.out_csv)
    print(f"nodes={g.number_of_nodes()} edges={g.number_of_edges()} "
          f"-> {args.out_json}, {args.out_csv}")


if __name__ == "__main__":
    main()
