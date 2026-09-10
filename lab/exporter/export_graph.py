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
from attackpath import graph as G  # noqa: E402


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


def build_graph(session, seed: int) -> "G.nx.DiGraph":
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
    return g


def main() -> None:
    ap = argparse.ArgumentParser(description=__doc__)
    ap.add_argument("--neo4j-uri", default="bolt://localhost:7687")
    ap.add_argument("--neo4j-user", default="neo4j")
    ap.add_argument("--neo4j-password", required=True)
    ap.add_argument("--seed", type=int, default=1)
    ap.add_argument("--out-json", default="lab/lab_graph.json")
    ap.add_argument("--out-csv", default="lab/lab_graph.csv")
    args = ap.parse_args()

    driver = GraphDatabase.driver(args.neo4j_uri, auth=(args.neo4j_user, args.neo4j_password))
    with driver.session() as session:
        g = build_graph(session, args.seed)
    driver.close()

    G.validate_structure(g)
    G.save_json(g, args.out_json)
    G.to_csv(g, args.out_csv)
    print(f"nodes={g.number_of_nodes()} edges={g.number_of_edges()} "
          f"-> {args.out_json}, {args.out_csv}")


if __name__ == "__main__":
    main()
