#!/usr/bin/env python3
"""Generate data/fit/misconfig_vectors.json from the misconfig rubric document.

The rubric is the single source of truth. Hand-maintaining the JSON
alongside it drifts the moment someone edits a vector in one place only --
that already happened once. Run this after editing the rubric.

    uv run python scripts/build_vectors.py

Only `p_source=fitted` rows are emitted. Deterministic rows carry all-N impact
vectors that sit outside the fit's support (every published CVE has at least one
non-N impact), so feeding one to the fit yields base score 0 -> p=0 -> w=inf.
Leaving them out makes a mislabelled edge fall through weights.py's loud
`expert` fallback instead of silently producing an infinite-weight edge.
"""
import json
import pathlib
import re

ROOT = pathlib.Path(__file__).resolve().parent.parent
RUBRIC = ROOT / "docs" / "MISCONFIG_RUBRIC.md"
OUT_VEC = ROOT / "data" / "fit" / "misconfig_vectors.json"
OUT_CONF = ROOT / "data" / "fit" / "misconfig_confidence.json"

VECTOR_RE = re.compile(
    r"`(AV:[NALP]/AC:[LH]/PR:[NLH]/UI:[NR]/S:[UC]/C:[NLH]/I:[NLH]/A:[NLH])`"
)
SOURCE_RE = re.compile(r"`(fitted|deterministic|epss|expert)`")
ID_RE = re.compile(r"`([a-z0-9-]+)`")

# gen.py uses the rubric's exact slugs, so no aliases are needed. Keep the map
# empty rather than deleting it: if a future generator drifts from the rubric
# again, this is where the mapping goes, and build_vectors fails loudly on a
# stale alias.
ALIASES: dict[str, str] = {}
# gen refs whose rubric row is deterministic -- these must be emitted by gen.py
# with kind="deterministic" (p=1.0) and never looked up here.
DETERMINISTIC_REFS = {
    "vpn-to-private-subnet": "vpn-dx-to-private-subnet",
    "ad-federation": "federated-identity-trust",
}


def parse(md):
    rows = {}
    for line in md.splitlines():
        if not line.startswith("|"):
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        if len(cells) < 5:
            continue
        rid = ID_RE.fullmatch(cells[0])
        vec = VECTOR_RE.search(cells[2])
        src = SOURCE_RE.search(cells[3])
        if not (rid and vec and src):
            continue
        rows[rid.group(1)] = (vec.group(1), src.group(1), cells[4])
    return rows


def main():
    rows = parse(RUBRIC.read_text())
    fitted = {k: v for k, (v, s, _) in rows.items() if s == "fitted"}
    conf = {k: c for k, (_, s, c) in rows.items() if s == "fitted"}

    for alias, target in ALIASES.items():
        if target not in fitted:
            raise SystemExit(f"alias {alias!r} points at missing rubric row {target!r}")
        fitted[alias] = fitted[target]
        conf[alias] = conf[target]

    for ref, target in DETERMINISTIC_REFS.items():
        if rows.get(target, (None, None, None))[1] != "deterministic":
            raise SystemExit(f"{target!r} is no longer deterministic; revisit {ref!r}")

    # data/ is gitignored, so these JSON files are the ONLY copy of the vectors
    # once the rubric drifts. Overwriting them from a rubric that failed to
    # parse silently sends every misconfig edge to the expert fallback, which
    # looks like a modelling choice rather than a wiped file. Refuse instead.
    previous = len(json.loads(OUT_VEC.read_text())) if OUT_VEC.exists() else 0
    if len(fitted) < previous or not fitted:
        raise SystemExit(
            f"refusing to shrink {OUT_VEC.name}: {previous} rows on disk, "
            f"{len(fitted)} parsed from "
            f"{RUBRIC.name}. Either the rubric lost rows or its table format changed. "
            f"Fix the rubric, or delete the JSON deliberately if the shrink is intended."
        )
    OUT_VEC.write_text(json.dumps(fitted, indent=2, sort_keys=True) + "\n")
    OUT_CONF.write_text(json.dumps(conf, indent=2, sort_keys=True) + "\n")
    print(f"{len(rows)} rubric rows -> {len(fitted)} fitted vectors")
    print(f"deterministic refs (gen.py must set kind='deterministic'): "
          f"{sorted(DETERMINISTIC_REFS)}")


def demo():
    """Self-check: parse the real rubric and assert the invariants."""
    rows = parse(RUBRIC.read_text())
    assert rows, "no rows parsed -- rubric table format changed"
    assert "aws-key-on-host" in rows, "primary cross-domain class missing"
    for rid, (vec, src, _) in rows.items():
        metrics = dict(p.split(":") for p in vec.split("/"))
        assert set(metrics) == set("AV AC PR UI S C I A".split()), rid
        impacts = {metrics["C"], metrics["I"], metrics["A"]}
        if src == "deterministic":
            assert impacts == {"N"}, f"{rid}: deterministic row must have all-N impact"
        else:
            assert impacts != {"N"}, f"{rid}: all-N impact is outside the fit's support"
    print(f"demo ok: {len(rows)} rows, impact/p_source invariant holds")


if __name__ == "__main__":
    import sys
    (demo if "--check" in sys.argv else main)()
