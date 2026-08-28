# /// script
# requires-python = ">=3.11"
# dependencies = ["numpy", "pandas"]
# ///
"""Check every assigned vector in the misconfig rubric against real CVE data.

The rubric assigns a CVSS vector to each misconfig class by judgement. This asks
the data two questions about each assignment:

  1. Is the vector inside the fit's support at all? A cell with no real CVEs
     means the fit is extrapolating, and its p(e) for that class is invented.
  2. What EPSS do real CVEs in that exact cell actually have? That is the
     empirical check on the assignment -- rubric row measured, not asserted.

Turns each rubric assignment from asserted into evidenced. Run after the pull.

Usage:  uv run scripts/calibrate_rubric.py [joined.csv]
"""
import os
import re
import sys

import numpy as np
import pandas as pd

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RUBRIC = os.path.join(ROOT, "docs", os.environ.get(
    "RUBRIC_FILE", "MISCONFIG_RUBRIC.md"))
FIT = os.path.join(ROOT, "data", "fit")
METRICS = ["AV", "AC", "PR", "UI", "S", "C", "I", "A"]
ABBR = {"NETWORK": "N", "ADJACENT_NETWORK": "A", "LOCAL": "L", "PHYSICAL": "P",
        "LOW": "L", "HIGH": "H", "NONE": "N", "REQUIRED": "R",
        "UNCHANGED": "U", "CHANGED": "C"}
VEC_RE = re.compile(
    r"AV:([NALP])/AC:([LH])/PR:([NLH])/UI:([NR])/S:([UC])/C:([NLH])/I:([NLH])/A:([NLH])")


def parse_rubric(path):
    """One row per table line that carries a full v3.1 vector.

    Handles both rubric formats. The slug version carries an explicit p_source
    column; the older MC-* draft does not, so p_source is inferred from the
    rubric's own rule -- all-N impact means the edge only grants reachability,
    which is outside the fit's support and must be deterministic.
    """
    rows = []
    for line in open(path):
        if not line.startswith("|"):
            continue
        m = VEC_RE.search(line)
        if not m:
            continue
        cells = [c.strip() for c in line.strip().strip("|").split("|")]
        rid = cells[0].strip("`") if cells else "?"
        src = next((c.strip("`") for c in cells
                    if c.strip("`") in ("fitted", "deterministic", "expert")), "?")
        conf = next((c for c in cells if c in ("high", "med", "low")), "?")
        if src == "?":
            src = "deterministic" if m.group(6) == m.group(7) == m.group(8) == "N" \
                  else "fitted"
        rows.append({"rubric_id": rid, "p_source": src, "conf": conf,
                     "vector": m.group(0),
                     **dict(zip(METRICS, m.groups()))})
    return pd.DataFrame(rows)


def check_drift(rub):
    """misconfig_vectors.json is generated from the rubric. It has already
    drifted out of sync with it once before, and it lives in gitignored
    data/, so nothing else catches a mismatch. Fail loudly."""
    gen = os.path.join(FIT, "misconfig_vectors.json")
    if not os.path.exists(gen):
        return
    import json
    vecs = json.load(open(gen))
    by_id = dict(zip(rub.rubric_id, rub.vector))
    print(f"\n--- drift check: {os.path.basename(gen)} ({len(vecs)} keys) "
          f"vs rubric on disk ({len(by_id)} rows) ---")

    orphan = {k: v for k, v in vecs.items() if k not in by_id}
    missing = {k: v for k, v in by_id.items()
               if k not in vecs and rub.set_index("rubric_id").p_source[k] == "fitted"}
    disagree = {k: (vecs[k], by_id[k]) for k in vecs if k in by_id and vecs[k] != by_id[k]}

    # aliases: two slugs, one vector -- one of them is probably dead weight
    rev = {}
    for k, v in vecs.items():
        rev.setdefault(v, []).append(k)
    alias = {v: ks for v, ks in rev.items() if len(ks) > 1}

    if orphan:
        print(f"  ORPHAN ({len(orphan)}) in JSON but not in the rubric on disk "
              f"-- no recorded justification exists for these:")
        for k, v in sorted(orphan.items()):
            print(f"    {k:34s} {v}")
    if missing:
        print(f"  MISSING ({len(missing)}) fitted rubric rows absent from the JSON:")
        for k, v in sorted(missing.items()):
            print(f"    {k:34s} {v}")
    if disagree:
        print(f"  DISAGREE ({len(disagree)}) same slug, different vector:")
        for k, (a, b) in sorted(disagree.items()):
            print(f"    {k:34s} json={a}  rubric={b}")
    if alias:
        print(f"  ALIAS ({len(alias)} vectors carry >1 slug) -- if gen.py emits "
              f"one and the rubric documents the other, one class is undocumented:")
        for v, ks in sorted(alias.items()):
            print(f"    {v}  <- {', '.join(sorted(ks))}")
    if not (orphan or missing or disagree or alias):
        print("  clean -- JSON matches the rubric on disk")


def main():
    joined = next((a for a in sys.argv[1:] if a.endswith(".csv")),
                  "cvss_epss_joined.csv")
    path = os.path.join(FIT, joined)
    if not os.path.exists(path):
        sys.exit(f"missing {path} -- run scripts/pull_data.py first")

    df = pd.read_csv(path).dropna(subset=METRICS + ["epss", "published"])
    df = df[df.published.astype(str) >= "2016-01-01"]
    for m in METRICS:
        df[m] = df[m].map(lambda v: ABBR.get(v, v))

    rub = parse_rubric(RUBRIC)
    print(f"rubric rows with a vector: {len(rub)}   CVE reference pool: {len(df)}")
    check_drift(rub)

    # the rubric's own rule: all-N impact => reachability only => outside the
    # fit's support. Check whether real CVE data actually backs that.
    alln = df[(df.C == "N") & (df.I == "N") & (df.A == "N")]
    print(f"published CVEs with C:N/I:N/A:N in the pool: {len(alln)} "
          f"({100*len(alln)/len(df):.2f}%) "
          f"-- rubric routes these to p=1.0/deterministic instead of the fit")

    out = []
    for r in rub.itertuples():
        sel = df
        for m in METRICS:
            sel = sel[sel[m] == getattr(r, m)]
        row = {"rubric_id": r.rubric_id, "p_source": r.p_source, "conf": r.conf,
               "vector": r.vector, "n_cve": len(sel)}
        if len(sel):
            row |= {"epss_p10": float(sel.epss.quantile(.10)),
                    "epss_median": float(sel.epss.median()),
                    "epss_p90": float(sel.epss.quantile(.90)),
                    "epss_max": float(sel.epss.max())}
        out.append(row)
    res = pd.DataFrame(out).sort_values("n_cve", ascending=False)
    pd.set_option("display.width", 250)
    print("\n" + res.to_string(index=False))
    res.to_csv(os.path.join(FIT, "rubric_calibration.csv"), index=False)

    fitted = res[res.p_source == "fitted"]
    thin = fitted[fitted.n_cve < 10]
    print(f"\nfitted rows: {len(fitted)}   with >=10 real CVEs in cell: "
          f"{(fitted.n_cve >= 10).sum()}   THIN (<10): {len(thin)}")
    if len(thin):
        print("  thin cells -- fit is extrapolating, flag conf=low in the report:")
        for t in thin.itertuples():
            print(f"    {t.rubric_id:34s} n={t.n_cve:<4d} {t.vector}")
    det = res[res.p_source == "deterministic"]
    print(f"deterministic rows: {len(det)}  "
          f"(n_cve is expected to be ~0 -- that is the point, not a problem)")


if __name__ == "__main__":
    main()
