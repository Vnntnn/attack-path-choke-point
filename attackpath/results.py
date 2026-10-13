"""One locked row schema for every experiment CSV.

Fixed up front on purpose: a missing `seed` or `n_entries` column is only
discovered after 540 graphs have been generated, and then the run is worthless.
Every simulated graph must carry a fixed seed, recorded on every row, so it
can be regenerated later.

Deliberately minimal: a csv.DictWriter with a required prefix, not a results
framework.
"""
from __future__ import annotations

import csv
import os
import subprocess
import time

# Columns every row of every experiment must carry.
COMMON = ["exp", "graph_id", "seed", "n_requested", "n_nodes", "n_edges",
          "n_entries", "n_targets", "cross_density", "segmentation",
          "weight_model", "synthetic_cves", "n_repair", "repair_frac",
          "cve_pool_size", "epss_snapshot", "git_rev", "ts"]


CODE_PATHS = ["attackpath", "experiments", "scripts", "pyproject.toml", "uv.lock"]


def git_rev() -> str:
    """HEAD, plus '+dirty' when the code that produces results has uncommitted
    changes (results/ itself is excluded: every run modifies it). Without this a
    row claims a commit whose code never produced it."""
    try:
        rev = subprocess.check_output(["git", "rev-parse", "--short", "HEAD"],
                                      text=True).strip()
        dirty = subprocess.check_output(
            ["git", "status", "--porcelain", "--", *CODE_PATHS], text=True).strip()
        return rev + ("+dirty" if dirty else "")
    except Exception:
        return "unknown"


def graph_row(G) -> dict:
    """The common prefix, read straight off the graph's own metadata."""
    g = G.graph
    return {"seed": g.get("seed"), "n_requested": g.get("n_requested"),
            "n_nodes": G.number_of_nodes(), "n_edges": G.number_of_edges(),
            "n_entries": g.get("n_entries"), "n_targets": g.get("n_targets"),
            "cross_density": g.get("cross_density"),
            "segmentation": g.get("segmentation"),
            "weight_model": g.get("weight_model"),
            "synthetic_cves": bool(g.get("synthetic_cves", False)),
            # a repaired graph is not a draw from the declared distribution;
            # a reader needs to know what share of the corpus that is
            "n_repair": g.get("n_repair_edges"),
            "repair_frac": (round(g["n_repair_edges"] / G.number_of_edges(), 4)
                            if g.get("n_repair_edges") is not None else None),
            "cve_pool_size": g.get("cve_pool_size"),
            "epss_snapshot": g.get("epss_snapshot")}


class Writer:
    """Appends rows to results/<exp>.csv, header written once."""

    def __init__(self, exp: str, extra: list[str], outdir="results"):
        os.makedirs(outdir, exist_ok=True)
        self.exp, self.path = exp, os.path.join(outdir, f"{exp}.csv")
        self.cols = COMMON + extra
        self.rev = git_rev()
        new = not os.path.exists(self.path)
        self.fh = open(self.path, "a", newline="")
        self.w = csv.DictWriter(self.fh, fieldnames=self.cols, extrasaction="raise")
        if new:
            self.w.writeheader()

    def write(self, **row):
        row.setdefault("exp", self.exp)
        row["git_rev"], row["ts"] = self.rev, time.strftime("%Y-%m-%dT%H:%M:%S")
        missing = [c for c in self.cols if c not in row]
        if missing:
            raise ValueError(f"{self.exp}: row missing {missing}")
        self.w.writerow(row)
        self.fh.flush()

    def close(self):
        self.fh.close()

    def __enter__(self):
        return self

    def __exit__(self, *exc):
        self.close()
