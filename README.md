# attack-path-choke-point

Choke point analysis of attack paths on hybrid (on-prem + cloud) infrastructure.

Independent study project for 06016421 Information Technology Infrastructure Security, IT KMITL. Advisor: Asst. Prof. Dr. Sumet Prabhavat. The full report (in Thai) is in [`docs/pdf/ITIS2026_Full_Report.pdf`](docs/pdf/ITIS2026_Full_Report.pdf).

## What it does

An attack graph has nodes of the form `(resource, privilege)` and edges for the three ways an attacker can move: a CVE, a misconfiguration, or a deterministic step (for example, a network path that is simply open). Every edge carries a domain (`onprem`, `cloud` or `cross`) and a success probability `p`.

On that graph the code answers one question: which nodes should a defender fix first? It computes the answer in two ways and compares them:

- **Dominator-based choke points.** Nodes that lie on every path from an entry to a target. Purely structural, ignores probabilities.
- **Weighted node min-cut.** The cheapest set of nodes whose removal disconnects every entry from every target, using edge probabilities as weights.

The weights come from one of four models: EPSS scores, a CVSS-to-EPSS fit, uniform, or random. The code also measures how stable the resulting ranking is when the weights are noisy or when edges are missing.

## Main results

Numbers from 216 generated hybrid graphs and the lab graph; see the report for the method and caveats.

- With EPSS weights, the min-cut matches the dominator set in 72% of comparable cases. With CVSS or uniform weights it matches in 100%. The structural and the empirical view can disagree.
- The CVSS-to-EPSS fit is weak: R² is 0.219 on the logit scale, and the error is largest on the edges most likely to be exploited.
- Rankings survive noisy weights (Jaccard@5 is 0.912 at 8 times the measured noise) but not missing edges (0.493 after dropping only 5%).
- The same pipeline runs unchanged on a real lab graph built from Terraform, LocalStack, Cartography, Neo4j and a Docker on-prem network.

## Layout

| Path | Contents |
| --- | --- |
| `attackpath/` | graph schema and validation, graph generator, weight models, choke point analysis, robustness metrics |
| `experiments/` | experiment runner (`run.py`), fit-error experiment (`exp6_fit_error.py`), summary tables and plots (`analyze.py`) |
| `scripts/` | EPSS/NVD download, CVSS-to-EPSS fit, rubric checks, report figures, `check_claims.py` |
| `lab/` | Terraform, LocalStack, on-prem Docker topology and the Neo4j exporter; see [`lab/README.md`](lab/README.md) |
| `tests/` | pytest suite, including a brute-force check of the dominator code on random graphs |
| `results/` | CSV output of the experiments |
| `docs/` | report sources (`docs/report/`), built PDF, misconfiguration rubric |

## Running it

Requires Python 3.13 and [uv](https://docs.astral.sh/uv/).

```bash
uv sync
uv run pytest -q                                   # tests

uv run python scripts/pull_data.py                 # EPSS + NVD, cached in data/raw/
uv run --group fit scripts/fit_weights.py          # CVSS -> EPSS fit
uv run python experiments/run.py --jobs 8          # full grid, about 30 minutes
uv run python -m experiments.exp6_fit_error        # fit-error experiment
uv run --group report experiments/analyze.py       # tables and plots
uv run python scripts/check_claims.py              # numbers in the report vs. results
```

`experiments/run.py` refuses to overwrite existing `results/exp*.csv`; pass `--force` to start over. The `data/` directory is not tracked, so the first step downloads it again.

The lab needs Docker and Terraform. Steps are in [`lab/README.md`](lab/README.md).

## Building the report

```bash
cd docs/report && sh build.sh
```

Needs [tectonic](https://tectonic-typesetting.github.io/) and uv. The output is copied to `docs/pdf/ITIS2026_Full_Report.pdf`. The body font is TH Sarabun New, bundled under `docs/report/fonts/`.

## Limitations

- No AND-nodes: an edge is usable if its source is reachable, never "only if two things hold".
- The lab uses LocalStack instead of real AWS (the AWS Academy account blocks IAM creation), `nmap` instead of Nessus, and Docker networking instead of GNS3. The lab graph therefore has no CVE edges.
- The generated graphs are chain-like and have not been checked against real network topologies.

## License

MIT, see [`LICENSE`](LICENSE).
