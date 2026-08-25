#!/usr/bin/env python3
"""Pull EPSS scores + NVD CVSS v3.1 vectors, cache to data/raw/, emit joined CSV.

Feeds the objective-2 weighting fit (CVSS metrics -> EPSS). Resumable: every
NVD page is cached on disk and never refetched.

Usage:  python3 scripts/pull_data.py [--stride N] [--api-key KEY]

Stdlib only, deliberately -- the fit step can bring in numpy/scipy.
"""
import argparse
import csv
import gzip
import json
import os
import sys
import time
import urllib.error
import urllib.request

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
RAW = os.path.join(ROOT, "data", "raw")
NVD_DIR = os.path.join(RAW, "nvd")
FIT = os.path.join(ROOT, "data", "fit")

EPSS_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
PAGE = 2000
# NVD public rate limit: 5 req / 30s without a key, 50 req / 30s with one.
DELAY_NOKEY, DELAY_KEY = 6.5, 0.8


def log(*a):
    print(*a, file=sys.stderr, flush=True)


def fetch(url, key=None, tries=4):
    req = urllib.request.Request(url, headers={"User-Agent": "ITIS2026-research/0.1"})
    if key:
        req.add_header("apiKey", key)
    for attempt in range(tries):
        try:
            with urllib.request.urlopen(req, timeout=90) as r:
                return r.read()
        except (urllib.error.URLError, TimeoutError) as e:
            if attempt == tries - 1:
                raise
            back = 5 * (2**attempt)
            log(f"  retry {attempt+1}/{tries-1} after {back}s ({e})")
            time.sleep(back)


def pull_epss():
    """Download today's EPSS snapshot. Returns {cve: (epss, percentile)}."""
    os.makedirs(RAW, exist_ok=True)
    dated = os.path.join(RAW, f"epss_scores-{time.strftime('%Y-%m-%d')}.csv.gz")
    existing = sorted(f for f in os.listdir(RAW) if f.startswith("epss_scores-"))
    path = os.path.join(RAW, existing[-1]) if existing else dated
    if not os.path.exists(path):
        log(f"EPSS -> {os.path.basename(path)}")
        with open(path, "wb") as fh:
            fh.write(fetch(EPSS_URL))
    else:
        log(f"EPSS cached: {os.path.basename(path)}")

    scores = {}
    with gzip.open(path, "rt") as fh:
        for row in csv.reader(fh):
            # file starts with a '#model_version...' comment line, then a header
            if not row or row[0].startswith("#") or row[0] == "cve":
                continue
            scores[row[0]] = (float(row[1]), float(row[2]))
    log(f"EPSS rows: {len(scores)}")
    return scores


def load_cached():
    """Join whatever pages are already on disk. Lets the fit get an early read
    on R^2 while the full pull is still running."""
    rows = []
    files = sorted(f for f in os.listdir(NVD_DIR) if f.endswith(".json.gz"))
    for f in files:
        page = int(f.split("_")[1].split(".")[0])
        for r in extract(json.load(open(os.path.join(NVD_DIR, f), "rb")
                                   and gzip.open(os.path.join(NVD_DIR, f), "rt"))):
            r["nvd_page"] = page
            rows.append(r)
    log(f"cached pages: {len(files)}  CVEs with a CVSS v3.x vector: {len(rows)}")
    return rows


def pull_nvd(stride, key, start_index=0):
    """Systematic sample of NVD pages. Every page cached; safe to re-run."""
    os.makedirs(NVD_DIR, exist_ok=True)
    delay = DELAY_KEY if key else DELAY_NOKEY

    head = json.loads(fetch(f"{NVD_URL}?resultsPerPage=1&startIndex=0", key))
    total = head["totalResults"]
    n_pages = -(-total // PAGE)
    # NVD orders by CVE ID ascending, so startIndex is effectively a year axis.
    # CVSS v3 scoring only became systematic in 2016; sampling below that index
    # burns requests on pages that are ~99% CVSS v2 only.
    first = start_index // PAGE
    pages = list(range(first, n_pages, stride))
    log(f"NVD total={total} pages={n_pages} sampling {len(pages)} "
        f"from page {first} (stride={stride})")

    rows = []
    for i, p in enumerate(pages):
        idx = p * PAGE
        cache = os.path.join(NVD_DIR, f"page_{idx:07d}.json.gz")
        if os.path.exists(cache):
            with gzip.open(cache, "rt") as fh:
                data = json.load(fh)
        else:
            log(f"  [{i+1}/{len(pages)}] startIndex={idx}")
            raw = fetch(f"{NVD_URL}?resultsPerPage={PAGE}&startIndex={idx}", key)
            data = json.loads(raw)
            with gzip.open(cache, "wt") as fh:
                json.dump(data, fh)
            time.sleep(delay)
        got = extract(data)
        for r in got:
            r["nvd_page"] = idx
        rows.extend(got)
        log(f"      v3 yield {len(got)}/{len(data.get('vulnerabilities', []))}")
    log(f"NVD CVEs with a CVSS v3.x vector: {len(rows)}")
    return rows


def extract(page):
    """cveId + primary CVSS v3.x vector. v3.1 preferred, v3.0 accepted."""
    out = []
    for item in page.get("vulnerabilities", []):
        cve = item["cve"]
        if cve.get("vulnStatus") == "Rejected":
            continue
        metrics = cve.get("metrics", {})
        entries = metrics.get("cvssMetricV31") or metrics.get("cvssMetricV30") or []
        if not entries:
            continue
        # Primary = the NVD's own scoring; fall back to whatever is first.
        m = next((e for e in entries if e.get("type") == "Primary"), entries[0])
        d = m["cvssData"]
        out.append(
            {
                "cve": cve["id"],
                "scorer": m.get("type", ""),
                "source": m.get("source", ""),
                "published": cve.get("published", "")[:10],
                "cvss_version": d.get("version", ""),
                "vector": d.get("vectorString", ""),
                "base_score": d.get("baseScore", ""),
                "AV": d.get("attackVector", ""),
                "AC": d.get("attackComplexity", ""),
                "PR": d.get("privilegesRequired", ""),
                "UI": d.get("userInteraction", ""),
                "S": d.get("scope", ""),
                "C": d.get("confidentialityImpact", ""),
                "I": d.get("integrityImpact", ""),
                "A": d.get("availabilityImpact", ""),
            }
        )
    return out


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--stride", type=int, default=3,
                    help="take every Nth NVD page (1 = full pull)")
    ap.add_argument("--api-key", default=os.environ.get("NVD_API_KEY"))
    ap.add_argument("--start-index", type=int, default=72000,
                    help="skip the pre-CVSS-v3 head of the index (~2016 boundary)")
    ap.add_argument("--join-only", action="store_true",
                    help="skip fetching, join only the pages already cached")
    ap.add_argument("--out", default="cvss_epss_joined.csv")
    args = ap.parse_args()

    epss = pull_epss()
    nvd = load_cached() if args.join_only else pull_nvd(args.stride, args.api_key, args.start_index)

    os.makedirs(FIT, exist_ok=True)
    out = os.path.join(FIT, args.out)
    cols = ["cve", "published", "nvd_page", "scorer", "source", "cvss_version", "vector", "base_score",
            "AV", "AC", "PR", "UI", "S", "C", "I", "A", "epss", "percentile"]
    matched = 0
    with open(out, "w", newline="") as fh:
        w = csv.DictWriter(fh, fieldnames=cols)
        w.writeheader()
        for r in nvd:
            hit = epss.get(r["cve"])
            if hit is None:
                continue
            r["epss"], r["percentile"] = hit
            w.writerow(r)
            matched += 1
    log(f"joined rows: {matched} -> {out}")
    if matched < 1000:
        log("WARNING: thin join, fit will be unreliable. Lower --stride.")


if __name__ == "__main__":
    main()
