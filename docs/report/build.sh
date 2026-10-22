#!/bin/sh
# Build the report PDF -> docs/report/build/pdf/main.pdf, then copy it to
# docs/pdf/ITIS2026_Full_Report.pdf (the submission copy).
# Needs: tectonic (self-contained XeTeX; first run downloads LaTeX packages) and uv.
# Thai word breaks are inserted at build time by thai_zwsp.py (see its docstring).
set -e
cd "$(dirname "$0")"
T="${TECTONIC:-$(command -v tectonic || echo "$HOME/Utilities/tectonic-dl/bin/tectonic")}"
uv run --no-project --with pythainlp python -I thai_zwsp.py
cd build/src
mkdir -p ../pdf
"$T" -X compile --keep-logs --outdir ../pdf main.tex
cd ../..
mkdir -p ../pdf
cp build/pdf/main.pdf ../pdf/ITIS2026_Full_Report.pdf
echo "-> docs/pdf/ITIS2026_Full_Report.pdf"
