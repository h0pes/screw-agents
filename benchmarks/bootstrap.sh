#!/usr/bin/env bash
# Download external benchmark suites for agent evaluation.
# These are large repos and are gitignored (benchmarks/suites/).
#
# Usage: ./benchmarks/bootstrap.sh

set -euo pipefail

SUITES_DIR="$(dirname "$0")/suites"
mkdir -p "$SUITES_DIR"

echo "Downloading benchmark suites into $SUITES_DIR..."

# Primary benchmark: real-world CVEs, multi-language
if [ ! -d "$SUITES_DIR/reality-check" ]; then
  echo "Cloning flawgarden/reality-check..."
  git clone --depth 1 https://github.com/flawgarden/reality-check.git "$SUITES_DIR/reality-check"
else
  echo "reality-check already present, skipping."
fi

# Supplementary: enhanced OWASP Benchmark with mutations
if [ ! -d "$SUITES_DIR/BenchmarkJava-mutated" ]; then
  echo "Cloning flawgarden/BenchmarkJava-mutated..."
  git clone --depth 1 https://github.com/flawgarden/BenchmarkJava-mutated.git "$SUITES_DIR/BenchmarkJava-mutated"
else
  echo "BenchmarkJava-mutated already present, skipping."
fi

echo "Done. Suites available in $SUITES_DIR/"
