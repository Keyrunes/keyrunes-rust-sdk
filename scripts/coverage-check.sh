#!/usr/bin/env bash
#
# Line-coverage gate.
#
# Writes `lcov.info` for whatever collects reports, prints the human summary,
# and fails when the total drops below the threshold.
#
# The total is read back out of the LCOV file rather than scraped from the
# summary table: LCOV's `LF`/`LH` records are line counts by definition, while
# the table's column order shifts with the llvm-cov version and with whether
# branch coverage was collected.
set -euo pipefail

readonly THRESHOLD="${COVERAGE_THRESHOLD:-90}"
readonly REPORT="lcov.info"

cargo llvm-cov --all-features --locked --lcov --output-path "$REPORT"
cargo llvm-cov --all-features --locked --summary-only

coverage=$(awk -F: '
    /^LF:/ { found += $2 }
    /^LH:/ { hit   += $2 }
    END {
        if (found == 0) { exit 1 }
        printf "%.2f", 100 * hit / found
    }
' "$REPORT") || {
    echo "No lines were instrumented; $REPORT carries no coverage to check." >&2
    exit 1
}

echo "Line coverage: ${coverage}% (threshold ${THRESHOLD}%)"

if awk -v c="$coverage" -v t="$THRESHOLD" 'BEGIN { exit !(c + 0 < t + 0) }'; then
    echo "Coverage is below ${THRESHOLD}%." >&2
    exit 1
fi

echo "Coverage is at or above ${THRESHOLD}%."
