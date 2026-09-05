#!/usr/bin/env bash
#
# Mutation testing.
#
# Coverage says which lines ran; this says whether anything would have noticed
# had they done the wrong thing. cargo-mutants rewrites one expression at a
# time and reruns the suite: a surviving mutant is a line no assertion
# constrains. Shared settings live in `.cargo/mutants.toml`.
#
# `mutagen` is the better-known name for this in Rust but is unmaintained and
# nightly-only; cargo-mutants is its de-facto successor and runs on stable.
#
# Two scopes, because the framework middleware compiles only with its feature
# enabled and pulls the entire framework in with it:
#
#   core        the library proper, on default features (the pre-commit gate)
#   middleware  the axum/actix/rocket/loco adapters, on all features
#   all         both in one pass
set -euo pipefail

if ! command -v cargo-mutants >/dev/null 2>&1; then
    echo "cargo-mutants is not installed. Run: cargo install cargo-mutants --locked" >&2
    exit 1
fi

# Each job gets its own copy of the tree and its own target directory, so the
# useful number is bounded by disk rather than by cores.
JOBS="${MUTANTS_JOBS:-4}"

scope="${1:-core}"
shift || true

case "$scope" in
    core)
        exec cargo mutants --jobs "$JOBS" --exclude 'src/middleware/**' "$@"
        ;;
    middleware)
        exec cargo mutants --jobs "$JOBS" --all-features --file 'src/middleware/**' "$@"
        ;;
    all)
        exec cargo mutants --jobs "$JOBS" --all-features "$@"
        ;;
    *)
        echo "Unknown scope '$scope'. Use: core | middleware | all" >&2
        exit 64
        ;;
esac
