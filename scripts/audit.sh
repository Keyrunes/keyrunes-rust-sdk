#!/usr/bin/env bash
#
# Security audit.
#
# `.cargo/audit.toml` silences exactly one advisory, RUSTSEC-2026-0258, because
# two optional dependencies pin the h2 0.3 line, which has no fixed release.
# cargo-audit ignores by advisory ID and cannot be told "only for 0.3", so that
# entry would equally hide a regression on the 0.4 line — which *is* fixed and
# which this crate actually uses through reqwest. The floor below closes that
# gap: the exception stays as narrow as it was argued to be.
set -euo pipefail

readonly H2_FLOOR="0.4.16"

lockfile_versions_of() {
    awk -v crate="name = \"$1\"" '
        $0 == crate { getline; gsub(/version = |"/, ""); print }
    ' Cargo.lock
}

for version in $(lockfile_versions_of h2); do
    case "$version" in
        0.4.*)
            lowest=$(printf '%s\n%s\n' "$version" "$H2_FLOOR" | sort -V | head -1)
            if [ "$lowest" != "$H2_FLOOR" ]; then
                echo "h2 $version is below the $H2_FLOOR floor that RUSTSEC-2026-0258 requires." >&2
                echo "The ignore in .cargo/audit.toml covers the unfixable 0.3 line only." >&2
                echo "Run: cargo update -p h2@$version" >&2
                exit 1
            fi
            ;;
    esac
done

exec cargo audit "$@"
