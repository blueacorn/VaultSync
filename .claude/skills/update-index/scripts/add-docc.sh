#!/usr/bin/env bash
# add-docc.sh: Prepend /// <purpose> DocC comment to Swift files listed in INDEX.yaml
# Usage: run from project root

set -euo pipefail

while IFS=$'\t' read -r path purpose; do
    [[ -f "$path" ]] || continue
    [[ -n "$purpose" ]] || continue

    docc="/// $purpose"
    first_line=$(head -1 "$path")

    if [[ "$first_line" == "$docc" ]]; then
        continue
    fi

    tmp=$(mktemp)
    if [[ "$first_line" == "/// "* ]]; then
        { echo "$docc"; tail -n +2 "$path"; } > "$tmp"
        mv "$tmp" "$path"
        echo "updated: $path"
    else
        { echo "$docc"; cat "$path"; } > "$tmp"
        mv "$tmp" "$path"
        echo "added:   $path"
    fi
done < <(
    yq -o json INDEX.yaml \
    | jq -r '.files[] | select(.path | endswith(".swift")) | [.path, (.purpose // "")] | @tsv'
)
