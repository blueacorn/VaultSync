#!/bin/bash
# Removes VaultSync runtime state: database and app group config.

set -euo pipefail
source "$(dirname "$0")/app-ids.sh"

DB="$HOME/Library/Containers/$APP_BUNDLE_ID/Data/Documents/files.db"
CFG="$HOME/Library/Group Containers/$APP_GROUP_ID/Library/Application Support/config.json"
CACHE="$HOME/Library/Group Containers/$APP_GROUP_ID/OneDriveCache"

removed=0

for path in "$DB" "$CFG" "$CACHE"; do
    if [ -e "$path" ]; then
        rm -rf "$path"
        echo "Removed: $path"
        removed=$((removed + 1))
    else
        echo "Not found: $path"
    fi
done

echo "Done. $removed item(s) removed."
