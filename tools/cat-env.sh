#!/bin/bash
# Prints out runtime state: database and app group config.

set -euo pipefail
source "$(dirname "$0")/app-ids.sh"

DB="$HOME/Library/Containers/$APP_BUNDLE_ID/Data/Documents/files.db"
CFG="$HOME/Library/Group Containers/$APP_GROUP_ID/Library/Application Support/config.json"
CACHE="$HOME/Library/Group Containers/$APP_GROUP_ID/OneDriveCache"

echo "Database: $DB"
if [ -f "$DB" ]; then
    echo "Found database file."
    sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table';"
    for table in $(sqlite3 "$DB" "SELECT name FROM sqlite_master WHERE type='table';"); do
        echo
        echo "================================================================"
        echo "  TABLE: $table"
        echo "----------------------------------------------------------------"
        sqlite3 -header -column "$DB" "SELECT * FROM \"$table\" LIMIT 5;"
    done
else
    echo "Database file not found."
fi

echo
echo "OneDriveCache: $CACHE"
if [ -d "$CACHE" ]; then
    # Find every database that has a -wal sidecar (active databases).
    found=0
    while IFS= read -r wal; do
        found=1
        db="${wal%-wal}"
        echo
        echo "################################################################"
        echo "# DATABASE: $db"
        echo "################################################################"
        for table in $(sqlite3 "$db" "SELECT name FROM sqlite_master WHERE type='table';"); do
            echo
            echo "================================================================"
            echo "  TABLE: $table"
            echo "----------------------------------------------------------------"
            sqlite3 -header -column "$db" "SELECT * FROM \"$table\" LIMIT 5;"
        done
    done < <(find "$CACHE" -name '*-wal' 2>/dev/null)
    [ "$found" -eq 0 ] && echo "No WAL databases found."
else
    echo "Cache folder not found."
fi

echo
echo "Config: $CFG"
if [ -f "$CFG" ]; then
    echo "Found config file."
    cat "$CFG"
else
    echo "Config file not found."
fi