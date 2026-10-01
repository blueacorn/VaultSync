#!/bin/bash
set -e

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"
source tools/app-ids.sh

RUN_ALL=true
RUN_PERF=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --integration)
            RUN_ALL=false
            shift
            ;;
        --perf)
            RUN_ALL=false
            RUN_PERF=true
            shift
            ;;
        *)
            echo "Usage: run-tests.sh [--integration | --perf]"
            echo "  (default)       Run all tests"
            echo "  --integration   Run integration tests only (BC01IntegrationTests)"
            echo "  --perf          Run the GraphDeltaSync throughput benchmark (live OneDrive)"
            echo ""
            echo "  --perf environment:"
            echo "    FB_PERF_DOMAIN_ID   OneDrive domain to crawl (required if several configured)"
            echo "    FB_PERF_ROOT        crawl root override; 'root' = whole drive"
            echo "    FB_PERF_OUT         append the report to this file"
            exit 1
            ;;
    esac
done

# The live throughput benchmark. Runs via an .xctestrun so the FB_PERF_* variables actually
# reach the test process: `xcodebuild test` forwards neither its own environment nor
# `KEY=VALUE` (that sets a build setting), but the .xctestrun's per-target EnvironmentVariables
# dict is honoured. Requires a OneDrive credential already configured in VaultSync.app.
if [ "$RUN_PERF" = true ]; then
    echo "=== GraphDeltaSync throughput benchmark ==="

    xcodebuild build-for-testing -scheme VaultSync -allowProvisioningUpdates -quiet

    SETTINGS=$(xcodebuild -scheme VaultSync -showBuildSettings -json 2>/dev/null)
    PRODUCTS_DIR=$(echo "$SETTINGS" | /usr/bin/python3 -c \
        "import json,sys; print(json.load(sys.stdin)[0]['buildSettings']['BUILT_PRODUCTS_DIR'])")
    # The .xctestrun resolves its product paths relative to its own directory, so the edited
    # copy has to live beside the original.
    BASE=$(ls -t "$(dirname "$PRODUCTS_DIR")"/*.xctestrun | head -1)
    RUN="$(dirname "$BASE")/perf-$$.xctestrun"
    trap 'rm -f "$RUN"' EXIT
    cp "$BASE" "$RUN"

    # Resolve the domain up front when the caller did not name one: the test refuses to guess
    # among several configured domains, and discovering that from the result bundle afterwards
    # is a poor trade for a 20-second run.
    if [ -z "$FB_PERF_DOMAIN_ID" ]; then
        CONFIG="$HOME/Library/Group Containers/$APP_GROUP_ID/Library/Application Support/config.json"
        if [ -f "$CONFIG" ]; then
            CANDIDATES=$(/usr/bin/python3 -c "
import json,sys
try: accounts = json.load(open(sys.argv[1])).get('accounts') or {}
except Exception: sys.exit(0)
for k, v in sorted(accounts.items()):
    # Credentials live in the keychain keyed by domain id, not in config.json;
    # the backend kind is all this pre-flight can see. The test itself skips when
    # the chosen domain turns out to have no usable credential.
    if v.get('backendKind') == 'oneDrive':
        print(k)
" "$CONFIG")
            COUNT=$(echo "$CANDIDATES" | grep -c . || true)
            if [ "$COUNT" -eq 1 ]; then
                export FB_PERF_DOMAIN_ID="$CANDIDATES"
            elif [ "$COUNT" -gt 1 ]; then
                echo "Several OneDrive domains are configured. Set FB_PERF_DOMAIN_ID to one of:"
                echo "$CANDIDATES" | /usr/bin/sed 's/^/  /'
                echo ""
                echo "  FB_PERF_DOMAIN_ID=<uuid> FB_PERF_ROOT=root ./run-tests.sh --perf"
                exit 1
            fi
        fi
    fi

    ARGS=(-c "Add :ExtensionTests:EnvironmentVariables:FB_PERF_ONEDRIVE string 1")
    for VAR in FB_PERF_DOMAIN_ID FB_PERF_ROOT FB_PERF_OUT FB_PERF_ONEDRIVE; do
        if [ -n "${!VAR}" ]; then
            ARGS+=(-c "Add :ExtensionTests:EnvironmentVariables:$VAR string ${!VAR}")
        fi
    done
    /usr/libexec/PlistBuddy "${ARGS[@]}" "$RUN" > /dev/null

    START=$(date +%s)
    xcodebuild test-without-building -xctestrun "$RUN" \
        -destination "platform=macOS,arch=$(uname -m)" \
        -only-testing ExtensionTests/GraphDeltaSyncPerfTests

    # The report is written to os_log, not stdout: the test host's stdout is not forwarded.
    echo ""
    echo "=== Results ==="
    /usr/bin/log show --start "@$START" --info --style compact \
        --predicate 'category == "delta-perf"' \
        | grep -v "^Timestamp" | /usr/bin/sed 's/^.*delta-perf\] //'
    exit 0
fi

echo "=== Fetching Data files ==="
git lfs pull

echo "=== Run Tests ==="

if [ "$RUN_ALL" = true ]; then
    echo "Running all tests (integration + unit)..."
    # Common: crypto + metadata + stream-decrypt unit/integration tests.
    xcodebuild test -scheme Common
    # VaultSync: hosts VaultSyncTests + ExtensionTests (GraphStreamDownload, etc.).
    xcodebuild test -scheme VaultSync
    # Server: local (emulated) server tests (Currently empty)
    xcodebuild test -scheme Server
else
    echo "Running integration tests..."
    xcodebuild test -scheme Common \
        -only-testing CommonTests/BC01IntegrationTests
fi

echo ""
echo "✓ Tests passed"
