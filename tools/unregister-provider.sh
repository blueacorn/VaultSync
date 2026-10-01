#!/bin/bash
# Unregisters stale VaultSync copies (and their Provider/Action extensions) from LaunchServices
# and pluginkit, keeping one build configuration, then restarts fileproviderd.
#
# Multiple registered copies sharing one bundle ID cause fileproviderd to resolve the wrong
# extension ("The application cannot be used right now").
#
# Usage: unregister-provider.sh [--keep Debug|Release|none] [--delete]
#   --keep    build configuration to keep registered (default: none)
#   --delete  also remove the unregistered .app bundles from disk

set -euo pipefail
source "$(dirname "$0")/app-ids.sh"

LSREGISTER=/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister
KEEP_CONFIG=none
DELETE=0

while [[ $# -gt 0 ]]; do
    case "$1" in
        --keep)   KEEP_CONFIG="$2"; shift 2 ;;
        --delete) DELETE=1; shift ;;
        *) echo "usage: $0 [--keep Debug|Release|none] [--delete]" >&2; exit 64 ;;
    esac
done

# All registered app bundles whose identifier is APP_BUNDLE_ID.
registered_apps() {
    "$LSREGISTER" -dump 2>/dev/null | awk -v id="$APP_BUNDLE_ID" '
        /^path:/       { sub(/^path:[[:space:]]+/, ""); sub(/ \(0x[0-9a-f]+\)$/, ""); path = $0 }
        /^identifier:/ { if ($2 == id && path ~ /\.app$/) print path }
    ' | sort -u
}

KEPT=""
while IFS= read -r app; do
    [[ -n "$app" ]] || continue
    if [[ "$KEEP_CONFIG" != none && "$app" == */Build/Products/$KEEP_CONFIG/* ]]; then
        KEPT="$app"; echo "keep:       $app"; continue
    fi
    echo "unregister: $app"
    for appex in "$app"/Contents/PlugIns/*.appex; do
        [[ -e "$appex" ]] && pluginkit -r "$appex" 2>/dev/null || true
    done
    "$LSREGISTER" -u "$app" 2>/dev/null || true
    if [[ $DELETE -eq 1 && -e "$app" ]]; then rm -rf "$app"; echo "deleted:    $app"; fi
done < <(registered_apps)

if [[ -n "$KEPT" ]]; then
    "$LSREGISTER" -f "$KEPT"
    pluginkit -a "$KEPT/Contents/PlugIns/Provider.appex"
    pluginkit -e use -i "$APP_BUNDLE_ID.Provider"
fi

killall fileproviderd 2>/dev/null || true
killall -9 Provider 2>/dev/null || true

pluginkit -m -v -i "$APP_BUNDLE_ID.Provider" || echo "no provider registered for $APP_BUNDLE_ID.Provider"
