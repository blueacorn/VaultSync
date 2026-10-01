#!/bin/bash
# Sourced by tools: derives APP_BUNDLE_ID / APP_GROUP_ID from Configuration/Application.xcconfig,
# honouring overrides in Configuration/Local.xcconfig.

_CONFIG_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)/Configuration"
_xcconfig_value() {
    local key="$1" file value=""
    for file in "$_CONFIG_DIR/Application.xcconfig" "$_CONFIG_DIR/Local.xcconfig"; do
        [[ -f "$file" ]] || continue
        local found
        found="$(sed -nE "s/^$key[[:space:]]*=[[:space:]]*([^[:space:]]+).*/\1/p" "$file" | tail -1)"
        [[ -n "$found" ]] && value="$found"
    done
    printf '%s' "$value"
}
BUNDLE_ID_PREFIX="$(_xcconfig_value BUNDLE_ID_PREFIX)"
APP_BUNDLE_ID="$BUNDLE_ID_PREFIX.VaultSync"
APP_GROUP_ID="group.$APP_BUNDLE_ID"
