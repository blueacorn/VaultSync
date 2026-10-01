#!/bin/bash

# Shows unredacted logs for VaultSync.app and Provider.appex processes

set -e

cleanup() {
    trap - INT TERM EXIT
    # `log stream`, strip_prefix and colorize_component are all direct
    # children of this script (a pipeline doesn't nest them), and this
    # script does not reliably become its own process-group leader when
    # backgrounded — so a plain `kill -- -$$` can miss them or hit the
    # wrong group. Kill this script's actual children by PID instead.
    pkill -P $$ 2>/dev/null
    exit 0
}
trap cleanup INT TERM EXIT

run_stream() {
    log stream --predicate "$1" --info --debug | strip_prefix | colorize_component
}

STREAM_MODE=false
MINUTES=10
SHOW_APP=true
SHOW_PROVIDER=true
OS_MODE=false

while [[ $# -gt 0 ]]; do
    case "$1" in
        --stream)
            STREAM_MODE=true
            shift
            ;;
        --minutes)
            MINUTES="$2"
            shift 2
            ;;
        --app)
            SHOW_APP=true
            SHOW_PROVIDER=false
            shift
            ;;
        --provider)
            SHOW_PROVIDER=true
            SHOW_APP=false
            shift
            ;;
        --os)
            OS_MODE=true
            shift
            ;;
        *)
            echo "Usage: show-logs.sh [--stream] [--minutes N] [--app|--provider] [--os]"
            echo "  --stream     Show logs in real-time"
            echo "  --minutes N  Show last N minutes (default: 10)"
            echo "  --app        Show VaultSync.app logs only"
            echo "  --provider   Show Provider.appex logs only"
            echo "  --os         Show macOS Finder/FileProvider internal logs (not VaultSync-tagged)"
            echo "  (default: show both processes)"
            exit 1
            ;;
    esac
done

strip_prefix() {
    # Compresses 'YYYY-MM-DD HH:MM:SS.ffffff-ZZZZ 0xHEX  Level  0xHEX  PID  TID '
    # to 'HH:MM:SS  <icon> '.
    # -l: line-buffer stdout. Without it, sed block-buffers when its stdout is
    # a pipe (i.e. always, since this feeds colorize_component next), so a
    # `--stream` run can sit with no visible output for a long time even
    # though log stream is delivering lines.
    sed -l -E \
        -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+[+-][0-9]{4} +0x[0-9a-f]+ +Debug +0x[0-9a-f]+ +[0-9]+ +[0-9]+ +/\1  ⚪️ /' \
        -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+[+-][0-9]{4} +0x[0-9a-f]+ +Info +0x[0-9a-f]+ +[0-9]+ +[0-9]+ +/\1  🔵 /' \
        -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+[+-][0-9]{4} +0x[0-9a-f]+ +Error +0x[0-9a-f]+ +[0-9]+ +[0-9]+ +/\1  🔴 /' \
        -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+[+-][0-9]{4} +0x[0-9a-f]+ +Fault +0x[0-9a-f]+ +[0-9]+ +[0-9]+ +/\1  🔴 /' \
        -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+[+-][0-9]{4} +0x[0-9a-f]+ +Default +0x[0-9a-f]+ +[0-9]+ +[0-9]+ +/\1  ⚫️ /' \
        -e 's/^[0-9]{4}-[0-9]{2}-[0-9]{2} ([0-9]{2}:[0-9]{2}:[0-9]{2})\.[0-9]+[+-][0-9]{4} +0x[0-9a-f]+ +Activity +0x[0-9a-f]+ +[0-9]+ +[0-9]+ +/\1  🟣 /'
}

colorize_component() {
    # Colors the first '[component]' bracket token per line by a hash of its
    # text, so each component gets a stable (but arbitrary) color.
    # fflush() after every line: awk fully block-buffers when stdout isn't a
    # TTY, which it never is here since this is the last pipeline stage
    # writing into a redirect/terminal driver pipe — without the flush,
    # `--stream` output can stall indefinitely.
    awk '
        {
            if (match($0, /\[[^]]+\]/)) {
                token = substr($0, RSTART, RLENGTH)
                hash = 0
                for (i = 1; i <= length(token); i++) {
                    hash = (hash * 31 + index("\
0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ.:_-[]", substr(token, i, 1))) % 997
                }
                n = split("30 63 71 108 137 143 173 178 208", palette, " ")
                color = palette[(hash % n) + 1]
                printf "%s\033[38;5;%sm%s\033[0m%s\n", substr($0, 1, RSTART - 1), color, token, substr($0, RSTART + RLENGTH)
            } else {
                print
            }
            fflush()
        }
    '
}

if [ "$OS_MODE" = true ]; then
    echo "=== macOS Finder / FileProvider Logs ==="
    echo ""

    OS_PREDICATE='subsystem == "com.apple.FileProvider" OR subsystem == "com.apple.fileprovider" OR subsystem == "com.apple.filecoordination" OR subsystem == "com.apple.finder" OR process == "Finder" OR process == "fileproviderd" OR process == "FileProvider"'

    if [ "$STREAM_MODE" = true ]; then
        echo "Streaming logs (Ctrl+C to stop)..."
        echo ""
        run_stream "$OS_PREDICATE"
    else
        log show --predicate "$OS_PREDICATE" --last "${MINUTES}m" --info --debug 2>/dev/null | strip_prefix | colorize_component || echo "No logs found"
    fi
    exit 0
fi

echo "=== VaultSync Logs ==="
echo ""

if [ "$STREAM_MODE" = true ]; then
    echo "Streaming logs (Ctrl+C to stop)..."
    echo ""

    if [ "$SHOW_APP" = true ] && [ "$SHOW_PROVIDER" = true ]; then
        PREDICATE='(process == "VaultSync" OR process == "Provider") AND subsystem CONTAINS ".VaultSync"'
    elif [ "$SHOW_APP" = true ]; then
        PREDICATE='process == "VaultSync" AND subsystem CONTAINS ".VaultSync"'
    else
        PREDICATE='process == "Provider" AND subsystem CONTAINS ".VaultSync"'
    fi

    run_stream "$PREDICATE"
else
    # Show logs from last N minutes
    SINCE=$((MINUTES * 60))

    if [ "$SHOW_APP" = true ]; then
        echo "=== VaultSync.app ==="
        log show --predicate 'process == "VaultSync" AND subsystem CONTAINS ".VaultSync"' --last "${MINUTES}m" --info --debug 2>/dev/null | strip_prefix | colorize_component || echo "No logs found"
    fi

    if [ "$SHOW_APP" = true ] && [ "$SHOW_PROVIDER" = true ]; then
        echo ""
    fi

    if [ "$SHOW_PROVIDER" = true ]; then
        echo "=== Provider.appex ==="
        log show --predicate 'process == "Provider" AND subsystem CONTAINS ".VaultSync"' --last "${MINUTES}m" --info --debug 2>/dev/null | strip_prefix | colorize_component || echo "No logs found"
    fi
fi
