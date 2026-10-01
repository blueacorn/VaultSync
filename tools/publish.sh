#!/usr/bin/env bash
#
# publish.sh — export HEAD to the public repo working copy.
#
#   1. Tags HEAD as yyyy-mm-dd (suffix .N if the tag exists on a different commit).
#   2. `git archive` HEAD (honours `export-ignore` / `export-subst` in .gitattributes,
#      restricted to PUBLISH_PATHS) into PUBLIC_DIR, replacing its tracked content.
#   3. Commits in PUBLIC_DIR; optionally pushes main to origin.
#
# Usage: tools/publish.sh -m|--message "<msg>" [-p|--publish]

set -euo pipefail

PUBLIC_DIR="/Users/home/Code/VaultSync/Public"
BRANCH="main"
# Folder filter: paths to export. Empty = whole tree (still subject to export-ignore).
PUBLISH_PATHS=()

message=""
publish=0

usage() { echo "usage: $0 -m|--message \"<msg>\" [-p|--publish]" >&2; exit 2; }

while [[ $# -gt 0 ]]; do
    case "$1" in
        -m|--message) [[ $# -ge 2 ]] || usage; message="$2"; shift 2 ;;
        -p|--publish) publish=1; shift ;;
        -h|--help)    usage ;;
        *)            usage ;;
    esac
done

[[ -n "$message" ]] || usage

src_root="$(git rev-parse --show-toplevel)"
cd "$src_root"

[[ -z "$(git status --porcelain)" ]] || { echo "error: source working tree not clean" >&2; exit 1; }
[[ -d "$PUBLIC_DIR/.git" ]] || { echo "error: $PUBLIC_DIR is not a git working copy (git clone <public-url> $PUBLIC_DIR)" >&2; exit 1; }

head_sha="$(git rev-parse HEAD)"

# --- 1. Tag -----------------------------------------------------------------
tag="$(date +%Y-%m-%d)"
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null; then
    if [[ "$(git rev-list -n1 "$tag")" != "$head_sha" ]]; then
        n=1
        while git rev-parse -q --verify "refs/tags/$tag.$n" >/dev/null; do n=$((n + 1)); done
        tag="$tag.$n"
        git tag -a "$tag" -m "Publish $tag" "$head_sha"
    fi
else
    git tag -a "$tag" -m "Publish $tag" "$head_sha"
fi
echo "tag: $tag -> ${head_sha:0:10}"

# --- 2. Export --------------------------------------------------------------
git -C "$PUBLIC_DIR" checkout -q "$BRANCH" 2>/dev/null || git -C "$PUBLIC_DIR" checkout -q -b "$BRANCH"

# Remove tracked files so deletions/renames upstream propagate; .git is preserved.
git -C "$PUBLIC_DIR" ls-files -z | (cd "$PUBLIC_DIR" && xargs -0 rm -f --)
find "$PUBLIC_DIR" -mindepth 1 -type d -empty -not -path "$PUBLIC_DIR/.git*" -delete

git archive --format=tar "$head_sha" -- ${PUBLISH_PATHS[@]+"${PUBLISH_PATHS[@]}"} \
    | tar -x -C "$PUBLIC_DIR"

# --- 3. Commit / push -------------------------------------------------------
cd "$PUBLIC_DIR"
git add -A
if git diff --cached --quiet; then
    echo "no changes to commit"
else
    git commit -q -m "$message"
    echo "committed: $(git rev-parse --short HEAD) $message"
fi

if [[ $publish -eq 1 ]]; then
    git push origin "$BRANCH"
fi
