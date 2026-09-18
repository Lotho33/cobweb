#!/usr/bin/env bash
# Cut a new release: bump the version in Cargo.toml/Cargo.lock, commit, tag
# vX.Y.Z, and push the branch + tag.
#
#   scripts/release.sh 0.2.0            # bump + commit + tag + push
#   scripts/release.sh 0.2.0 -n        # dry-run
#
# Pushing the tag triggers the Docker-image build workflow
# (.forgejo/workflows/release.yml, or the GitHub Actions equivalent).
#
# Override the git remote / branch with RELEASE_REMOTE / RELEASE_BRANCH.
set -euo pipefail

REMOTE=${RELEASE_REMOTE:-origin}
BRANCH=${RELEASE_BRANCH:-main}

ver=${1:-}
dry=false
[[ "${2:-}" == "-n" || "${2:-}" == "--dry-run" ]] && dry=true

if [[ ! "$ver" =~ ^[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
  echo "uso: $0 X.Y.Z [-n]   (es. $0 0.2.0)" >&2
  exit 2
fi
tag="v$ver"

cd "$(git rev-parse --show-toplevel)"

# --- controlli -------------------------------------------------------------
cur_branch=$(git branch --show-current)
[[ "$cur_branch" == "$BRANCH" ]] || { echo "sei su '$cur_branch', non '$BRANCH'." >&2; exit 1; }

git fetch -q "$REMOTE" --tags || true
if git rev-parse -q --verify "refs/tags/$tag" >/dev/null || \
   git ls-remote --exit-code --tags "$REMOTE" "$tag" >/dev/null 2>&1; then
  echo "il tag $tag esiste gia (locale o su $REMOTE)." >&2
  exit 1
fi

# Solo Cargo.toml / Cargo.lock possono essere gia modificati tra i file
# tracciati (i non tracciati non bloccano il rilascio).
dirty=$(git status --porcelain --untracked-files=no | grep -vE ' (Cargo\.toml|Cargo\.lock)$' || true)
[[ -z "$dirty" ]] || { echo "albero di lavoro sporco:"; echo "$dirty"; exit 1; }

# --- bump versione -------------------------------------------------------
old_line=$(grep -m1 -E '^version = ' Cargo.toml || true)
echo "Cargo.toml: '${old_line}'  ->  'version = \"${ver}\"'"
echo "commit + tag $tag, poi push '$BRANCH' e '$tag' su '$REMOTE'"

if $dry; then echo "(dry-run, nulla eseguito)"; exit 0; fi

# [package].version + la voce del pacchetto cobweb in Cargo.lock: il Dockerfile
# builda con --locked, quindi i due file devono restare allineati.
sed -i -E '/^\[package\]/,/^\[/ s/^version = ".*"/version = "'"$ver"'"/' Cargo.toml
sed -i -E '/^name = "cobweb"$/{n;s/^version = ".*"/version = "'"$ver"'"/;}' Cargo.lock

git add Cargo.toml Cargo.lock
git commit -m "$tag" -m "" \
  -m "Co-Authored-By: Claude Sonnet 5 <noreply@anthropic.com>"
git tag -a "$tag" -m "$tag"

git push "$REMOTE" "$BRANCH"
git push "$REMOTE" "$tag"

echo
echo "done. pushed $BRANCH + $tag to '$REMOTE'; the image build runs from the tag."
