#!/usr/bin/env bash

set -euo pipefail

usage() {
  cat <<'EOF'
Usage: scripts/audit-authors.sh [--name NAME] [--email EMAIL]

Audits every local branch after applying .mailmap and verifies that commit
authors match the repository owner's configured Git identity. Committers and
Co-authored-by trailers are reported separately and are never rewritten.

This script is intentionally read-only. It does not run filter-branch,
filter-repo, commit --amend, or force-push.
EOF
}

canonical_name=""
canonical_email=""

while [[ $# -gt 0 ]]; do
  case "$1" in
    --name)
      [[ $# -ge 2 ]] || { printf 'Missing value for --name.\n' >&2; exit 2; }
      canonical_name=$2
      shift 2
      ;;
    --email)
      [[ $# -ge 2 ]] || { printf 'Missing value for --email.\n' >&2; exit 2; }
      canonical_email=$2
      shift 2
      ;;
    --help|-h)
      usage
      exit 0
      ;;
    *)
      printf 'Unknown argument: %s\n' "$1" >&2
      usage >&2
      exit 2
      ;;
  esac
done

git rev-parse --is-inside-work-tree >/dev/null 2>&1 || {
  printf 'Run this script inside a Git repository.\n' >&2
  exit 2
}

repo_root=$(git rev-parse --show-toplevel)
cd "$repo_root"

canonical_name=${canonical_name:-$(git config --get user.name || true)}
canonical_email=${canonical_email:-$(git config --get user.email || true)}

if [[ -z "$canonical_name" || -z "$canonical_email" ]]; then
  printf 'Configure user.name and user.email, or pass --name and --email.\n' >&2
  exit 2
fi

canonical_identity="$canonical_name <$canonical_email>"
mapfile -t local_branches < <(git for-each-ref --format='%(refname)' refs/heads)

if [[ ${#local_branches[@]} -eq 0 ]]; then
  printf 'No local branches were found.\n' >&2
  exit 2
fi

printf 'Canonical commit author: %s\n' "$canonical_identity"
printf 'Auditing %d local branch(es) with .mailmap applied...\n' "${#local_branches[@]}"

failed=0
for branch in "${local_branches[@]}"; do
  branch_name=${branch#refs/heads/}
  mapfile -t authors < <(git log --use-mailmap --format='%aN <%aE>' "$branch" | sort -u)
  unexpected=()
  for author in "${authors[@]}"; do
    [[ "$author" == "$canonical_identity" ]] || unexpected+=("$author")
  done

  if [[ ${#unexpected[@]} -eq 0 ]]; then
    printf '  OK   %-32s %s\n' "$branch_name" "$canonical_identity"
  else
    failed=1
    printf '  FAIL %s contains additional author identities:\n' "$branch_name" >&2
    printf '       %s\n' "${unexpected[@]}" >&2
  fi
done

printf '\nDistinct raw commit authors (metadata as stored):\n'
git log --all --format='  %an <%ae>' | sort -u

printf '\nDistinct committers (hosting services may legitimately appear here):\n'
git log --all --format='  %cn <%ce>' | sort -u

mapfile -t coauthors < <(git log --all --format='%(trailers:key=Co-authored-by,valueonly)' | sed '/^[[:space:]]*$/d' | sort -u)
printf '\nPreserved Co-authored-by attribution:\n'
if [[ ${#coauthors[@]} -eq 0 ]]; then
  printf '  (none)\n'
else
  printf '  %s\n' "${coauthors[@]}"
fi

if [[ $failed -ne 0 ]]; then
  cat >&2 <<'EOF'

Audit failed. Do not remap an additional identity unless the person who owns
that identity confirms it is their alias. Preserve genuine contributor and
Co-authored-by attribution.
EOF
  exit 1
fi

printf '\nAuthor audit passed. No history was changed.\n'
