#!/usr/bin/env bash
# Candidate-only checks. No registry/policy writes, production signers or authority evaluation.
# Ordinary Go build/toolchain caches may be used.
set -euo pipefail
caller_dir="$PWD"
cd "$(dirname "$0")/.."
case "${1:-}" in
  "")
    test "$#" -eq 0
    go test ./internal/wire ./internal/keylog -run '^TestFixedRootCandidate' -count=1
    ;;
  --statement|--policy)
    if test "$#" -ne 2; then
      echo 'usage: validate-fixed-root-identity.sh [--statement FILE | --policy FILE]' >&2
      exit 2
    fi
    export RC_IDENTITY_CANDIDATE_FILE
    case "$2" in
      /*) RC_IDENTITY_CANDIDATE_FILE="$2" ;;
      *) RC_IDENTITY_CANDIDATE_FILE="$caller_dir/$2" ;;
    esac
    export RC_IDENTITY_CANDIDATE_POLICY=0
    if test "$1" = --policy; then export RC_IDENTITY_CANDIDATE_POLICY=1; fi
    go test ./internal/wire -run '^TestFixedRootCandidateFile$' -count=1 -v
    ;;
  *)
    echo 'usage: validate-fixed-root-identity.sh [--statement FILE | --policy FILE]' >&2
    exit 2
    ;;
esac
