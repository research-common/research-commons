#!/usr/bin/env bash
# Run every phase suite against throwaway registries. Never touches the live one.
#   tests/run-all.sh            # all suites
#   tests/run-all.sh tiers      # only matching suites
#
# HERMETIC BY DESIGN: each suite runs with commons-related env cleared. Suites that
# need an identity mint their own throwaway key. Leaking the operator's ambient
# COMMONS_SIGNING_KEY / COMMONS_ROOT / COMMONS_EXEC in changes what the code does —
# which once produced 91 spurious failures that looked like product bugs but were
# entirely the harness's fault. A test that passes only in a clean shell is not a
# test, so the harness guarantees the clean shell.
set -uo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
FILTER="${1:-}"

LEAKED=()
for v in COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC \
         COMMONS_REQUIRE_SIG COMMONS_REQUIRE_VIEWS COMMONS_CONTAINER_CMD COMMONS_VIEM_DIR; do
  [ -n "${!v:-}" ] && LEAKED+=("$v")
done
if [ ${#LEAKED[@]} -gt 0 ]; then
  printf '\033[33mnote:\033[0m clearing inherited env for hermeticity: %s\n' "${LEAKED[*]}"
fi

rc=0; ran=0
for suite in "$HERE"/test-*.sh; do
  name="$(basename "$suite" .sh)"; name="${name#test-}"
  [ -n "$FILTER" ] && [[ "$name" != *"$FILTER"* ]] && continue
  printf '\n\033[1m═══ %s ═══\033[0m\n' "$name"
  # `env -u` rather than a subshell unset: guarantees the child cannot see them.
  env -u COMMONS_SIGNING_KEY -u COMMONS_ROOT -u COMMONS_AGENT -u COMMONS_EXEC \
      -u COMMONS_REQUIRE_SIG -u COMMONS_REQUIRE_VIEWS -u COMMONS_CONTAINER_CMD -u COMMONS_VIEM_DIR \
      bash "$suite" || rc=1
  ran=$((ran+1))
done
[ "$ran" -eq 0 ] && { echo "no suites matched '$FILTER'"; exit 1; }
printf '\n\033[1mrun-all: %s\033[0m\n' "$([ $rc -eq 0 ] && echo 'ALL GREEN' || echo 'FAILURES ABOVE')"
exit $rc
