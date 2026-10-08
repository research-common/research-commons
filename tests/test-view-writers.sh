#!/usr/bin/env bash
# Phase 2: real CLI writer/reader regressions, with offline container execution.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
env -u COMMONS_SIGNING_KEY -u COMMONS_ROOT -u COMMONS_AGENT -u COMMONS_EXEC \
    -u COMMONS_REQUIRE_SIG -u COMMONS_CONTAINER_CMD \
    PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/test-view-writers.py"
