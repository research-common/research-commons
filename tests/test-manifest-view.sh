#!/usr/bin/env bash
# Fixed manifest-view/1 wire vectors and actual EIP-191 verification.
set -euo pipefail
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
PYTHONDONTWRITEBYTECODE=1 python3 "$HERE/test-manifest-view.py"
