#!/usr/bin/env bash
# Browse freshness: deterministic age boundaries, legacy RFC 3339 instants, and
# list/search/collection rendering. No live registry, signer, or Docker needed.
set -euo pipefail
unset COMMONS_SIGNING_KEY COMMONS_ROOT COMMONS_AGENT COMMONS_EXEC COMMONS_REQUIRE_SIG
HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMMONS="${COMMONS_TEST_BIN:-$(dirname "$HERE")/bin/commons}"
PYTHONDONTWRITEBYTECODE=1 python3 - "$COMMONS" <<'PY'
import copy
import importlib.machinery
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from unittest.mock import patch

passed = failed = 0

def check(label, got, expected):
    global passed, failed
    if got == expected:
        passed += 1
        print('  ok   ' + label)
    else:
        failed += 1
        print('  FAIL %s (want %r, got %r)' % (label, expected, got))

commons = str(Path(sys.argv[1]).resolve())
with tempfile.TemporaryDirectory(prefix='commons-freshness-') as root:
    os.environ['COMMONS_ROOT'] = root
    os.environ['COMMONS_AGENT'] = 'test-freshness'
    loader = importlib.machinery.SourceFileLoader('commons_freshness_test', commons)
    spec = importlib.util.spec_from_loader(loader.name, loader)
    c = importlib.util.module_from_spec(spec)
    loader.exec_module(c)
    # JSON rows now resolve authenticated derived state from the held registry.
    c.ensure_dirs()
    if not hasattr(c, 'fmt_age'):
        check('freshness formatter exists', False, True)
    else:
        fixed = c.parse_ts('2026-09-26T12:00:00Z')
        real_gmtime = c.time.gmtime
        with patch.object(c.time, 'gmtime',
                          lambda secs=None: real_gmtime(fixed if secs is None else secs)):
            for seconds, expected in [
                (0, '<1h'), (3599, '<1h'), (3600, '1h'), (86399, '23h'),
                (86400, '1d'), (2591999, '29d'), (2592000, '1mo'),
                (31535999, '12mo'), (31536000, '1y'), (-120, '<1h'),
            ]:
                check('age boundary %ss' % seconds, c.fmt_age(c.fmt_ts(fixed-seconds)), expected)
            for value in (None, '', 'not-a-date', 123):
                check('unparseable timestamp %r is harmless' % (value,), c.fmt_age(value), None)
            check('legacy numeric offset preserves the instant',
                  c.fmt_age('2026-09-25T05:00:00-07:00'), '1d')
            check('legacy fractional seconds preserve the age',
                  c.fmt_age('2026-09-25T12:00:00.500Z'), '1d')
            m = {'id': 'ds-1234abcd', 'type': 'dataset', 'title': 'freshness fixture',
                 'created': '2026-09-26T11:59:00Z', 'verification': {'tier': 'T3'},
                 'availability': {'obtainability': 'open'}}
            check('unattested means pub, not obs', c.age_display(m), 'pub <1h')
            check('missing observation is explicit null', c.observed_of(m), None)
            m['verification']['attested_by'] = {
                'statement': {'observed': '2026-04-26T12:00:00Z'}}
            for bad in ('garbage-not-a-timestamp', 17, ['x']):
                m['verification']['attested_by'] = {'statement': {'observed': bad}}
                check('malformed observed %r falls back to pub' % (bad,),
                      c.age_display(m), 'pub <1h')
            m['verification']['attested_by'] = {
                'statement': {'observed': '2026-04-26T12:00:00Z'}}
            before = copy.deepcopy(m)
            check('observation age takes priority', c.age_display(m), 'obs 5mo')
            check('list row keeps availability before age',
                  '[open] [obs 5mo] freshness fixture' in c._fmt_row(m), True)
            check('collection row keeps availability before age',
                  '[open] [obs 5mo] freshness fixture' in c._member_line(m), True)
            check('rendering does not mutate tier or manifest', m, before)
            with patch.object(c, 'verified_agent_of', lambda unused: None):
                row = c._json_row(m, {})
            check('JSON observed is absolute', row['observed'], '2026-04-26T12:00:00Z')
            check('JSON created is unchanged', row['created'], m['created'])
            check('JSON has no computed age', 'age' in row, False)

        def run(*args):
            return subprocess.run([commons, *args], text=True, capture_output=True,
                                  env=os.environ, check=False)

        data = Path(root) / 'fixture.csv'
        data.write_text('sample,value\n1,17\n')
        result = run('publish', 'dataset', str(data), 'freshness fixture',
                     '--license', 'CC0-1.0', '--obtainability', 'open')
        check('fixture publish succeeds', result.returncode, 0)
        aid = result.stdout.strip()
        collection = Path(root) / 'collection.json'
        collection.write_text(json.dumps({
            'scope': 'Freshness rendering regression fixture',
            'maintainers': [{'addr': '0x' + '12' * 20}],
            'members': [{'id': aid, 'role': 'dataset'}],
        }))
        result = run('publish', 'collection', str(collection), 'Freshness collection')
        check('collection fixture publish succeeds', result.returncode, 0)
        cid = result.stdout.strip()
        for label, args in [('list', ('list',)),
                            ('search', ('search', 'freshness fixture')),
                            ('collection show', ('collection', 'show', cid))]:
            result = run(*args)
            check(label + ' exits successfully', result.returncode, 0)
            check(label + ' displays labelled publish age',
                  '[open] [pub <1h] freshness fixture' in result.stdout, True)

        # Renderer-only fixture in a throwaway registry. This is intentionally NOT
        # a valid signature; signature validity belongs to test-signing.sh/verify.
        manifest_path = Path(root) / 'registry' / 'artifacts' / (aid + '.json')
        m = json.loads(manifest_path.read_text())
        m['verification']['attested_by'] = {
            'statement': {'observed': '2020-01-01T00:00:00Z'}}
        manifest_path.write_text(json.dumps(m))
        for label, args in [('list', ('list',)),
                            ('search', ('search', 'freshness fixture')),
                            ('collection show', ('collection', 'show', cid))]:
            result = run(*args)
            check(label + ' shows observation age without reindex',
                  '[open] [obs ' in result.stdout, True)
        result = run('list', '--json')
        rows = {row['id']: row for row in json.loads(result.stdout)}
        check('CLI JSON emits the original observed instant',
              rows[aid]['observed'], '2020-01-01T00:00:00Z')
        check('CLI JSON includes explicit null for an unattested collection',
              'observed' in rows[cid] and rows[cid]['observed'] is None, True)

print('test-freshness: %d passed, %d failed' % (passed, failed))
sys.exit(bool(failed))
PY
