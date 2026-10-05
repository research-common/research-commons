// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 The Research Commons Authors
// research-commons: sign a raw message with EIP-191 personal_sign.
//
// Message-in / signature-out: the signed object is a canonical JSON string (a ledger
// entry), never a file, so nothing is rewritten. One primitive (viem signMessage), no
// new crypto.
//
// Usage:  MESSAGE=<string> node sign-message.mjs
//         echo -n <string> | node sign-message.mjs --stdin
//         echo -n '{"m1":…,"m2":…}' | node sign-message.mjs --stdin --pair
// Key:    COMMONS_SIGNING_KEY, else ~/.commons/signing.key. Nothing else: no
//         generic wallet-key variable is consulted, because an env var exported for
//         some other signing tool would then silently become the commons identity.
//         (The CLI never reaches the fallback: it signs only when COMMONS_SIGNING_KEY
//         is set, and writes unsigned entries otherwise.)
//
//         The fallback is a DEDICATED commons identity, deliberately not a payment
//         wallet. A commons signature and a payment authorisation must never share a
//         key: publishing an artifact would then be indistinguishable, at the key
//         level, from authorising a transfer, and sharing the ledger address would
//         expose the wallet's on-chain activity to every peer.
// Output: {"address": "0x…", "signature": "0x…"}  (never the key); with --pair also
//         "signature2", the signature over m2.
import { readFileSync, existsSync } from 'node:fs';
import { homedir } from 'node:os';
import { createRequire } from 'node:module';

// viem is resolved from COMMONS_VIEM_DIR, else this repo's own node_modules
// (`npm ci` at the repo root), else the cwd. Node's ESM resolver searches next to the
// *script*, so resolve explicitly rather than depending on the caller's cwd.
function loadViem(sub) {
  const roots = [
    process.env.COMMONS_VIEM_DIR,
    new URL('..', import.meta.url).pathname,  // repo root: `npm ci` here
    process.cwd() + '/',
  ].filter(Boolean);
  for (const root of roots) {
    try {
      const resolved = createRequire(root.endsWith('/') ? root : root + '/').resolve(sub);
      return import(new URL('file://' + resolved).href);
    } catch { /* try next root */ }
  }
  console.error('error: cannot locate viem. Run `npm ci` in the repo root, or set '
    + 'COMMONS_VIEM_DIR to a dir containing node_modules/viem.');
  process.exit(2);
}
const { privateKeyToAccount } = await loadViem('viem/accounts');

const keyPath = process.env.COMMONS_SIGNING_KEY
  || homedir() + '/.commons/signing.key';

let message;
if (process.argv.includes('--stdin')) {
  message = readFileSync(0, 'utf8');
} else {
  message = process.env.MESSAGE;
}
if (message === undefined) {
  console.error('error: set MESSAGE env var or pass --stdin');
  process.exit(2);
}

let raw;
try {
  raw = readFileSync(keyPath, 'utf8').trim();
} catch (e) {
  console.error(`error: cannot read signing key at ${keyPath}: ${e.code || e.message}`);
  process.exit(2);
}
if (!/^(0x)?[0-9a-fA-F]{64}$/.test(raw)) {
  // Never echo key material, not even a fragment.
  console.error('error: signing key is not a 32-byte hex private key');
  process.exit(2);
}

try {
  const account = privateKeyToAccount(raw.startsWith('0x') ? raw : '0x' + raw);
  if (process.argv.includes('--pair')) {
    // Two messages in one process (the ledger's v1 `sig` and v2 `sig2`), so a
    // dual-signed event still spawns one signer. Input: {"m1": "...", "m2": "..."}.
    const { m1, m2 } = JSON.parse(message);
    if (typeof m1 !== 'string' || typeof m2 !== 'string') {
      console.error('error: --pair expects {"m1": string, "m2": string}');
      process.exit(2);
    }
    const signature = await account.signMessage({ message: m1 });
    const signature2 = await account.signMessage({ message: m2 });
    console.log(JSON.stringify({ address: account.address, signature, signature2 }));
  } else {
    const signature = await account.signMessage({ message });
    console.log(JSON.stringify({ address: account.address, signature }));
  }
} catch (e) {
  console.error('error: signing failed: ' + e.message);
  process.exit(2);
}
