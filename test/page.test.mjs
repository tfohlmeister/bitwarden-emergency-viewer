// The page's security properties are structural: they hold because of what is
// and is not in the file. These checks guard exactly those.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync, statSync } from "node:fs";

import { VAULT_HTML, readCryptoBlock } from "../tools/crypto.mjs";

const html = readFileSync(VAULT_HTML, "utf8");

test("the crypto block is extractable", () => {
  const block = readCryptoBlock();
  assert.ok(block.includes("async function deriveKeys"));
  assert.ok(block.includes("async function argon2id"));
  // Nothing between the markers may touch the DOM, or it cannot run in Node.
  assert.doesNotMatch(block, /\bdocument\.|\bwindow\.|getElementById/);
});

test("the page keeps its Content-Security-Policy", () => {
  const meta = html.match(/<meta http-equiv="Content-Security-Policy"[\s\S]*?>/);
  assert.ok(meta, "CSP meta tag missing");
  for (const directive of ["default-src 'none'", "form-action 'none'", "base-uri 'none'"]) {
    assert.ok(meta[0].includes(directive), `CSP lost ${directive}`);
  }
  assert.doesNotMatch(meta[0], /connect-src|wasm-unsafe-eval|unsafe-eval/);
});

test("the page loads nothing from the network", () => {
  const external = html.match(/(?:src|href|action)\s*=\s*["']\s*(?:https?:|\/\/)/gi);
  assert.equal(external, null, `external reference: ${external}`);
  assert.doesNotMatch(html, /<script[^>]+\bsrc\s*=/i);
  assert.doesNotMatch(html, /<link[^>]+rel\s*=\s*["']?stylesheet/i);
  assert.doesNotMatch(html, /@import\b/);
  // fetch/XHR would be blocked by the CSP anyway, but their presence would mean
  // someone tried, and the next reader should not have to guess whether it works.
  assert.doesNotMatch(html, /\bfetch\s*\(|XMLHttpRequest|navigator\.sendBeacon|new\s+WebSocket/);
});

test("the page stays small enough to read and to carry around", () => {
  const kb = statSync(VAULT_HTML).size / 1024;
  assert.ok(kb < 100, `vault.html grew to ${kb.toFixed(0)} kB`);
});

test("the page declares its language", () => {
  assert.match(html, /<html lang="en">/);
});
