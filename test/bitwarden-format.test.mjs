// The one test that is not this repo agreeing with itself.
//
// The fixture it reads was written by the official Bitwarden CLI against a real
// Vaultwarden, by tools/vaultwarden-fixture.mjs. The committed copy keeps this
// runnable offline; CI regenerates it against today's Bitwarden and today's
// Vaultwarden before running these same assertions, so a format change upstream
// surfaces here rather than during a recovery.
import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";

import { loadCrypto } from "../tools/crypto.mjs";
import { FIXTURE_PASSWORD } from "../tools/make-fixtures.mjs";
import { ITEM_NAMES, KDF, OUT } from "../tools/vaultwarden-fixture.mjs";

const crypto2 = await loadCrypto();
const data = JSON.parse(readFileSync(OUT, "utf8"));

test("the export Bitwarden wrote carries the account's Argon2id parameters", () => {
  assert.equal(data.encrypted, true);
  assert.equal(data.passwordProtected, true);
  assert.equal(data.kdfType, 1);
  assert.equal(data.kdfIterations, KDF.kdfIterations);
  assert.equal(data.kdfMemory, KDF.kdfMemory);
  assert.equal(data.kdfParallelism, KDF.kdfParallelism);
});

test("the page opens an export written by the Bitwarden CLI", async () => {
  const keys = await crypto2.deriveKeys(FIXTURE_PASSWORD, data);
  await crypto2.decrypt(data.encKeyValidation_DO_NOT_EDIT, keys);
  const vault = JSON.parse(await crypto2.decrypt(data.data, keys));

  assert.deepEqual([...vault.items.map((i) => i.name)].sort(), [...ITEM_NAMES].sort());

  const login = vault.items.find((i) => i.login);
  assert.equal(login.login.username, "ada@example.com");
  assert.equal(login.login.password, "correct-horse-battery-staple");
  assert.equal(login.login.totp, "JBSWY3DPEHPK3PXP");
  assert.ok(login.fields.some((f) => f.name === "PIN" && f.value === "8842"));

  const card = vault.items.find((i) => i.card);
  assert.equal(card.card.number, "4111111111111111");
});

test("a wrong password is refused on a real export too", async () => {
  const keys = await crypto2.deriveKeys("not-the-export-password", data);
  await assert.rejects(
    () => crypto2.decrypt(data.encKeyValidation_DO_NOT_EDIT, keys),
    /MAC mismatch/,
  );
});
