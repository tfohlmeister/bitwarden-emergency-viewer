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
import {
  ACCOUNT_PASSWORD, ITEM_KEYED, ITEM_NAMES, KDF, ORGANIZATION, ORG_ITEMS, ORG_ITEM_KEYED, OUT,
  SECOND_EMAIL, SECOND_ITEMS, SECOND_KDF, SECOND_PASSWORD, SNAPSHOT_OUT,
} from "../tools/vaultwarden-fixture.mjs";

const crypto2 = await loadCrypto();
const data = JSON.parse(readFileSync(OUT, "utf8"));
const snapshot = JSON.parse(readFileSync(SNAPSHOT_OUT, "utf8"));

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

// The snapshot is the server's own encrypted copy, so these check our reading
// of what Vaultwarden stores, not of what an export writer produces.
test("the snapshot carries each account's KDF and salt as the server reports them", () => {
  assert.equal(snapshot.format, "bitwarden-account-snapshot");
  assert.equal(snapshot.version, 2);
  const [first, second] = snapshot.accounts;
  assert.equal(first.salt, "fixture@example.com");
  assert.equal(first.kdfType, 1);
  assert.equal(first.kdfIterations, KDF.kdfIterations);
  assert.equal(first.kdfMemory, KDF.kdfMemory);
  assert.equal(first.kdfParallelism, KDF.kdfParallelism);
  assert.equal(second.salt, SECOND_EMAIL);
  assert.equal(second.kdfType, 0);
  assert.equal(second.kdfIterations, SECOND_KDF.kdfIterations);
});

test("the organization carries its key for both members, as RSA-OAEP type 4", () => {
  const [org] = snapshot.organizations;
  assert.equal(org.name, ORGANIZATION);
  assert.deepEqual(Object.keys(org.keys).sort(), snapshot.accounts.map((a) => a.id).sort());
  for (const key of Object.values(org.keys)) assert.match(key, /^4\.[A-Za-z0-9+/]+=*$/);
  assert.ok(org.ciphers.some((c) => c.key), "the item-keyed organization cipher lost its key");
});

const orgNames = [...ORG_ITEMS.map((i) => i.name), ORG_ITEM_KEYED.name];

test("the page opens a snapshot of a real Vaultwarden account", async () => {
  const vault = await crypto2.readSnapshot(
    snapshot, await crypto2.unlockSnapshot(ACCOUNT_PASSWORD, snapshot));

  assert.deepEqual(vault.failed, []);
  assert.deepEqual(vault.items.map((i) => i.name).sort(),
                   [...ITEM_NAMES, ITEM_KEYED.name, ...orgNames].sort());
  assert.deepEqual(vault.items.filter((i) => i.organization).map((i) => i.name).sort(), orgNames.sort());
  const family = vault.items.find((i) => i.name === ORG_ITEMS[0].name);
  assert.equal(family.login.password, ORG_ITEMS[0].login.password);
  assert.equal(family.organization, ORGANIZATION);
  assert.equal(vault.items.find((i) => i.name === ORG_ITEM_KEYED.name).login.password,
               ORG_ITEM_KEYED.login.password);

  const login = vault.items.find((i) => i.name === "Vaultwarden Login");
  assert.equal(login.login.password, "correct-horse-battery-staple");
  assert.equal(login.login.totp, "JBSWY3DPEHPK3PXP");
  assert.equal(login.login.uris[0].uri, "https://mail.example.com");
  assert.ok(login.fields.some((f) => f.name === "PIN" && f.value === "8842"));

  const keyed = vault.items.find((i) => i.name === ITEM_KEYED.name);
  assert.ok(snapshot.accounts[0].ciphers.some((c) => c.key), "the item-keyed cipher lost its key");
  assert.equal(keyed.login.password, ITEM_KEYED.login.password);

  const ssh = vault.items.find((i) => i.sshKey);
  assert.match(ssh.sshKey.privateKey, /BEGIN OPENSSH PRIVATE KEY/);
  assert.equal(vault.items.find((i) => i.identity).identity.lastName, "Lovelace");
});

test("the second account opens with its own password, the organization with it", async () => {
  const vault = await crypto2.readSnapshot(
    snapshot, await crypto2.unlockSnapshot(SECOND_PASSWORD, snapshot, null, 1));
  assert.deepEqual(vault.failed, []);
  assert.deepEqual(vault.items.map((i) => i.name).sort(),
                   [...SECOND_ITEMS.map((i) => i.name), ...orgNames].sort());
  assert.equal(vault.items.find((i) => i.name === SECOND_ITEMS[0].name).login.password,
               SECOND_ITEMS[0].login.password);
});

test("a wrong password is refused on a real snapshot too", async () => {
  await assert.rejects(() => crypto2.unlockSnapshot("not-the-password", snapshot), /MAC mismatch/);
  await assert.rejects(() => crypto2.unlockSnapshot(ACCOUNT_PASSWORD, snapshot, null, 1), /MAC mismatch/);
});
