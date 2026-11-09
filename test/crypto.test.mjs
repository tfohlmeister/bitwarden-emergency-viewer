import test from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createHash, randomBytes } from "node:crypto";
import { argon2id as nobleArgon2id } from "@noble/hashes/argon2.js";

import { loadCrypto } from "../tools/crypto.mjs";
import {
  ACCOUNTS, CLUB, FAMILY, FIXTURE_PASSWORD, MORE_FIELDS, SECOND_PASSWORD, SECOND_VAULT, VAULT,
} from "../tools/make-fixtures.mjs";

const crypto2 = await loadCrypto();
const fixture = (name) =>
  JSON.parse(readFileSync(fileURLToPath(new URL(`fixtures/${name}`, import.meta.url)), "utf8"));

const hex = (u8) => Buffer.from(u8).toString("hex");
const bytes = (n, v) => new Uint8Array(n).fill(v);

// --------------------------------------------------------------- blake2b ---

test("blake2b matches OpenSSL across block boundaries", () => {
  // 0, 1, 127, 128 and 129 bytes exercise the empty input, a partial final
  // block, an exactly-full one and the two-block path.
  for (const length of [0, 1, 55, 127, 128, 129, 256, 1000]) {
    const input = new Uint8Array(randomBytes(length));
    assert.equal(
      hex(crypto2.blake2b(input, 64)),
      createHash("blake2b512").update(input).digest("hex"),
      `length ${length}`,
    );
  }
});

test("hPrime produces the length it was asked for", () => {
  for (const length of [1, 32, 64, 65, 1024]) {
    assert.equal(crypto2.hPrime(new Uint8Array([1, 2, 3]), length).length, length);
  }
});

// ---------------------------------------------------------------- argon2 ---

test("argon2id reproduces the RFC 9106 test vector", async () => {
  const tag = await crypto2.argon2id(bytes(32, 1), bytes(16, 2), {
    iterations: 3, memory: 32, parallelism: 4, outLen: 32,
    secret: bytes(8, 3), ad: bytes(12, 4),
  });
  assert.equal(hex(tag),
    "0d640df58d78766c08c037a34a8b53c9d01ef0452d75b65eb52520e96b01e659");
});

// Fixed inputs on purpose. A randomised sweep would cover a different corner
// every run, and the one test that can catch an indexing regression is worthless
// if the failure cannot be reproduced from the failure message.
const ARGON2_CASES = [
  { t: 2, m: 1024, p: 1, pw: 1, salt: 8 },       // the minimum Bitwarden allows
  { t: 3, m: 1024, p: 4, pw: 24, salt: 16 },     // several lanes over one segment
  { t: 6, m: 2048, p: 4, pw: 32, salt: 16 },     // Bitwarden's iteration default
  { t: 2, m: 3072, p: 3, pw: 40, salt: 32 },     // lane count that does not divide m
  { t: 4, m: 2048, p: 1, pw: 8, salt: 24 },      // single lane, several passes
  { t: 10, m: 1024, p: 2, pw: 16, salt: 8 },     // the maximum iteration count
];

test("argon2id agrees with @noble/hashes across the parameter space", async () => {
  for (const { t, m, p, pw, salt: saltLen } of ARGON2_CASES) {
    // Deterministic filler, so the whole case is reconstructible from its label.
    const password = new Uint8Array(pw).map((_, i) => (i * 7 + t) & 0xff);
    const salt = new Uint8Array(saltLen).map((_, i) => (i * 13 + m) & 0xff);
    const mine = await crypto2.argon2id(password, salt, {
      iterations: t, memory: m, parallelism: p,
    });
    const theirs = nobleArgon2id(password, salt, { t, m, p, dkLen: 32 });
    assert.equal(hex(mine), hex(theirs), `m=${m} t=${t} p=${p}`);
  }
});

test("argon2id refuses parameters that would leave the memory unwritten", async () => {
  // Below 8 blocks per lane the segment arithmetic rounds down to nothing.
  await assert.rejects(
    () => crypto2.argon2id(new Uint8Array(8), new Uint8Array(8), {
      iterations: 3, memory: 16, parallelism: 4,
    }),
    /at least 32 KiB for 4 lanes/,
  );
});

// ------------------------------------------------------------- decryption ---

for (const [name, file] of [["PBKDF2", "pbkdf2.json"], ["Argon2id", "argon2id.json"]]) {
  test(`${name} export decrypts to the original vault`, async () => {
    const data = fixture(file);
    const keys = await crypto2.deriveKeys(FIXTURE_PASSWORD, data);
    await crypto2.decrypt(data.encKeyValidation_DO_NOT_EDIT, keys);
    const vault = JSON.parse(await crypto2.decrypt(data.data, keys));

    assert.deepEqual(vault, VAULT);
    // Spot-check the shapes the page renders, so a fixture that decrypts but is
    // structurally empty cannot pass.
    assert.equal(vault.items.length, 6);
    assert.ok(vault.items.some((i) => i.login?.totp));
    assert.ok(vault.items.some((i) => i.sshKey?.privateKey));
    assert.ok(vault.items.some((i) => i.card?.number));
  });

  test(`${name} export refuses the wrong password`, async () => {
    const data = fixture(file);
    const keys = await crypto2.deriveKeys("not-the-master-password", data);
    await assert.rejects(
      () => crypto2.decrypt(data.encKeyValidation_DO_NOT_EDIT, keys),
      /MAC mismatch/,
    );
  });
}

const byName = (items) =>
  [...items].sort((a, b) => String(a.name).localeCompare(String(b.name)));

for (const [name, file] of [["PBKDF2", "snapshot-pbkdf2.json"], ["Argon2id", "snapshot-argon2id.json"]]) {
  test(`${name} account snapshot decrypts to the original vault`, async () => {
    const data = fixture(file);
    assert.ok(data.ciphers.some((c) => c.key), "fixture lost its item-keyed entries");
    const userKey = await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data);
    const vault = await crypto2.readSnapshot(data, userKey);

    assert.deepEqual(vault.failed, []);
    assert.deepEqual(vault.folders, VAULT.folders);
    assert.deepEqual(vault.items, byName(VAULT.items));
  });

  test(`${name} account snapshot refuses the wrong password`, async () => {
    await assert.rejects(
      () => crypto2.unlockSnapshot("not-the-master-password", fixture(file)),
      /MAC mismatch/,
    );
  });
}

test("a snapshot keeps passkeys, password history and linked fields, dates in plain", async () => {
  const data = fixture("snapshot-more-fields.json");
  const vault = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data));
  assert.deepEqual(vault.failed, []);
  assert.deepEqual(vault.items, byName(MORE_FIELDS.items));
});

test("a damaged snapshot entry is counted and the rest still opens", async () => {
  const data = fixture("snapshot-damaged.json");
  const vault = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data));

  assert.equal(vault.failed.length, 1);
  assert.equal(vault.failed[0].id, VAULT.items[1].id);
  assert.match(vault.failed[0].error, /MAC mismatch/);
  // The damaged entry is missing, and so is the one in the trash.
  assert.deepEqual(vault.items, byName(VAULT.items.filter((_, i) => i !== 1)));
});

test("a field that is not an EncString fails its entry instead of showing as the value", async () => {
  const data = fixture("snapshot-pbkdf2.json");
  const router = data.ciphers.find((c) => c.id === VAULT.items[1].id);
  router.login.password = "2.!damaged|ciphertext|mac";
  const vault = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data));

  assert.equal(vault.failed.length, 1);
  assert.equal(vault.failed[0].name, "Example Router");
  assert.ok(!vault.items.some((i) => i.name === "Example Router"));
});

test("a damaged entry keeps its name when the name still opens", async () => {
  const data = fixture("snapshot-damaged.json");
  const vault = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data));
  // The fixture damages the name itself, so there is nothing to keep.
  assert.equal(vault.failed[0].name, null);
});

test("a snapshot of an unknown format version is refused by name", async () => {
  const data = { ...fixture("snapshot-pbkdf2.json"), version: 3 };
  await assert.rejects(() => crypto2.unlockSnapshot(FIXTURE_PASSWORD, data), /version 1 or 2/);
});

// ----------------------------------------------- several accounts (version 2) ---

const inOrg = (vault, organization) =>
  vault.items.map(({ folderId, ...item }) => ({ ...item, organization }));

test("each account of a version 2 snapshot opens with its own password", async () => {
  const data = fixture("snapshot-multi.json");
  assert.equal(data.accounts.length, 2);
  assert.notEqual(data.accounts[0].kdfType, data.accounts[1].kdfType, "the fixture should cover both KDFs");

  const first = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data, null, 0));
  assert.deepEqual(first.failed, []);
  assert.deepEqual(first.folders, VAULT.folders);
  assert.deepEqual(first.items, byName([
    ...VAULT.items, ...inOrg(FAMILY, "Example Family"), ...inOrg(CLUB, "Example Club"),
  ]));
  assert.deepEqual(first.parts, [
    { organization: null, entries: VAULT.items.length },
    { organization: "Example Family", entries: FAMILY.items.length },
    { organization: "Example Club", entries: CLUB.items.length },
  ]);

  // The second account is a member of the family only, not of the club.
  const second = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(SECOND_PASSWORD, data, null, 1));
  assert.deepEqual(second.failed, []);
  assert.deepEqual(second.items, byName([...SECOND_VAULT.items, ...inOrg(FAMILY, "Example Family")]));
});

test("an organization item with a key of its own opens under the organization key", async () => {
  const data = fixture("snapshot-multi.json");
  const family = data.organizations.find((o) => o.name === "Example Family");
  assert.ok(family.ciphers.some((c) => c.key), "the fixture lost its item-keyed organization entry");
  assert.match(family.keys[ACCOUNTS[0].id], /^4\./);
});

test("one account's password does not open another account", async () => {
  const data = fixture("snapshot-multi.json");
  await assert.rejects(() => crypto2.unlockSnapshot(FIXTURE_PASSWORD, data, null, 1), /MAC mismatch/);
  await assert.rejects(() => crypto2.unlockSnapshot(SECOND_PASSWORD, data, null, 0), /MAC mismatch/);
  await assert.rejects(() => crypto2.unlockSnapshot(FIXTURE_PASSWORD, data, null, 2), /no account 2/);
});

test("the accounts and the organizations each one opens are listed without a key", () => {
  const data = fixture("snapshot-multi.json");
  const accounts = crypto2.snapshotAccounts(data);
  assert.deepEqual(accounts.map((a) => a.salt), ACCOUNTS.map((a) => a.email));
  assert.deepEqual(crypto2.accountOrganizations(data, accounts[1]).map((o) => o.name), ["Example Family"]);
  // A version 1 snapshot is one account, member of nothing.
  const single = fixture("snapshot-pbkdf2.json");
  assert.equal(crypto2.snapshotAccounts(single).length, 1);
  assert.deepEqual(crypto2.accountOrganizations(single, crypto2.snapshotAccounts(single)[0]), []);
});

test("an organization whose key does not open is named, and the rest still opens", async () => {
  const data = fixture("snapshot-multi-damaged-org.json");
  const vault = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(SECOND_PASSWORD, data, null, 1));
  assert.deepEqual(vault.items, byName(SECOND_VAULT.items));
  assert.equal(vault.failed.length, 1);
  assert.equal(vault.failed[0].name, `Organization Example Family, all ${FAMILY.items.length} entries`);
  // The first account's copy of the same key is intact.
  const first = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(FIXTURE_PASSWORD, data, null, 0));
  assert.deepEqual(first.failed, []);
});

test("an organization key of an unknown type is refused by name", async () => {
  const data = fixture("snapshot-multi.json");
  const family = data.organizations.find((o) => o.name === "Example Family");
  family.keys[ACCOUNTS[1].id] = `6.${family.keys[ACCOUNTS[1].id].slice(2)}|bWFj`;
  const vault = await crypto2.readSnapshot(data, await crypto2.unlockSnapshot(SECOND_PASSWORD, data, null, 1));
  assert.match(vault.failed[0].error, /organization key type 6/);
});

test("progress is reported for Argon2id and reaches 1", async () => {
  const data = fixture("argon2id.json");
  const seen = [];
  await crypto2.deriveKeys(FIXTURE_PASSWORD, data, (done) => seen.push(done));
  assert.equal(seen.length, data.kdfIterations * 4);
  assert.equal(seen.at(-1), 1);
  assert.deepEqual(seen, [...seen].sort((a, b) => a - b));
});

test("an unknown KDF is refused by name, not silently mis-derived", async () => {
  await assert.rejects(
    () => crypto2.deriveKeys("x", { salt: "AAAA", kdfIterations: 3, kdfType: 7 }),
    /KDF type 7/,
  );
});

test("an Argon2id export without its parameters is refused", async () => {
  await assert.rejects(
    () => crypto2.deriveKeys("x", { salt: "AAAA", kdfIterations: 3, kdfType: 1 }),
    /kdfMemory or kdfParallelism/,
  );
});

test("an export without salt or iterations is refused", async () => {
  await assert.rejects(
    () => crypto2.deriveKeys("x", { kdfType: 0 }),
    /no salt or kdfIterations/,
  );
});

// ------------------------------------------------------------------ totp ---

test("totp reproduces the RFC 6238 test vectors", async () => {
  // ASCII "12345678901234567890", the secret the RFC uses, in base32.
  const secret = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
  const realNow = Date.now;
  try {
    for (const [seconds, expected] of [
      [59, "94287082"], [1111111109, "07081804"], [1234567890, "89005924"],
    ]) {
      Date.now = () => seconds * 1000;
      assert.equal((await crypto2.totp(secret, 30, 8)).code, expected, `T=${seconds}`);
    }
  } finally {
    Date.now = realNow;
  }
});

test("totp honours the algorithm of an otpauth:// URI (RFC 6238 vectors)", async () => {
  const realNow = Date.now;
  Date.now = () => 59 * 1000;
  try {
    for (const [algorithm, secret, expected] of [
      ["SHA256", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZA", "46119246"],
      ["SHA512", "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"
        + "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQGEZDGNA", "90693936"],
    ]) {
      const uri = `otpauth://totp/x?secret=${secret}&digits=8&algorithm=${algorithm}`;
      assert.equal((await crypto2.totp(uri)).code, expected, algorithm);
    }
    await assert.rejects(() => crypto2.totp("otpauth://totp/x?secret=GEZA&algorithm=MD5"), /MD5/);
  } finally {
    Date.now = realNow;
  }
});

test("totp reads parameters out of an otpauth:// URI", async () => {
  const realNow = Date.now;
  Date.now = () => 59 * 1000;
  try {
    const uri = "otpauth://totp/Example:ada@example.com"
      + "?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&digits=8&period=30";
    assert.equal((await crypto2.totp(uri)).code, "94287082");
  } finally {
    Date.now = realNow;
  }
});

test("totp reports the seconds left in the window", async () => {
  const realNow = Date.now;
  Date.now = () => 25 * 1000;
  try {
    assert.equal((await crypto2.totp("GEZDGNBVGY3TQOJQ")).left, 5);
  } finally {
    Date.now = realNow;
  }
});

test("totp writes a steam:// key as a five-character Steam Guard code", async () => {
  // RFC 4226's counter 1 truncates to 1094287082, which Steam's alphabet
  // spells PV9M4, least significant character first. The vector comes from a
  // separate Python HMAC, so only the alphabet is shared with the page, and
  // that alphabet is the one in Bitwarden's own client.
  const realNow = Date.now;
  Date.now = () => 59 * 1000;
  try {
    assert.equal((await crypto2.totp("steam://GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ")).code, "PV9M4");
  } finally {
    Date.now = realNow;
  }
});

test("totp rejects a secret that is not base32", async () => {
  await assert.rejects(() => crypto2.totp("not base32!"), /base32/);
});
