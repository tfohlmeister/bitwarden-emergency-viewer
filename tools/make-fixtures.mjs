// Builds the encrypted exports the tests and the demo page use.
//
// Deliberately written against Node's crypto and @noble/hashes, never against
// vault.html. That makes decrypting these files a cross-implementation check
// rather than the page agreeing with itself.
import { mkdirSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { createCipheriv, createHmac, pbkdf2Sync, randomBytes, randomUUID } from "node:crypto";
import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";

const root = (p) => fileURLToPath(new URL(`../${p}`, import.meta.url));

// RFC 5869 expand, the half Bitwarden uses.
function hkdfExpand(prk, info, length = 32) {
  const out = Buffer.alloc(length);
  let prev = Buffer.alloc(0);
  let at = 0;
  for (let i = 1; at < length; i++) {
    prev = createHmac("sha256", prk)
      .update(Buffer.concat([prev, Buffer.from(info, "utf8"), Buffer.from([i])]))
      .digest();
    prev.copy(out, at);
    at += prev.length;
  }
  return out;
}

function stretch(masterKey) {
  return { encKey: hkdfExpand(masterKey, "enc"), macKey: hkdfExpand(masterKey, "mac") };
}

// Bitwarden's EncString type 2: AES-256-CBC then HMAC-SHA256 over iv || ct.
// Strings go in as UTF-8, buffers (keys) as they are.
function encString(plaintext, { encKey, macKey }) {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac = createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

function deriveMaster(password, salt, kdf) {
  if (kdf.kdfType === 0) {
    // The base64 salt goes in as a string, not as decoded bytes.
    return pbkdf2Sync(password, salt, kdf.kdfIterations, 32, "sha256");
  }
  // Argon2id hashes that same string first, and counts memory in 1 KiB blocks.
  return Buffer.from(argon2id(Buffer.from(password, "utf8"), sha256(Buffer.from(salt, "utf8")), {
    t: kdf.kdfIterations,
    m: kdf.kdfMemory * 1024,
    p: kdf.kdfParallelism,
    dkLen: 32,
  }));
}

export function buildExport(vault, password, kdf) {
  const salt = randomBytes(16).toString("base64");
  const keys = stretch(deriveMaster(password, salt, kdf));
  return {
    encrypted: true,
    passwordProtected: true,
    salt,
    ...kdf,
    encKeyValidation_DO_NOT_EDIT: encString(randomUUID(), keys),
    data: encString(JSON.stringify(vault, null, 2), keys),
  };
}

// A 64-byte user or item key, split the way Bitwarden splits it.
const splitKey = (raw) => ({ encKey: raw.subarray(0, 32), macKey: raw.subarray(32) });

// What Bitwarden leaves plain: ids and record timestamps. A date the owner
// types in, like a passport's expiry, is an EncString like any other field.
const PLAIN = new Set(["id", "folderId", "creationDate", "revisionDate", "archivedDate",
                       "deletedDate", "passwordRevisionDate", "lastUsedDate"]);

// Every other string of a cipher is its own EncString; numbers stay plain.
function encryptFields(value, keys, name = "") {
  if (typeof value === "string") return PLAIN.has(name) ? value : encString(value, keys);
  if (Array.isArray(value)) return value.map((v) => encryptFields(v, keys));
  if (value && typeof value === "object") {
    return Object.fromEntries(Object.entries(value).map(([k, v]) => [k, encryptFields(v, keys, k)]));
  }
  return value;
}

// An account snapshot of the same vault: the user key wrapped by the master
// key, salted with the account email, and every field encrypted on its own.
// Items listed in withItemKey get a key of their own, as newer clients write.
export function buildSnapshot(vault, password, kdf, { email = "ada@example.com", withItemKey = [] } = {}) {
  const userKeyRaw = randomBytes(64);
  const userKey = splitKey(userKeyRaw);
  return {
    format: "bitwarden-account-snapshot",
    version: 1,
    created: "2026-11-06T02:00:00Z",
    server: "https://vault.example.com",
    serverVersion: "1.37.5",
    salt: email,
    ...kdf,
    userKey: encString(userKeyRaw, stretch(deriveMaster(password, email, kdf))),
    folders: vault.folders.map((f) => ({ id: f.id, name: encString(f.name, userKey) })),
    ciphers: vault.items.map((item) => {
      if (!withItemKey.includes(item.id)) return { ...encryptFields(item, userKey), key: null };
      const itemKeyRaw = randomBytes(64);
      return { ...encryptFields(item, splitKey(itemKeyRaw)), key: encString(itemKeyRaw, userKey) };
    }),
  };
}

const PBKDF2 = { kdfType: 0, kdfIterations: 600000 };
const ARGON2ID = { kdfType: 1, kdfIterations: 3, kdfMemory: 16, kdfParallelism: 4 };

// Bitwarden's own defaults are 6 iterations over 32 MiB. The fixtures use the
// smallest allowed settings so the suite stays quick; the browser test and the
// demo run the real thing.
const ARGON2ID_DEFAULTS = { kdfType: 1, kdfIterations: 6, kdfMemory: 32, kdfParallelism: 4 };

const FOLDER = "6f1c9f5e-0000-4000-8000-000000000001";

// Every item type the page renders, so a rendering regression has something to
// fail against. Invented data only: this file ends up on a public demo page.
const VAULT = {
  folders: [{ id: FOLDER, name: "Infrastructure" }],
  items: [
    {
      id: "a0000000-0000-4000-8000-000000000001",
      type: 1,
      name: "Example Mail",
      folderId: FOLDER,
      notes: "Recovery codes are in the safe.\nSecond line, to prove line breaks survive.",
      login: {
        username: "ada@example.com",
        password: "correct-horse-battery-staple",
        totp: "JBSWY3DPEHPK3PXP",
        uris: [{ uri: "https://mail.example.com" }],
      },
      fields: [
        { name: "Account number", value: "AC-4711", type: 0 },
        { name: "PIN", value: "8842", type: 1 },
      ],
    },
    {
      id: "a0000000-0000-4000-8000-000000000002",
      type: 1,
      name: "Example Router",
      login: {
        username: "admin",
        password: "hunter2-but-longer",
        uris: [{ uri: "https://192.0.2.1" }],
      },
    },
    {
      id: "a0000000-0000-4000-8000-000000000003",
      type: 3,
      name: "Example Card",
      card: { number: "4111111111111111", expMonth: "11", expYear: "2031", code: "123" },
    },
    {
      // A card the owner only ever typed the number into. Bitwarden drops the
      // fields that were left empty rather than storing them as null, so this
      // is what the common case actually looks like on the way back in.
      id: "a0000000-0000-4000-8000-000000000006",
      type: 3,
      name: "Example Card Without Expiry",
      card: { number: "5555555555554444" },
    },
    {
      id: "a0000000-0000-4000-8000-000000000004",
      type: 4,
      name: "Example Identity",
      identity: {
        firstName: "Ada", lastName: "Lovelace", email: "ada@example.com",
        phone: "+1 555 0100", address1: "1 Example Street", city: "Springfield",
        postalCode: "12345", country: "US", passportNumber: "X1234567",
      },
    },
    {
      id: "a0000000-0000-4000-8000-000000000005",
      type: 5,
      name: "Example SSH Key",
      folderId: FOLDER,
      sshKey: {
        privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END OPENSSH PRIVATE KEY-----",
        publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyNotReal",
        keyFingerprint: "SHA256:ExampleFingerprintNotReal",
      },
    },
  ],
};

// The parts of an entry that sit beside its main fields: passkeys, password
// history, a linked custom field, a Steam Guard key, and the card and identity
// fields the first fixture leaves out. Kept out of VAULT for the same reason as
// the newer item types below.
const MORE_FIELDS = {
  folders: [],
  items: [
    {
      id: "c0000000-0000-4000-8000-000000000001",
      type: 1,
      name: "Example Server",
      login: {
        username: "root",
        password: "current-server-password",
        totp: "otpauth://totp/Example:root?secret=JBSWY3DPEHPK3PXP&issuer=Example",
        uris: [{ uri: "ssh://server.example.com" }],
        fido2Credentials: [{
          credentialId: "6f1c9f5e-0000-4000-8000-0000000000aa", keyType: "public-key",
          keyAlgorithm: "ECDSA", keyCurve: "P-256", keyValue: "bm90LWEtcmVhbC1rZXk=",
          rpId: "server.example.com", userHandle: "dXNlci1oYW5kbGU=", userName: "root",
          counter: "0", rpName: "Example Server", userDisplayName: "Root",
          discoverable: "true", creationDate: "2025-06-01T08:00:00.000Z",
        }],
      },
      passwordHistory: [
        { password: "older-server-password", lastUsedDate: "2026-02-01T09:30:00.000Z" },
        { password: "oldest-server-password", lastUsedDate: "2025-07-15T12:00:00.000Z" },
      ],
      fields: [{ name: "Sudo password", value: null, type: 3, linkedId: 101 }],
    },
    {
      id: "c0000000-0000-4000-8000-000000000002",
      type: 1,
      name: "Example Steam",
      login: { username: "ada", password: "steam-password", totp: "steam://JBSWY3DPEHPK3PXP" },
    },
    {
      id: "c0000000-0000-4000-8000-000000000003",
      type: 3,
      name: "Example Branded Card",
      card: { brand: "Visa", number: "4111111111111111" },
    },
    {
      id: "c0000000-0000-4000-8000-000000000004",
      type: 4,
      name: "Example Titled Identity",
      identity: { title: "Dr", firstName: "Ada", lastName: "Lovelace", city: "Springfield", state: "Illinois" },
    },
    {
      id: "c0000000-0000-4000-8000-000000000005",
      type: 2,
      name: "Example Note",
      secureNote: { type: 0 },
      notes: "The spare key is under the blue flowerpot.",
    },
  ],
};

const FIXTURE_PASSWORD = "fixture-master-password";
const DEMO_PASSWORD = "demo";

if (import.meta.url === `file://${process.argv[1]}`) {
  mkdirSync(root("test/fixtures"), { recursive: true });
  mkdirSync(root("site"), { recursive: true });

  const write = (path, value) => {
    writeFileSync(root(path), `${JSON.stringify(value, null, 2)}\n`);
    console.log(`wrote ${path}`);
  };

  write("test/fixtures/vault.json", VAULT);
  write("test/fixtures/pbkdf2.json", buildExport(VAULT, FIXTURE_PASSWORD, PBKDF2));
  write("test/fixtures/argon2id.json", buildExport(VAULT, FIXTURE_PASSWORD, ARGON2ID));
  write("site/demo-vault.json", buildExport(VAULT, DEMO_PASSWORD, ARGON2ID_DEFAULTS));

  // Two broken files, because how the page fails matters as much as how it
  // succeeds. A damaged backup must not be reported as a wrong password.
  const damaged = buildExport(VAULT, FIXTURE_PASSWORD, PBKDF2);
  const [prefix, payload] = damaged.data.split(".", 2);
  const [iv, ct, mac] = payload.split("|");
  const flipped = Buffer.from(ct, "base64");
  flipped[0] ^= 0xff;
  damaged.data = `${prefix}.${iv}|${flipped.toString("base64")}|${mac}`;
  write("test/fixtures/damaged.json", damaged);

  const noValidation = buildExport(VAULT, FIXTURE_PASSWORD, PBKDF2);
  delete noValidation.encKeyValidation_DO_NOT_EDIT;
  write("test/fixtures/no-validation.json", noValidation);

  const ITEM_KEYED = [VAULT.items[0].id, VAULT.items[5].id];
  write("test/fixtures/snapshot-pbkdf2.json",
        buildSnapshot(VAULT, FIXTURE_PASSWORD, PBKDF2, { withItemKey: ITEM_KEYED }));
  write("test/fixtures/snapshot-argon2id.json",
        buildSnapshot(VAULT, FIXTURE_PASSWORD, ARGON2ID, { withItemKey: ITEM_KEYED }));

  // One entry damaged and one already in the trash: the rest has to open, the
  // damaged one has to be counted, and the deleted one has to stay out.
  const partly = buildSnapshot(VAULT, FIXTURE_PASSWORD, PBKDF2, { withItemKey: ITEM_KEYED });
  const [p2, rest] = partly.ciphers[1].name.split(".", 2);
  const [piv, pct, pmac] = rest.split("|");
  const bent = Buffer.from(pct, "base64");
  bent[0] ^= 0xff;
  partly.ciphers[1].name = `${p2}.${piv}|${bent.toString("base64")}|${pmac}`;
  partly.ciphers.push({ ...partly.ciphers[2], id: "a0000000-0000-4000-8000-0000000000ff",
                        deletedDate: "2026-11-01T00:00:00Z" });
  write("test/fixtures/snapshot-damaged.json", partly);

  // The item types newer than the page's dedicated blocks, which it shows field
  // by field. Kept out of VAULT so the export fixtures stay what a CLI writes.
  write("test/fixtures/snapshot-newer-types.json", buildSnapshot({
    folders: [],
    items: [
      { id: "b0000000-0000-4000-8000-000000000006", type: 6, name: "Example Bank Account",
        bankAccount: { bankName: "Example Bank", iban: "DE89370400440532013000", pin: "4711" } },
      { id: "b0000000-0000-4000-8000-000000000007", type: 7, name: "Example Licence",
        driversLicense: { licenseNumber: "B072RRE2I55", issuingCountry: "DE" } },
      { id: "b0000000-0000-4000-8000-000000000008", type: 8, name: "Example Passport",
        passport: { passportNumber: "C01X00T47", surname: "Lovelace" } },
    ],
  }, FIXTURE_PASSWORD, PBKDF2));

  write("test/fixtures/more-fields.json", buildExport(MORE_FIELDS, FIXTURE_PASSWORD, PBKDF2));
  write("test/fixtures/snapshot-more-fields.json", buildSnapshot(MORE_FIELDS, FIXTURE_PASSWORD, PBKDF2));
}

export { VAULT, MORE_FIELDS, PBKDF2, ARGON2ID, ARGON2ID_DEFAULTS, FIXTURE_PASSWORD, DEMO_PASSWORD };
