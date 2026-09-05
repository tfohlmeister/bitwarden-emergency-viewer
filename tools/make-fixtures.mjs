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
function encString(plaintext, { encKey, macKey }) {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext, "utf8"), cipher.final()]);
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
}

export { VAULT, PBKDF2, ARGON2ID, ARGON2ID_DEFAULTS, FIXTURE_PASSWORD, DEMO_PASSWORD };
