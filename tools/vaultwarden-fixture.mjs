// Produces a fixture that Bitwarden's own code wrote.
//
// Everything else in this repo checks our reading of the export format against
// another reading of it. This tool removes the assumption: it starts a
// throwaway Vaultwarden, registers an account whose KDF is Argon2id, fills the
// vault through the official Bitwarden CLI and lets that CLI write the
// encrypted export. If Bitwarden ever changes how a password-protected export
// is built, this is what notices. It also takes an account snapshot from the
// server's sync answers, the other format the page opens: of that account, of
// a second one with PBKDF2, and of an organization both are members of, whose
// items the CLI writes under the organization key.
//
// Needs Docker and openssl. Run it with `npm run fixture:vaultwarden`.
import { execFileSync } from "node:child_process";
import { request } from "node:https";
import { mkdtempSync, mkdirSync, readFileSync, rmSync, writeFileSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import {
  constants, createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, publicEncrypt, randomBytes,
  randomUUID,
} from "node:crypto";
import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { FIXTURE_PASSWORD } from "./make-fixtures.mjs";
import { snapshotFromSyncs } from "./snapshot.mjs";

// The Bitwarden CLI refuses plain HTTP, so the throwaway server gets a
// throwaway certificate that only the processes started here ever trust.
const CONTAINER = "bitwarden-emergency-viewer-fixture";
const IMAGE = process.env.VAULTWARDEN_IMAGE || "vaultwarden/server:latest";
const PORT = Number(process.env.VAULTWARDEN_PORT || 8222);
const SERVER = `https://localhost:${PORT}`;
const EMAIL = "fixture@example.com";
const ACCOUNT_PASSWORD = "fixture-account-password";
const SECOND_EMAIL = "second@example.com";
const SECOND_PASSWORD = "second-account-password";
const OUT = fileURLToPath(new URL("../test/fixtures/vaultwarden-argon2id.json", import.meta.url));
const SNAPSHOT_OUT = fileURLToPath(
  new URL("../test/fixtures/vaultwarden-snapshot.json", import.meta.url));

// The account KDF that the export inherits. Bitwarden's own Argon2id defaults.
const KDF = { kdf: 1, kdfIterations: 6, kdfMemory: 32, kdfParallelism: 4 };
// The second account keeps the older default, so the snapshot covers both.
const SECOND_KDF = { kdf: 0, kdfIterations: 600000, kdfMemory: null, kdfParallelism: null };

const docker = (...args) =>
  execFileSync("docker", args, { encoding: "utf8", stdio: ["ignore", "pipe", "pipe"] }).trim();

// Removing a container that is not there is the normal case on a fresh runner,
// and older Docker versions report it as an error.
const removeContainer = () => {
  try {
    docker("rm", "-f", CONTAINER);
  } catch { /* nothing to remove */ }
};

function makeCertificate(dir) {
  execFileSync("openssl", [
    "req", "-x509", "-newkey", "rsa:2048", "-nodes", "-days", "1",
    "-subj", "/CN=localhost", "-addext", "subjectAltName=DNS:localhost,IP:127.0.0.1",
    "-keyout", join(dir, "key.pem"), "-out", join(dir, "cert.pem"),
  ], { stdio: "ignore" });
  // Vaultwarden reads them as a non-root user inside the container.
  execFileSync("chmod", ["644", join(dir, "key.pem"), join(dir, "cert.pem")]);
  return join(dir, "cert.pem");
}

// Node's global fetch cannot be pointed at a CA at runtime, so the two calls
// that have to trust the throwaway certificate go through node:https directly.
function httpsRequest(url, { method = "GET", body, ca, headers = {} } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(url, {
      method, ca,
      headers: { ...(body ? { "Content-Type": "application/json" } : {}), ...headers },
    }, (res) => {
      const chunks = [];
      res.on("data", (chunk) => chunks.push(chunk));
      res.on("end", () => resolve({
        status: res.statusCode,
        body: Buffer.concat(chunks).toString("utf8"),
      }));
    });
    req.on("error", reject);
    if (body) req.write(body);
    req.end();
  });
}

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

function encString(plaintext, encKey, macKey) {
  const iv = randomBytes(16);
  const cipher = createCipheriv("aes-256-cbc", encKey, iv);
  const ct = Buffer.concat([cipher.update(plaintext), cipher.final()]);
  const mac = createHmac("sha256", macKey).update(Buffer.concat([iv, ct])).digest();
  return `2.${iv.toString("base64")}|${ct.toString("base64")}|${mac.toString("base64")}`;
}

// An account's master key is salted with the email address rather than with a
// random salt. Argon2id hashes that salt first, PBKDF2 does not.
function accountMasterKey(password, email, kdf) {
  const salt = email.trim().toLowerCase();
  if (kdf.kdf === 0) return pbkdf2Sync(password, salt, kdf.kdfIterations, 32, "sha256");
  return Buffer.from(argon2id(Buffer.from(password, "utf8"), sha256(Buffer.from(salt, "utf8")), {
    t: kdf.kdfIterations, m: kdf.kdfMemory * 1024, p: kdf.kdfParallelism, dkLen: 32,
  }));
}

const ACCOUNTS = {
  first: { email: EMAIL, password: ACCOUNT_PASSWORD, kdf: KDF },
  second: { email: SECOND_EMAIL, password: SECOND_PASSWORD, kdf: SECOND_KDF },
};

// Derived once per run, not at import: the tests import this module for its
// constants and should not pay for an Argon2id run.
const accounts = {};
function credentials(name = "first") {
  if (!accounts[name]) {
    const { email, password, kdf } = ACCOUNTS[name];
    const masterKey = accountMasterKey(password, email, kdf);
    accounts[name] = {
      email, password, kdf, masterKey,
      masterPasswordHash: pbkdf2Sync(masterKey, password, 1, 32, "sha256").toString("base64"),
      userKey: randomBytes(64),             // what actually protects the vault
      keyPair: generateKeyPairSync("rsa", { modulusLength: 2048 }),
    };
  }
  return accounts[name];
}

// The CLI cannot create accounts, so registration goes straight at the API.
async function register(ca, name) {
  const { email, kdf, masterKey, masterPasswordHash, userKey, keyPair } = credentials(name);
  const { publicKey, privateKey } = keyPair;

  // Without SMTP, Vaultwarden hands the email verification token back directly
  // instead of mailing it, as plain text since the request sends no Accept.
  const verify = await httpsRequest(`${SERVER}/identity/accounts/register/send-verification-email`, {
    method: "POST", body: JSON.stringify({ email, name: "Fixture" }), ca,
  });
  if (verify.status !== 200) {
    throw new Error(`send-verification-email failed: HTTP ${verify.status} ${verify.body}`);
  }

  const payload = {
    email,
    emailVerificationToken: verify.body.trim(),
    name: "Fixture",
    masterPasswordHash,
    masterPasswordHint: null,
    key: encString(userKey, hkdfExpand(masterKey, "enc"), hkdfExpand(masterKey, "mac")),
    keys: {
      publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      encryptedPrivateKey: encString(
        privateKey.export({ type: "pkcs8", format: "der" }),
        userKey.subarray(0, 32), userKey.subarray(32, 64)),
    },
    ...kdf,
  };

  const res = await httpsRequest(`${SERVER}/identity/accounts/register/finish`, {
    method: "POST", body: JSON.stringify(payload), ca,
  });
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`register failed: HTTP ${res.status} ${res.body}`);
  }
}

async function accessToken(ca, name = "first") {
  const { email, masterPasswordHash } = credentials(name);
  const form = new URLSearchParams({
    grant_type: "password", username: email, password: masterPasswordHash,
    scope: "api offline_access", client_id: "cli",
    deviceType: "25", deviceIdentifier: randomUUID(), deviceName: "fixture",
  }).toString();
  const res = await httpsRequest(`${SERVER}/identity/connect/token`, {
    method: "POST", body: form, ca,
    headers: { "Content-Type": "application/x-www-form-urlencoded" },
  });
  if (res.status !== 200) throw new Error(`token failed: HTTP ${res.status} ${res.body}`);
  return JSON.parse(res.body).access_token;
}

// Whether the CLI writes per-item keys depends on what the server advertises
// (CLI 2026.10.1 against Vaultwarden 1.37.5 does, for every entry), and vaults
// that moved between servers carry them either way. One item with a key is
// therefore written here, so the test does not hang on the CLI's choice,
// encrypted the way the Bitwarden clients do it: the item key under the user
// key, the fields under the item key.
const ITEM_KEYED = {
  type: 1, name: "Vaultwarden Item Key", notes: "Encrypted under a key of its own.",
  login: { username: "item-key@example.com", password: "own-key-password" },
};

// With an organization, the item key sits under the organization key and the
// cipher goes in with the collection it belongs to.
async function createItemKeyed(ca, token, item = ITEM_KEYED, org = null) {
  const parentKey = org ? org.key : credentials().userKey;
  const itemKey = randomBytes(64);
  const [ik, im] = [itemKey.subarray(0, 32), itemKey.subarray(32)];
  const auth = { Authorization: `Bearer ${token}` };
  const profile = await httpsRequest(`${SERVER}/api/accounts/profile`, { ca, headers: auth });
  const cipher = {
    // Current servers want to know whose key the cipher was encrypted for.
    encryptedFor: JSON.parse(profile.body).id,
    type: item.type, folderId: null, organizationId: org?.id ?? null, favorite: false, reprompt: 0,
    key: encString(itemKey, parentKey.subarray(0, 32), parentKey.subarray(32)),
    name: encString(item.name, ik, im),
    notes: encString(item.notes, ik, im),
    login: {
      username: encString(item.login.username, ik, im),
      password: encString(item.login.password, ik, im),
      uris: [],
    },
  };
  const res = await httpsRequest(`${SERVER}/api/ciphers${org ? "/create" : ""}`, {
    method: "POST", ca, headers: auth,
    body: JSON.stringify(org ? { cipher, collectionIds: [org.collectionId] } : cipher),
  });
  if (res.status !== 200) throw new Error(`create item-keyed cipher failed: HTTP ${res.status} ${res.body}`);
}

// RSA-OAEP with SHA-1, the EncString type 4 the clients wrap organization keys in.
const wrapFor = (publicKey, key) => `4.${publicEncrypt({
  key: publicKey, padding: constants.RSA_PKCS1_OAEP_PADDING, oaepHash: "sha1",
}, key).toString("base64")}`;

// No client creates organizations against Vaultwarden from the command line, so
// the organization goes in through the API, with its key wrapped for the first
// account the way the clients write it. The CLI then has to unwrap that key to
// write the organization's items, which checks the wrapping from Bitwarden's side.
// The second account is invited (without SMTP an existing user is accepted at
// once) and confirmed with the key wrapped for it.
async function createOrganization(ca, token) {
  const auth = { Authorization: `Bearer ${token}` };
  const call = async (method, path, body) => {
    const res = await httpsRequest(`${SERVER}${path}`, {
      method, ca, headers: auth, body: body && JSON.stringify(body),
    });
    if (res.status !== 200) throw new Error(`${method} ${path} failed: HTTP ${res.status} ${res.body}`);
    return res.body ? JSON.parse(res.body) : null;
  };
  const key = randomBytes(64);
  const [ok, om] = [key.subarray(0, 32), key.subarray(32)];
  const orgKeys = generateKeyPairSync("rsa", { modulusLength: 2048 });
  const org = await call("POST", "/api/organizations", {
    name: ORGANIZATION, billingEmail: EMAIL, planType: 0,
    collectionName: encString("Fixture Collection", ok, om),
    key: wrapFor(credentials().keyPair.publicKey, key),
    keys: {
      publicKey: orgKeys.publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      encryptedPrivateKey: encString(orgKeys.privateKey.export({ type: "pkcs8", format: "der" }), ok, om),
    },
  });
  const collectionId = (await call("GET", `/api/organizations/${org.id}/collections`)).data[0].id;
  await call("POST", `/api/organizations/${org.id}/users/invite`, {
    emails: [SECOND_EMAIL], groups: [], type: 2, permissions: {},
    collections: [{ id: collectionId, readOnly: false, hidePasswords: false, manage: false }],
  });
  const member = (await call("GET", `/api/organizations/${org.id}/users`)).data
    .find((m) => m.email === SECOND_EMAIL);
  await call("POST", `/api/organizations/${org.id}/users/${member.id}/confirm`, {
    key: wrapFor(credentials("second").keyPair.publicKey, key),
  });
  return { id: org.id, key, collectionId };
}

// Vaultwarden leaves SSH keys out of the sync answer for clients that do not
// say they are new enough to know the type, so the snapshot has to say it.
const CLIENT_HEADERS = { "Bitwarden-Client-Name": "cli", "Bitwarden-Client-Version": "2026.10.1" };

async function takeSnapshot(ca, tokens) {
  const get = async (token, path) => {
    const res = await httpsRequest(`${SERVER}${path}`, {
      ca, headers: { Authorization: `Bearer ${token}`, ...CLIENT_HEADERS },
    });
    if (res.status !== 200) throw new Error(`${path} failed: HTTP ${res.status}`);
    return JSON.parse(res.body);
  };
  const syncs = [];
  for (const token of tokens) syncs.push(await get(token, "/api/sync?excludeDomains=true"));
  return snapshotFromSyncs(syncs, { server: SERVER, serverVersion: await get(tokens[0], "/api/version") });
}

// One item of each type the page renders a dedicated block for.
const ITEMS = [
  {
    type: 1, name: "Vaultwarden Login", notes: "Written by the Bitwarden CLI.",
    login: {
      username: "ada@example.com", password: "correct-horse-battery-staple",
      totp: "JBSWY3DPEHPK3PXP", uris: [{ match: null, uri: "https://mail.example.com" }],
    },
    fields: [{ name: "PIN", value: "8842", type: 1 }],
  },
  { type: 2, name: "Vaultwarden Note", notes: "A secure note.", secureNote: { type: 0 } },
  {
    type: 3, name: "Vaultwarden Card",
    card: { number: "4111111111111111", expMonth: "11", expYear: "2031", code: "123" },
  },
  {
    type: 4, name: "Vaultwarden Identity",
    identity: { firstName: "Ada", lastName: "Lovelace", email: "ada@example.com" },
  },
  {
    type: 5, name: "Vaultwarden SSH Key",
    sshKey: {
      privateKey: "-----BEGIN OPENSSH PRIVATE KEY-----\nbm90LWEtcmVhbC1rZXk=\n-----END OPENSSH PRIVATE KEY-----",
      publicKey: "ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIExampleKeyNotReal",
      keyFingerprint: "SHA256:ExampleFingerprintNotReal",
    },
  },
];

const ITEM_NAMES = ITEMS.map((item) => item.name);

// The organization, the entries the CLI writes into it, the one with a key of
// its own written through the API, and the second account's own entry.
const ORGANIZATION = "Fixture Family";
const ORG_ITEMS = [
  {
    type: 1, name: "Family Streaming", notes: "Written by the Bitwarden CLI into the organization.",
    login: { username: "family@example.com", password: "family-streaming-password", uris: [] },
  },
];
const ORG_ITEM_KEYED = {
  type: 1, name: "Family Item Key", notes: "Under a key of its own, under the organization key.",
  login: { username: "family-key@example.com", password: "family-own-key-password" },
};
const SECOND_ITEMS = [
  { type: 1, name: "Second Login", login: { username: "second@example.com", password: "second-password", uris: [] } },
];

async function startServer(dir) {
  const certs = makeCertificate(dir);
  removeContainer();
  docker(
    "run", "-d", "--name", CONTAINER,
    "-e", "SIGNUPS_ALLOWED=true",
    "-e", "I_REALLY_WANT_VOLATILE_STORAGE=true",
    "-e", "ROCKET_PORT=8222",
    "-e", 'ROCKET_TLS={certs="/certs/cert.pem",key="/certs/key.pem"}',
    "-v", `${dir}:/certs:ro`,
    "-p", `127.0.0.1:${PORT}:8222`,
    IMAGE,
  );

  const ca = readFileSync(certs);
  for (let attempt = 0; attempt < 60; attempt++) {
    try {
      const res = await httpsRequest(`${SERVER}/alive`, { ca });
      if (res.status === 200) return ca;
    } catch { /* not up yet */ }
    await sleep(1000);
  }
  throw new Error(`Vaultwarden did not come up on ${SERVER}\n${docker("logs", CONTAINER)}`);
}

async function main() {
  const dir = mkdtempSync(join(tmpdir(), "bw-fixture-"));
  try {
    const ca = await startServer(dir);
    console.log(`vaultwarden up on ${SERVER}`);
    for (const name of ["first", "second"]) {
      await register(ca, name);
      const { email, kdf } = credentials(name);
      console.log(`registered ${email}, kdf=${kdf.kdf} `
        + (kdf.kdf === 1 ? `(${kdf.kdfMemory} MiB, ${kdf.kdfIterations} passes, ${kdf.kdfParallelism} lanes)`
          : `(${kdf.kdfIterations} rounds)`));
    }

    // One CLI data directory per account, so the two logins do not meet.
    const bwAs = (appdata) => (...args) => execFileSync("npx", ["--no-install", "bw", ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
      env: {
        ...process.env,
        BITWARDENCLI_APPDATA_DIR: appdata,
        NODE_EXTRA_CA_CERTS: join(dir, "cert.pem"),
        NODE_NO_WARNINGS: "1",
      },
    }).trim();
    const createItem = (bw, session, item, org = null) => {
      bw("create", "item", Buffer.from(JSON.stringify({
        organizationId: org?.id ?? null, collectionIds: org ? [org.collectionId] : null, folderId: null,
        favorite: false, reprompt: 0, ...item,
      })).toString("base64"), "--session", session);
      console.log(`  created ${item.name}`);
    };

    const bw = bwAs(join(dir, "first"));
    bw("config", "server", SERVER);
    const session = bw("login", EMAIL, ACCOUNT_PASSWORD, "--raw");
    for (const item of ITEMS) createItem(bw, session, item);

    mkdirSync(fileURLToPath(new URL("../test/fixtures", import.meta.url)), { recursive: true });
    bw("export", "--format", "encrypted_json", "--password", FIXTURE_PASSWORD,
       "--output", OUT, "--session", session);
    console.log(`wrote ${OUT}`);

    const token = await accessToken(ca);
    await createItemKeyed(ca, token);
    console.log(`  created ${ITEM_KEYED.name} (with an item key)`);
    const org = await createOrganization(ca, token);
    console.log(`created ${ORGANIZATION}, ${SECOND_EMAIL} confirmed as a member`);
    bw("sync", "--session", session);
    for (const item of ORG_ITEMS) createItem(bw, session, item, org);
    await createItemKeyed(ca, token, ORG_ITEM_KEYED, org);
    console.log(`  created ${ORG_ITEM_KEYED.name} (with an item key, in the organization)`);
    bw("logout", "--session", session);

    const bw2 = bwAs(join(dir, "second"));
    bw2("config", "server", SERVER);
    const session2 = bw2("login", SECOND_EMAIL, SECOND_PASSWORD, "--raw");
    for (const item of SECOND_ITEMS) createItem(bw2, session2, item);
    bw2("logout", "--session", session2);

    const tokens = [token, await accessToken(ca, "second")];
    writeFileSync(SNAPSHOT_OUT, `${JSON.stringify(await takeSnapshot(ca, tokens), null, 2)}\n`);
    console.log(`wrote ${SNAPSHOT_OUT}`);
  } finally {
    if (!process.env.VAULTWARDEN_KEEP) removeContainer();
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();

export {
  ACCOUNT_PASSWORD, ITEM_KEYED, ITEM_NAMES, KDF, OUT, SNAPSHOT_OUT,
  ORGANIZATION, ORG_ITEMS, ORG_ITEM_KEYED, SECOND_EMAIL, SECOND_ITEMS, SECOND_KDF, SECOND_PASSWORD,
};
