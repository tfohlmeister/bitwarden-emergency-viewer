// Produces a fixture that Bitwarden's own code wrote.
//
// Everything else in this repo checks our reading of the export format against
// another reading of it. This tool removes the assumption: it starts a
// throwaway Vaultwarden, registers an account whose KDF is Argon2id, fills the
// vault through the official Bitwarden CLI and lets that CLI write the
// encrypted export. If Bitwarden ever changes how a password-protected export
// is built, this is what notices.
//
// Needs Docker and openssl. Run it with `npm run fixture:vaultwarden`.
import { execFileSync } from "node:child_process";
import { request } from "node:https";
import { mkdtempSync, mkdirSync, readFileSync, rmSync } from "node:fs";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { fileURLToPath } from "node:url";
import { setTimeout as sleep } from "node:timers/promises";
import {
  createCipheriv, createHmac, generateKeyPairSync, pbkdf2Sync, randomBytes,
} from "node:crypto";
import { argon2id } from "@noble/hashes/argon2.js";
import { sha256 } from "@noble/hashes/sha2.js";

import { FIXTURE_PASSWORD } from "./make-fixtures.mjs";

// The Bitwarden CLI refuses plain HTTP, so the throwaway server gets a
// throwaway certificate that only the processes started here ever trust.
const CONTAINER = "bitwarden-emergency-viewer-fixture";
const IMAGE = process.env.VAULTWARDEN_IMAGE || "vaultwarden/server:latest";
const PORT = Number(process.env.VAULTWARDEN_PORT || 8222);
const SERVER = `https://localhost:${PORT}`;
const EMAIL = "fixture@example.com";
const ACCOUNT_PASSWORD = "fixture-account-password";
const OUT = fileURLToPath(new URL("../test/fixtures/vaultwarden-argon2id.json", import.meta.url));

// The account KDF that the export inherits. Bitwarden's own Argon2id defaults.
const KDF = { kdf: 1, kdfIterations: 6, kdfMemory: 32, kdfParallelism: 4 };

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
function httpsRequest(url, { method = "GET", body, ca } = {}) {
  return new Promise((resolve, reject) => {
    const req = request(url, {
      method, ca,
      headers: body ? { "Content-Type": "application/json" } : {},
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
function accountMasterKey(password, email) {
  const salt = email.trim().toLowerCase();
  if (KDF.kdf === 0) return pbkdf2Sync(password, salt, KDF.kdfIterations, 32, "sha256");
  return Buffer.from(argon2id(Buffer.from(password, "utf8"), sha256(Buffer.from(salt, "utf8")), {
    t: KDF.kdfIterations, m: KDF.kdfMemory * 1024, p: KDF.kdfParallelism, dkLen: 32,
  }));
}

// The CLI cannot create accounts, so registration goes straight at the API.
async function register(ca) {
  const masterKey = accountMasterKey(ACCOUNT_PASSWORD, EMAIL);
  const userKey = randomBytes(64);          // what actually protects the vault
  const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });

  const payload = {
    email: EMAIL,
    name: "Fixture",
    masterPasswordHash: pbkdf2Sync(masterKey, ACCOUNT_PASSWORD, 1, 32, "sha256").toString("base64"),
    masterPasswordHint: null,
    key: encString(userKey, hkdfExpand(masterKey, "enc"), hkdfExpand(masterKey, "mac")),
    keys: {
      publicKey: publicKey.export({ type: "spki", format: "der" }).toString("base64"),
      encryptedPrivateKey: encString(
        privateKey.export({ type: "pkcs8", format: "der" }),
        userKey.subarray(0, 32), userKey.subarray(32, 64)),
    },
    ...KDF,
  };

  const res = await httpsRequest(`${SERVER}/identity/accounts/register`, {
    method: "POST", body: JSON.stringify(payload), ca,
  });
  // Re-running against a container that still has the account is fine; the
  // password is fixed, so the existing account is the one we want.
  if (res.status === 400 && res.body.includes("user already exists")) return;
  if (res.status < 200 || res.status >= 300) {
    throw new Error(`register failed: HTTP ${res.status} ${res.body}`);
  }
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
];

const ITEM_NAMES = ITEMS.map((item) => item.name);

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
    await register(ca);
    console.log(`registered ${EMAIL}, kdf=${KDF.kdf} `
      + `(${KDF.kdfMemory} MiB, ${KDF.kdfIterations} passes, ${KDF.kdfParallelism} lanes)`);

    const bw = (...args) => execFileSync("npx", ["--no-install", "bw", ...args], {
      encoding: "utf8",
      stdio: ["ignore", "pipe", "inherit"],
      env: {
        ...process.env,
        BITWARDENCLI_APPDATA_DIR: dir,
        NODE_EXTRA_CA_CERTS: join(dir, "cert.pem"),
        NODE_NO_WARNINGS: "1",
      },
    }).trim();

    bw("config", "server", SERVER);
    const session = bw("login", EMAIL, ACCOUNT_PASSWORD, "--raw");
    for (const item of ITEMS) {
      bw("create", "item", Buffer.from(JSON.stringify({
        organizationId: null, collectionIds: null, folderId: null,
        favorite: false, reprompt: 0, ...item,
      })).toString("base64"), "--session", session);
      console.log(`  created ${item.name}`);
    }

    mkdirSync(fileURLToPath(new URL("../test/fixtures", import.meta.url)), { recursive: true });
    bw("export", "--format", "encrypted_json", "--password", FIXTURE_PASSWORD,
       "--output", OUT, "--session", session);
    bw("logout", "--session", session);
    console.log(`wrote ${OUT}`);
  } finally {
    if (!process.env.VAULTWARDEN_KEEP) removeContainer();
    rmSync(dir, { recursive: true, force: true });
  }
}

if (import.meta.url === `file://${process.argv[1]}`) await main();

export { ITEM_NAMES, KDF, OUT };
