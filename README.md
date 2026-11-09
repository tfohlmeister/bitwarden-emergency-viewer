# Bitwarden Emergency Viewer

One HTML file that opens a password-protected Bitwarden or Vaultwarden export,
or an account snapshot (below), with nothing but a browser. No server, no account, no network, nothing to
install. Put it in the same backup as your export and you can read your
passwords on any machine that has a browser and your master password.

It handles both key derivation functions Bitwarden uses, **PBKDF2** and
**Argon2id**, and computes **live TOTP codes**, because an account with
two-factor auth is unreachable without one and the authenticator app is usually
gone in the same disaster as everything else.

## Why this exists

An encrypted Bitwarden export is a dead end without a Bitwarden. Reading one
normally means importing it into a running server or client, which is precisely
what a disaster takes away. This file closes that gap.

Other tools decrypt the same format. [`astik-dev/bitwarden-json-decryptor`][1]
does the cryptography and prints the JSON. That is enough when you know what you
are looking for. This one is built for the moment when you do not:

- a searchable list, so you do not have to know the entry's name
- passwords hidden until you click, and every value copyable
- **live TOTP codes with a countdown**, Steam Guard included, and the key
  itself, to set up an authenticator app on a new phone
- SSH keys, cards, identities and custom fields rendered, not just logins
- the password history, for the server that never got the new one
- meant to sit inside the backup, not to be found and downloaded during the
  emergency

[1]: https://github.com/astik-dev/bitwarden-json-decryptor

## Use it

1. Export your vault: **File → Export vault**, format **.json (Encrypted)**,
   password-protected. The CLI equivalent is
   `bw export --format encrypted_json --password <password>`.
2. Put `vault.html` next to the export file in your backup.
3. When you need it, open `vault.html` by double-clicking, choose the export,
   type the master password.

There is a [demo][demo] with an invented vault (master password `demo`).

### Or: an account snapshot

Writing a password-protected export means unlocking the vault, so whatever
produces it needs the master password. An automated backup job then holds the
one secret that opens everything. The account snapshot avoids that: it is the
encrypted vault exactly as the server hands it to every client at sync, and
producing it needs only an API login per account, never a master password.
Opening it needs nothing but the master password, the same as the export.

One file can hold several accounts (a household's) and the items of the
organizations they share. Each account opens with its own master password; an
organization's items open with the password of any member whose account is in
the file. The page asks which account to open when there is more than one.

[`tools/snapshot.mjs`](tools/snapshot.mjs) turns `/api/sync` answers into
one and documents the format:

```json
{
  "format": "bitwarden-account-snapshot", "version": 2,
  "created": "…", "server": "…", "serverVersion": "…",
  "accounts": [{
    "id": "…", "salt": "you@example.com",
    "kdfType": 1, "kdfIterations": 6, "kdfMemory": 32, "kdfParallelism": 4,
    "userKey": "2.…", "privateKey": "2.…",
    "folders": [{ "id": "…", "name": "2.…" }],
    "ciphers": [{ "id": "…", "type": 1, "key": null, "name": "2.…", "login": { … } }]
  }],
  "organizations": [{
    "id": "…", "name": "Family",
    "keys": { "<account id>": "4.…" },
    "ciphers": [{ "id": "…", "type": 1, "key": null, "name": "2.…", "login": { … } }]
  }]
}
```

`salt`, the KDF and `userKey` come from `userDecryption.masterPasswordUnlock`
of each account's sync answer, `privateKey` and the organization keys from its
`profile`. Fetch it with a `Bitwarden-Client-Version` header: Vaultwarden
leaves SSH keys out for clients that do not announce a version that knows them.

Version 1, a single account with its personal vault at the top level (no
`accounts`, no `organizations`), still opens.

[demo]: https://tfohlmeister.github.io/bitwarden-emergency-viewer/

## Security model

The page is a single file with no external references and this policy:

```
default-src 'none'; style-src 'unsafe-inline'; script-src 'unsafe-inline';
img-src data:; form-action 'none'; base-uri 'none'
```

That means it cannot load anything, cannot send anything and cannot submit a
form, even if someone modified the copy you are holding. It contains no
`fetch`, no `XMLHttpRequest` and no WebSocket, and the test suite fails if any
of that changes.

The export arrives through a file picker rather than through code, because
browsers block `file://` pages from reading other files. That restriction is
what lets the page work without a single permission.

What it does **not** protect you from:

- **The machine you run it on.** A decrypted vault lives in that browser
  window's memory. On a borrowed or rented computer, assume anything you reveal
  or copy can be recovered. Close the window when you are done and clear the
  clipboard yourself.
- **A tampered copy.** Verify the file you are about to trust. The whole thing
  is one readable file for exactly this reason: `grep -c fetch vault.html` should
  print `0`, and the CSP line should be intact.

### The cryptography

Mirrors Bitwarden's own handling of a password-protected export:

```
kdfType 0   masterKey = PBKDF2-SHA256(password, salt-as-STRING, kdfIterations)
kdfType 1   masterKey = Argon2id(password, SHA-256(salt-as-STRING),
                                 t = kdfIterations, m = kdfMemory MiB,
                                 p = kdfParallelism, 32 bytes, version 0x13)

encKey = HKDF-Expand(masterKey, "enc")
macKey = HKDF-Expand(masterKey, "mac")
```

The entire vault is one `EncString` under `data`: AES-256-CBC with an
HMAC-SHA256 over `iv || ciphertext`. The MAC is verified **before** decrypting,
so a wrong password produces a clear error instead of plausible garbage.

An account snapshot derives the same master key, salted with the account's
salt (its email address), and uses it to unwrap the user key:

```
userKey = decrypt(userKey) under encKey/macKey     64 bytes: enc | mac
itemKey = decrypt(cipher.key) under userKey        where a cipher has one
```

An organization's items sit under the organization key, which reaches each
member wrapped with that member's RSA public key:

```
privateKey = decrypt(account.privateKey) under userKey    PKCS#8, RSA-2048
orgKey     = RSA-OAEP(SHA-1) decrypt of keys[account.id]   EncString type 4
itemKey    = decrypt(cipher.key) under orgKey              where a cipher has one
```

Every field of a cipher is its own `EncString` under the item key, or the user
key when there is none, except ids and record timestamps such as
`revisionDate`; a date the owner typed in, like a passport's expiry, is
encrypted too. The user key's MAC is the
password check. Entries are opened one at a time, so a damaged one is counted
and listed by name (where its name still opens) instead of costing the whole
vault; an organization whose key does not open is listed as one damaged row
with its size, and the rest still opens.

Two details are easy to get wrong and are worth naming: the base64 salt goes in
as the characters of the string, not as decoded bytes, and Argon2id hashes that
string with SHA-256 first while PBKDF2 does not.

WebCrypto provides PBKDF2, HKDF, AES, HMAC and RSA-OAEP. It has no Argon2 and no BLAKE2b,
so both are implemented in the file. Argon2id at Bitwarden's defaults (32 MiB,
6 passes) takes roughly 3 to 5 seconds in a current browser; the page shows
progress while it runs.

## Verifying it yourself

```bash
npm ci
npm test          # crypto, format and page-invariant checks
npm run test:e2e  # the real page in Chromium, Firefox and WebKit
```

The tests never import a copy of the cryptography. They lift the code out of
`vault.html` between its `CRYPTO-BEGIN` and `CRYPTO-END` markers and run that,
because a copy would keep passing while the page itself rotted.

Four layers, weakest claim first:

| Layer | What it rules out |
|---|---|
| RFC 9106 test vector | Argon2id is not Argon2id |
| Differential against [`@noble/hashes`][noble] | agreement with an independent implementation, across the parameter space |
| Fixtures built by Node's crypto and `@noble/hashes` | the page agreeing only with itself |
| **A real export and a real snapshot from a real Vaultwarden** | our reading of Bitwarden's format being wrong |

That last one is the one that counts. `tools/vaultwarden-fixture.mjs` starts a
throwaway Vaultwarden in Docker, registers an account with Argon2id, fills it
through the **official Bitwarden CLI**, lets that CLI write the export, and
takes a snapshot from the server's sync answers: of that account, of a second
one with PBKDF2, and of an organization both belong to, whose items the CLI
writes under the organization key it unwrapped itself. One entry with a key of
its own goes in through the API for each of them, because whether the CLI
writes item keys depends on what the server advertises. CI runs it on
every push and once a week, so a format change upstream shows up here instead
of during a recovery.

```bash
npm run fixture:vaultwarden   # needs Docker and openssl
```

BLAKE2b is checked against OpenSSL, and TOTP against the RFC 6238 vectors.

[noble]: https://github.com/paulmillr/noble-hashes

## Limits

- Password-protected exports (`"encrypted": true`, `"passwordProtected": true`)
  and account snapshots only. An account-key-encrypted export is tied to a
  vault you no longer have, which defeats the purpose; the snapshot carries
  its wrapped user key and does not have that problem.
- An export holds the personal vault only, as the CLI writes it. Organization
  items are in a version 2 snapshot only.
- JavaScript is required.
- Passkeys are listed by site and user name, so you know which login needs
  another way in. They cannot be used from this page, and their private keys
  are not shown.
- Only the item types Bitwarden currently defines are rendered. Anything else
  shows up in the list but has no fields.

## License

MIT. See [LICENSE](LICENSE).
