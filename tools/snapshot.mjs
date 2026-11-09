// Turns a server's /api/sync answers into an account snapshot, the second format
// vault.html opens. Nothing is decrypted here: the snapshot is the encrypted
// vault exactly as the server stores it, trimmed to what opening it needs. That
// is the point of the format. Whoever produces it needs a login to the server,
// but never a master password.
//
// Format, version 2 (snapshotFromSyncs): several accounts and their organizations.
//   format, version              "bitwarden-account-snapshot", 2
//   created, server, serverVersion   where and when it was taken, informational
//   accounts                     [{ ... }], one per account, each opened with its
//                                own master password:
//     id                         the account's user id
//     salt, kdfType, kdfIterations,
//     kdfMemory, kdfParallelism  the account's master-password KDF
//     userKey                    the user key, wrapped by the master key
//     privateKey                 the account's RSA private key (PKCS#8) under the
//                                user key; null if the account has none
//     folders                    [{ id, name }], name under the user key
//     ciphers                    the personal, non-deleted ciphers, every field an
//                                EncString under the cipher's key or the user key
//   organizations                [{ ... }], one per organization any account is a
//                                confirmed member of:
//     id, name                   name in plain, as the server sends it
//     keys                       { <account id>: "4.…" }, the organization key
//                                wrapped with that member's RSA public key, for
//                                every account of the snapshot that is a member
//     ciphers                    the organization's non-deleted ciphers, every field
//                                an EncString under the cipher's key or the
//                                organization key; no folderId (folders are personal)
//
// Version 1 (snapshotFromSync) is one account at the top level, without
// privateKey and without organizations:
//   format, version, created, server, serverVersion,
//   salt, kdfType, kdfIterations, kdfMemory, kdfParallelism, userKey, folders, ciphers

export const CIPHER_FIELDS = [
  "id", "type", "folderId", "key", "name", "notes", "favorite", "reprompt",
  "login", "card", "identity", "secureNote", "sshKey", "bankAccount",
  "driversLicense", "passport", "fields", "passwordHistory",
  "creationDate", "revisionDate", "archivedDate",
];

// What the sync answer carries about a cipher that opening it does not need.
// Anything in neither list stops the snapshot: a field nobody knows about
// would otherwise be dropped without a trace.
export const IGNORED_FIELDS = [
  "object", "data", "attachments", "collectionIds", "organizationId", "organizationUseTotp",
  "edit", "viewPassword", "permissions", "deletedDate",
];

function pick(cipher, fields = CIPHER_FIELDS) {
  const unknown = Object.keys(cipher).filter((k) => cipher[k] != null
    && !CIPHER_FIELDS.includes(k) && !IGNORED_FIELDS.includes(k));
  if (unknown.length) throw new Error(`cipher carries unknown fields: ${unknown.join(", ")}`);
  return Object.fromEntries(fields.filter((k) => k in cipher).map((k) => [k, cipher[k]]));
}

const ORG_CIPHER_FIELDS = CIPHER_FIELDS.filter((k) => k !== "folderId");

function account(sync) {
  const unlock = sync.userDecryption?.masterPasswordUnlock;
  if (!unlock?.masterKeyWrappedUserKey || !unlock.salt || !unlock.kdf) {
    throw new Error("sync answer has no userDecryption.masterPasswordUnlock");
  }
  return {
    id: sync.profile?.id ?? null,
    salt: unlock.salt,
    kdfType: unlock.kdf.kdfType,
    kdfIterations: unlock.kdf.iterations,
    kdfMemory: unlock.kdf.memory ?? null,
    kdfParallelism: unlock.kdf.parallelism ?? null,
    userKey: unlock.masterKeyWrappedUserKey,
    privateKey: sync.profile?.privateKey ?? null,
    folders: (sync.folders || []).map(({ id, name }) => ({ id, name })),
    ciphers: (sync.ciphers || []).filter((c) => !c.organizationId && !c.deletedDate).map((c) => pick(c)),
  };
}

export function snapshotFromSync(sync, { server, serverVersion, created = new Date().toISOString() }) {
  const { id, privateKey, ...rest } = account(sync);
  return { format: "bitwarden-account-snapshot", version: 1, created, server, serverVersion, ...rest };
}

// Organization ciphers come from the first sync that holds them: every member
// sees the same ciphertext, and a later sync only adds what the earlier
// member's collections did not show.
export function snapshotFromSyncs(syncs, { server, serverVersion, created = new Date().toISOString() }) {
  const accounts = syncs.map(account);
  if (accounts.some((a) => !a.id)) throw new Error("sync answer has no profile.id");
  const organizations = new Map();
  for (const [i, sync] of syncs.entries()) {
    for (const o of sync.profile?.organizations || []) {
      if (!o.key) continue;   // invited or accepted, not yet confirmed
      if (!organizations.has(o.id)) organizations.set(o.id, { id: o.id, name: o.name, keys: {}, ciphers: new Map() });
      organizations.get(o.id).keys[accounts[i].id] = o.key;
    }
    for (const c of sync.ciphers || []) {
      if (!c.organizationId || c.deletedDate) continue;
      const org = organizations.get(c.organizationId);
      if (!org?.keys[accounts[i].id]) {
        throw new Error("sync answer carries an organization cipher without the organization's key");
      }
      if (!org.ciphers.has(c.id)) org.ciphers.set(c.id, pick(c, ORG_CIPHER_FIELDS));
    }
  }
  return {
    format: "bitwarden-account-snapshot",
    version: 2,
    created,
    server,
    serverVersion,
    accounts,
    organizations: [...organizations.values()].map((o) => ({ ...o, ciphers: [...o.ciphers.values()] })),
  };
}
