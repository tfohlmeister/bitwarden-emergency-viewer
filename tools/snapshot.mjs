// Turns a server's /api/sync answer into an account snapshot, the second format
// vault.html opens. Nothing is decrypted here: the snapshot is the encrypted
// vault exactly as the server stores it, trimmed to the personal vault and to
// what opening it needs. That is the point of the format. Whoever produces it
// needs a login to the server, but never the master password.
//
// Format, version 1:
//   format, version              "bitwarden-account-snapshot", 1
//   created, server, serverVersion   where and when it was taken, informational
//   salt, kdfType, kdfIterations,
//   kdfMemory, kdfParallelism    the account's master-password KDF
//   userKey                      the user key, wrapped by the master key
//   folders                      [{ id, name }], name under the user key
//   ciphers                      the personal, non-deleted ciphers, every field
//                                an EncString under the cipher's key or the user key

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

export function snapshotFromSync(sync, { server, serverVersion, created = new Date().toISOString() }) {
  const unlock = sync.userDecryption?.masterPasswordUnlock;
  if (!unlock?.masterKeyWrappedUserKey || !unlock.salt || !unlock.kdf) {
    throw new Error("sync answer has no userDecryption.masterPasswordUnlock");
  }
  const pick = (cipher) => {
    const unknown = Object.keys(cipher).filter((k) => cipher[k] != null
      && !CIPHER_FIELDS.includes(k) && !IGNORED_FIELDS.includes(k));
    if (unknown.length) throw new Error(`cipher carries unknown fields: ${unknown.join(", ")}`);
    return Object.fromEntries(CIPHER_FIELDS.filter((k) => k in cipher).map((k) => [k, cipher[k]]));
  };
  return {
    format: "bitwarden-account-snapshot",
    version: 1,
    created,
    server,
    serverVersion,
    salt: unlock.salt,
    kdfType: unlock.kdf.kdfType,
    kdfIterations: unlock.kdf.iterations,
    kdfMemory: unlock.kdf.memory ?? null,
    kdfParallelism: unlock.kdf.parallelism ?? null,
    userKey: unlock.masterKeyWrappedUserKey,
    folders: (sync.folders || []).map(({ id, name }) => ({ id, name })),
    ciphers: (sync.ciphers || [])
      .filter((c) => !c.organizationId && !c.deletedDate)
      .map(pick),
  };
}
