// Loads the crypto out of vault.html instead of duplicating it. A copy would
// keep passing its tests forever while the page itself rotted.
import { readFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

export const VAULT_HTML = fileURLToPath(new URL("../vault.html", import.meta.url));

const EXPORTS = ["deriveKeys", "decrypt", "totp", "argon2id", "blake2b", "hPrime"];

export function readCryptoBlock(path = VAULT_HTML) {
  const html = readFileSync(path, "utf8");
  const found = html.match(/\/\/ CRYPTO-BEGIN([\s\S]*?)\/\/ CRYPTO-END/);
  if (!found) {
    throw new Error(`CRYPTO-BEGIN/CRYPTO-END markers missing from ${path}`);
  }
  return found[1];
}

export function loadCrypto(path = VAULT_HTML) {
  const source = `${readCryptoBlock(path)}\nexport { ${EXPORTS.join(", ")} };`;
  return import(`data:text/javascript,${encodeURIComponent(source)}`);
}
