# Security

## Reporting a vulnerability

Open a [private security advisory][advisory] on this repository. Please do not
open a public issue for anything that would let someone read a vault they should
not be able to read.

[advisory]: https://github.com/tfohlmeister/bitwarden-emergency-viewer/security/advisories/new

## What this tool guarantees

- It never opens a network connection. The page declares `default-src 'none'`
  and contains no `fetch`, `XMLHttpRequest` or WebSocket. The test suite fails
  if that stops being true.
- A wrong master password is refused before any decryption, by verifying the
  HMAC over the validation block.
- Nothing is written to disk, to `localStorage` or to a cookie. Closing the
  window ends the decrypted state.

## What it cannot guarantee

- **The machine.** The decrypted vault is in the browser's memory, and anything
  you reveal or copy can be recovered from that machine afterwards. Treat a
  borrowed computer as compromised, and clear the clipboard yourself.
- **The copy you are holding.** Nothing here can verify itself. Read the file,
  or compare it against a release from this repository, before trusting it with
  a master password.
- **Argon2id timing.** The key derivation runs in plain JavaScript on the main
  thread and is not constant-time. It is not intended to resist an attacker who
  is already running code on the same machine.
