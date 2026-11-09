import { test, expect } from "@playwright/test";
import { readFileSync, writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";

import {
  FIXTURE_PASSWORD, DEMO_PASSWORD, PBKDF2, SECOND_PASSWORD, buildExport,
} from "../tools/make-fixtures.mjs";

const path = (p) => fileURLToPath(new URL(p, import.meta.url));
const VAULT_HTML = path("../vault.html");

async function unlock(page, exportFile, password) {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(exportFile);
  await expect(page.locator("#drop")).toContainText("kB loaded");
  await page.locator("#pw").fill(password);
  await page.locator("#go").click();
  await expect(page.locator("#result")).toBeVisible();
}

test("opens a PBKDF2 export and lists every entry", async ({ page }) => {
  await unlock(page, path("fixtures/pbkdf2.json"), FIXTURE_PASSWORD);
  await expect(page.locator("#count")).toHaveText("6 entries");
  await expect(page.locator(".entry")).toHaveCount(6);
});

test("opens an Argon2id export", async ({ page }) => {
  await unlock(page, path("fixtures/argon2id.json"), FIXTURE_PASSWORD);
  await expect(page.locator("#count")).toHaveText("6 entries");
});

test("opens an Argon2id export at Bitwarden's own defaults", async ({ page }, testInfo) => {
  // 32 MiB and 6 passes, the settings a real vault produces. Deliberately not
  // mocked down: if pure-JS Argon2id ever becomes too slow to use on a borrowed
  // laptop, this is where it shows up.
  const started = Date.now();
  await unlock(page, path("../site/demo-vault.json"), DEMO_PASSWORD);
  const seconds = (Date.now() - started) / 1000;
  testInfo.annotations.push({ type: "unlock", description: `${seconds.toFixed(1)}s` });
  await expect(page.locator("#count")).toHaveText("6 entries");
  expect(seconds).toBeLessThan(120);
});

test("reports progress while deriving an Argon2id key", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("../site/demo-vault.json"));
  await page.locator("#pw").fill(DEMO_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toContainText(/%/);
  await expect(page.locator("#result")).toBeVisible();
});

test("rejects a wrong master password without revealing anything", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/pbkdf2.json"));
  await page.locator("#pw").fill("wrong-password");
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toHaveText("Wrong master password.");
  await expect(page.locator("#result")).toBeHidden();
  await expect(page.locator("#go")).toBeEnabled();
});

test("refuses a file that is not a password-protected export", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/vault.json"));
  await page.locator("#pw").fill("anything");
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toContainText("Not a password-protected export");
});

test("search narrows the list", async ({ page }) => {
  await unlock(page, path("fixtures/pbkdf2.json"), FIXTURE_PASSWORD);
  await page.locator("#q").fill("router");
  await expect(page.locator("#count")).toHaveText("1 of 6 entries");
  await expect(page.locator(".entry")).toHaveCount(1);

  // Searchable by username and by folder, not just by name.
  await page.locator("#q").fill("infrastructure");
  await expect(page.locator("#count")).toHaveText("2 of 6 entries");
});

test("hides passwords until they are revealed", async ({ page }) => {
  await unlock(page, path("fixtures/pbkdf2.json"), FIXTURE_PASSWORD);
  const entry = page.locator(".entry", { hasText: "Example Router" });
  await entry.locator("summary").click();

  const row = entry.locator("dl.f", { hasText: "Password" });
  await expect(row.locator("dd .val")).toHaveText("••••••••••");
  await row.locator("button.icon").click();
  await expect(row.locator("dd .val")).toHaveText("hunter2-but-longer");
});

test("computes a live TOTP code with a countdown", async ({ page }) => {
  await unlock(page, path("fixtures/pbkdf2.json"), FIXTURE_PASSWORD);
  const entry = page.locator(".entry", { hasText: "Example Mail" });
  await entry.locator("summary").click();

  const totp = entry.locator("dd.totp");
  await expect(totp.locator(".val")).toHaveText(/^\d{6}$/);
  await expect(totp.locator(".left")).toHaveText(/^\d{1,2}s left$/);
});

test("renders an SSH private key with its line breaks intact", async ({ page }) => {
  await unlock(page, path("fixtures/pbkdf2.json"), FIXTURE_PASSWORD);
  const entry = page.locator(".entry", { hasText: "Example SSH Key" });
  await entry.locator("summary").click();

  const row = entry.locator("dl.f", { hasText: "Private key" });
  await row.locator("button.icon").click();
  const value = row.locator("dd .val");
  await expect(value).toHaveClass(/note/);
  await expect(value).toContainText("BEGIN OPENSSH PRIVATE KEY");
});

test("renders a card that has nothing but a number", async ({ page }) => {
  await unlock(page, path("fixtures/pbkdf2.json"), FIXTURE_PASSWORD);
  const entry = page.locator(".entry", { hasText: "Example Card Without Expiry" });
  await entry.locator("summary").click();

  await expect(entry.locator("dl.f", { hasText: "Card" })).toBeVisible();
  await expect(entry.locator("dl.f", { hasText: "Expires" })).toHaveCount(0);
  await expect(entry.locator(".body")).not.toContainText("undefined");
});

test("tells a damaged export apart from a wrong password", async ({ page }) => {
  // The validation block opens, so the password is proven right and the failure
  // is the file. Reporting this as a wrong password would send someone retyping
  // a password that was correct all along.
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/damaged.json"));
  await page.locator("#pw").fill(FIXTURE_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toContainText("master password is correct");
  await expect(page.locator("#msg")).toContainText("damaged");
  await expect(page.locator("#result")).toBeHidden();
});

test("names the problem when the validation block is missing", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/no-validation.json"));
  await page.locator("#pw").fill(FIXTURE_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toContainText("no encKeyValidation block");
  await expect(page.locator("#msg")).not.toContainText("undefined");
});

test("opens an account snapshot, item keys and folders included", async ({ page }) => {
  await unlock(page, path("fixtures/snapshot-argon2id.json"), FIXTURE_PASSWORD);
  await expect(page.locator("#count")).toHaveText("6 entries");
  await page.locator("#q").fill("infrastructure");
  await expect(page.locator("#count")).toHaveText("2 of 6 entries");

  // Example Mail carries a key of its own in the fixture. The search renders
  // after a debounce, so wait for the full list before opening an entry in it.
  await page.locator("#q").fill("");
  await expect(page.locator("#count")).toHaveText("6 entries");
  const entry = page.locator(".entry", { hasText: "Example Mail" });
  await entry.locator("summary").click();
  await expect(entry.locator("dd.totp .val")).toHaveText(/^\d{6}$/);
  const row = entry.locator("dl.f", { hasText: "Password" });
  await row.locator("button.icon").click();
  await expect(row.locator("dd .val")).toHaveText("correct-horse-battery-staple");
});

test("rejects a wrong master password on a snapshot", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/snapshot-pbkdf2.json"));
  await page.locator("#pw").fill("wrong-password");
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toHaveText("Wrong master password.");
  await expect(page.locator("#result")).toBeHidden();
});

test("opens what is intact of a damaged snapshot and lists the damaged entry", async ({ page }) => {
  await unlock(page, path("fixtures/snapshot-damaged.json"), FIXTURE_PASSWORD);
  await expect(page.locator("#sub")).toContainText("5 entries");
  await expect(page.locator("#sub")).toContainText("1 could not be read");
  const damaged = page.locator(".entry", { hasText: "(damaged)" });
  await expect(damaged).toHaveCount(1);
  await damaged.locator("summary").click();
  await expect(damaged.locator(".body")).toContainText("Try another copy");
});

test("shows every field of the newer item types", async ({ page }) => {
  await unlock(page, path("fixtures/snapshot-newer-types.json"), FIXTURE_PASSWORD);
  const bank = page.locator(".entry", { hasText: "Example Bank Account" });
  await bank.locator("summary").click();
  await expect(bank.locator("dl.f", { hasText: "Bank Name" })).toContainText("Example Bank");
  const pin = bank.locator("dl.f", { hasText: "Pin" });
  await expect(pin.locator("dd .val")).toHaveText("••••••••••");
  await pin.locator("button.icon").click();
  await expect(pin.locator("dd .val")).toHaveText("4711");

  const passport = page.locator(".entry", { hasText: "Example Passport" });
  await passport.locator("summary").click();
  await expect(passport.locator("dl.f", { hasText: "Surname" })).toContainText("Lovelace");
});

for (const file of ["more-fields.json", "snapshot-more-fields.json"]) {
  test(`shows the 2FA key, passkeys, a linked field and the password history (${file})`, async ({ page }) => {
    await unlock(page, path(`fixtures/${file}`), FIXTURE_PASSWORD);
    const entry = page.locator(".entry", { hasText: "Example Server" });
    await entry.locator("summary").first().click();

    const key = entry.locator("dl.f", { hasText: "2FA key" });
    await key.locator("button.icon").click();
    await expect(key.locator("dd .val")).toContainText("secret=JBSWY3DPEHPK3PXP");
    await expect(entry.locator("dl.f", { hasText: "Passkey" })).toContainText("server.example.com · root");
    await expect(entry.locator("dl.f", { hasText: "Sudo password" })).toContainText("linked to Password");

    const history = entry.locator("details.history");
    await expect(history.locator("summary")).toHaveText("Password history (2)");
    await history.locator("summary").click();
    const older = history.locator("dl.f", { hasText: "2026-02-01" });
    await expect(older.locator("dd .val")).toHaveText("••••••••••");
    await older.locator("button.icon").click();
    await expect(older.locator("dd .val")).toHaveText("older-server-password");
  });
}

test("computes a Steam Guard code", async ({ page }) => {
  await unlock(page, path("fixtures/snapshot-more-fields.json"), FIXTURE_PASSWORD);
  const entry = page.locator(".entry", { hasText: "Example Steam" });
  await entry.locator("summary").click();
  await expect(entry.locator("dd.totp .val")).toHaveText(/^[23456789BCDFGHJKMNPQRTVWXY]{5}$/);
});

test("shows a card's brand and an identity's title and state", async ({ page }) => {
  await unlock(page, path("fixtures/snapshot-more-fields.json"), FIXTURE_PASSWORD);
  const card = page.locator(".entry", { hasText: "Example Branded Card" });
  await card.locator("summary").click();
  await expect(card.locator("dl.f", { hasText: "Brand" })).toContainText("Visa");

  const identity = page.locator(".entry", { hasText: "Example Titled Identity" });
  await identity.locator("summary").click();
  await expect(identity.locator("dl.f", { hasText: "Name" })).toContainText("Dr Ada Lovelace");
  await expect(identity.locator("dl.f", { hasText: "State" })).toContainText("Illinois");
});

test("finds an entry by the text of its notes", async ({ page }) => {
  await unlock(page, path("fixtures/snapshot-more-fields.json"), FIXTURE_PASSWORD);
  await page.locator("#q").fill("flowerpot");
  await expect(page.locator("#count")).toHaveText("1 of 5 entries");
  await expect(page.locator(".entry")).toHaveText(["Example Note"]);
});

test("lists every entry of a large vault, not a first page of it", async ({ page }, testInfo) => {
  const items = Array.from({ length: 450 }, (_, i) => ({
    id: `d0000000-0000-4000-8000-${String(i).padStart(12, "0")}`,
    type: 1, name: `Same Name ${i}`, login: { username: "admin" },
  }));
  const file = testInfo.outputPath("large.json");
  writeFileSync(file, JSON.stringify(buildExport({ folders: [], items }, FIXTURE_PASSWORD, PBKDF2)));
  await unlock(page, file, FIXTURE_PASSWORD);
  await expect(page.locator(".entry")).toHaveCount(450);
});

test("offers the accounts of a snapshot and opens the one chosen", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/snapshot-multi.json"));
  await expect(page.locator("#accounts")).toBeVisible();
  await expect(page.locator("#account option")).toHaveText([
    "ada@example.com (personal vault, Example Family, Example Club)",
    "grace@example.com (personal vault, Example Family)",
  ]);
  await page.locator("#account").selectOption("1");
  await page.locator("#pw").fill(SECOND_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#result")).toBeVisible();
  await expect(page.locator("#sub")).toContainText(
    "3 entries for grace@example.com: 1 personal, 2 in Example Family");

  const entry = page.locator(".entry", { hasText: "Family Streaming" });
  await entry.locator("summary").click();
  await expect(entry.locator("dl.f", { hasText: "Organization" })).toContainText("Example Family");
  const row = entry.locator("dl.f", { hasText: "Password" });
  await row.locator("button.icon").click();
  await expect(row.locator("dd .val")).toHaveText("family-streaming-password");

  await page.locator("#q").fill("example family");
  await expect(page.locator("#count")).toHaveText("2 of 3 entries");
});

test("takes the first account unless another is chosen", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/snapshot-multi.json"));
  await page.locator("#pw").fill(SECOND_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#msg")).toHaveText("Wrong master password.");

  await page.locator("#pw").fill(FIXTURE_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#sub")).toContainText(
    "9 entries for ada@example.com: 6 personal, 2 in Example Family, 1 in Example Club");
});

test("shows no account choice for a single-account snapshot", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/snapshot-pbkdf2.json"));
  await expect(page.locator("#drop")).toContainText("kB loaded");
  await expect(page.locator("#accounts")).toBeHidden();
});

test("lists an organization that does not open as damaged and opens the rest", async ({ page }) => {
  await page.goto(`file://${VAULT_HTML}`);
  await page.locator("#file").setInputFiles(path("fixtures/snapshot-multi-damaged-org.json"));
  await page.locator("#account").selectOption("1");
  await page.locator("#pw").fill(SECOND_PASSWORD);
  await page.locator("#go").click();
  await expect(page.locator("#sub")).toContainText("1 entry for grace@example.com: 1 personal");
  await expect(page.locator("#sub")).toContainText("1 could not be read");
  await expect(page.locator(".entry", { hasText: "(damaged)" }))
    .toContainText("Organization Example Family, all 2 entries");
});

test("lists the vault even when an entry carries something else than a list", async ({ page }, testInfo) => {
  const data = JSON.parse(readFileSync(path("fixtures/snapshot-pbkdf2.json"), "utf8"));
  data.ciphers.find((c) => c.login).login.uris = {};
  const file = testInfo.outputPath("odd-uris.json");
  writeFileSync(file, JSON.stringify(data));
  await unlock(page, file, FIXTURE_PASSWORD);
  await expect(page.locator("#count")).toHaveText("6 entries");
});

test("makes no network requests at any point", async ({ page }) => {
  const offSite = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("file://")) offSite.push(request.url());
  });
  await unlock(page, path("fixtures/argon2id.json"), FIXTURE_PASSWORD);
  await page.locator("#q").fill("example");
  expect(offSite).toEqual([]);
});
