import { test, expect } from "@playwright/test";
import { fileURLToPath } from "node:url";

import { FIXTURE_PASSWORD, DEMO_PASSWORD } from "../tools/make-fixtures.mjs";

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

test("makes no network requests at any point", async ({ page }) => {
  const offSite = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("file://")) offSite.push(request.url());
  });
  await unlock(page, path("fixtures/argon2id.json"), FIXTURE_PASSWORD);
  await page.locator("#q").fill("example");
  expect(offSite).toEqual([]);
});
