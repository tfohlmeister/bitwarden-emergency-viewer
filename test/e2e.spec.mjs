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
  await expect(page.locator("#count")).toHaveText("5 entries");
  await expect(page.locator(".entry")).toHaveCount(5);
});

test("opens an Argon2id export", async ({ page }) => {
  await unlock(page, path("fixtures/argon2id.json"), FIXTURE_PASSWORD);
  await expect(page.locator("#count")).toHaveText("5 entries");
});

test("opens an Argon2id export at Bitwarden's own defaults", async ({ page }, testInfo) => {
  // 32 MiB and 6 passes, the settings a real vault produces. Deliberately not
  // mocked down: if pure-JS Argon2id ever becomes too slow to use on a borrowed
  // laptop, this is where it shows up.
  const started = Date.now();
  await unlock(page, path("../site/demo-vault.json"), DEMO_PASSWORD);
  const seconds = (Date.now() - started) / 1000;
  testInfo.annotations.push({ type: "unlock", description: `${seconds.toFixed(1)}s` });
  await expect(page.locator("#count")).toHaveText("5 entries");
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
  await expect(page.locator("#count")).toHaveText("1 of 5 entries");
  await expect(page.locator(".entry")).toHaveCount(1);

  // Searchable by username and by folder, not just by name.
  await page.locator("#q").fill("infrastructure");
  await expect(page.locator("#count")).toHaveText("2 of 5 entries");
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

test("makes no network requests at any point", async ({ page }) => {
  const offSite = [];
  page.on("request", (request) => {
    if (!request.url().startsWith("file://")) offSite.push(request.url());
  });
  await unlock(page, path("fixtures/argon2id.json"), FIXTURE_PASSWORD);
  await page.locator("#q").fill("example");
  expect(offSite).toEqual([]);
});
