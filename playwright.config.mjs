import { defineConfig, devices } from "@playwright/test";

// The page is opened from file:// in the situation it exists for, so that is
// how it gets tested. No server, no build step, no fixtures beyond the files
// that ship.
export default defineConfig({
  testDir: "test",
  testMatch: "**/*.spec.mjs",
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: 0,
  reporter: process.env.CI ? "github" : "list",
  // Argon2id at Bitwarden's defaults takes seconds, and more on a loaded runner.
  timeout: 180_000,
  expect: { timeout: 60_000 },
  projects: [
    { name: "chromium", use: { ...devices["Desktop Chrome"] } },
    { name: "firefox", use: { ...devices["Desktop Firefox"] } },
    { name: "webkit", use: { ...devices["Desktop Safari"] } },
  ],
});
