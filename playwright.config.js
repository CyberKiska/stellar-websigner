import { defineConfig } from '@playwright/test';

const port = 4173;
const baseURL = `http://127.0.0.1:${port}`;
const disabledPort = 4174;

export default defineConfig({
  testDir: './tests/browser',
  fullyParallel: false,
  forbidOnly: Boolean(process.env.CI),
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? 'github' : 'list',
  use: {
    baseURL,
    trace: 'retain-on-failure',
  },
  webServer: [
    {
      command: 'npm run dev',
      env: {
        ...process.env,
        BUILD_MODE: 'bundle',
        BUILD_TARGET: 'standalone',
        BASE_PATH: '/',
        BUILD_VARIANT: 'browser-enabled',
        LOCAL_SECRET_POLICY: 'enabled',
        PORT: String(port),
      },
      url: baseURL,
      reuseExistingServer: false,
      timeout: 120_000,
    },
    {
      command: 'npm run dev',
      env: {
        ...process.env,
        BUILD_MODE: 'bundle',
        BUILD_TARGET: 'standalone',
        BASE_PATH: '/',
        BUILD_VARIANT: 'browser-disabled',
        LOCAL_SECRET_POLICY: 'disabled',
        PORT: String(disabledPort),
      },
      url: `http://127.0.0.1:${disabledPort}`,
      reuseExistingServer: false,
      timeout: 120_000,
    },
  ],
  projects: [
    { name: 'chromium', use: { browserName: 'chromium' } },
    { name: 'firefox', use: { browserName: 'firefox' } },
    { name: 'webkit', use: { browserName: 'webkit' } },
  ],
});
