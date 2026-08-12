import { defineConfig } from '@playwright/test';

export default defineConfig({
  testDir: './tests',
  timeout: 30000,
  expect: {
    timeout: 5000
  },
  use: {
    baseURL: 'http://localhost:3456',
    extraHTTPHeaders: {
      'Content-Type': 'application/json'
    }
  },
  webServer: {
    command: 'npm start',
    url: 'http://localhost:3456/health',
    reuseExistingServer: !process.env.CI,
    timeout: 10000
  }
});
