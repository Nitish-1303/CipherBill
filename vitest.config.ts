import { defineConfig } from "vitest/config";

export default defineConfig({
  test: {
    include: ["lib/**/*.test.ts", "lib/__tests__/**/*.test.ts"],
    testTimeout: 120_000,
  },
});
