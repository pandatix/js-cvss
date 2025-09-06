import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    globals: true,
    environment: 'node',
    include: ['tests/**/*.test.ts'],
    coverage: {
      provider: 'v8',
      exclude: ['tests/**', 'dist/**']
    }
  },
  esbuild: {
    target: 'es2020'
  }
})