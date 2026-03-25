import { defineConfig } from 'vitest/config'

export default defineConfig({
  test: {
    projects: [
      {
        test: {
          name: 'unit',
          include: ['src/**/*.test.ts'],
          exclude: ['src/adapters/**/*.test.ts'],
        },
      },
      {
        test: {
          name: 'adapter',
          include: ['tests/adapter/**/*.test.ts'],
          sequence: { concurrent: false },
        },
      },
      {
        test: {
          name: 'e2e',
          include: ['tests/e2e/**/*.test.ts'],
          pool: 'forks',
          poolOptions: { forks: { maxForks: 2 } },
        },
      },
    ],
  },
})
