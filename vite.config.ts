// vitest/config re-exports Vite's defineConfig with the `test` field typed.
import { defineConfig } from 'vitest/config';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  server: {
    port: Number(process.env.PORT) || 3000,
    proxy: {
      '/keys': 'http://localhost:4000',
      '/api': 'http://localhost:4000',
    },
  },
  test: {
    // The signal module is pure TS with no DOM dependency.
    environment: 'node',
    include: ['src/**/*.test.ts'],
  },
});
