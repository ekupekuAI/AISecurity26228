import tailwindcss from '@tailwindcss/vite';
import react from '@vitejs/plugin-react';
import path from 'node:path';
import { defineConfig } from 'vite';

export default defineConfig({
  plugins: [react(), tailwindcss()],

  resolve: {
    alias: { '@': path.resolve(__dirname, '.') },
  },

  server: {
    hmr: process.env.DISABLE_HMR !== 'true',
    // Permit reaching the dev server through a tunnel for shared team testing. Leading-dot
    // entries match any subdomain; AIA_ALLOWED_HOSTS (comma-separated) adds a custom tunnel
    // or domain without editing this file. Dev-only: a production build is served by the
    // gateway from dist/, which has no host check. Vite's default block is a dev-only
    // DNS-rebinding guard, not a production control.
    allowedHosts: [
      'localhost',
      '.trycloudflare.com',
      '.ngrok-free.app',
      '.ngrok-free.dev',
      '.ngrok.app',
      '.ngrok.io',
      '.loca.lt',
      ...(process.env.AIA_ALLOWED_HOSTS?.split(',').map((h) => h.trim()).filter(Boolean) ?? []),
    ],
    watch: {
      /*
       * The dev server runs as Express middleware in the same process that owns the
       * SQLite database, and SQLite writes its WAL on essentially every request --
       * including the session touch that each authenticated request performs.
       *
       * Without these exclusions Vite sees those writes as source changes, issues a full
       * page reload, the reloaded page calls the API, that call writes the WAL again, and
       * the console reload-loops until it never finishes rendering. Nothing under these
       * paths is ever imported by the browser bundle.
       */
      ignored: [
        '**/data/**',
        '**/dist/**',
        '**/ml-engine/**',
        '**/demo-assets/**',
        '**/node_modules/**',
        '**/.git/**',
        '**/*.db',
        '**/*.db-wal',
        '**/*.db-shm',
        '**/*.log',
      ],
    },
  },

  build: {
    outDir: 'dist',
    // Fail the build rather than silently shipping an inlined asset that would violate
    // the strict CSP at runtime.
    assetsInlineLimit: 0,
    sourcemap: false,
    rollupOptions: {
      output: {
        // Split the heavy vendor libraries out of the app chunk so a code change does not
        // invalidate 1 MB of unchanged dependency bytes in the browser cache.
        manualChunks(id: string) {
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('recharts') || id.includes('d3-')) return 'charts';
          if (id.includes('motion') || id.includes('framer')) return 'motion';
          if (id.includes('react-dom') || id.includes('/react/') || id.includes('scheduler')) {
            return 'react';
          }
          return 'vendor';
        },
      },
    },
  },
});
