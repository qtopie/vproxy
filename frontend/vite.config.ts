import { defineConfig } from 'vite';
import react from '@vitejs/plugin-react';

export default defineConfig({
  plugins: [react()],
  base: './',
  server: {
    port: 3000,
    proxy: {
      '/api': {
        target: 'http://127.0.0.1:8899',
        changeOrigin: true,
      },
    },
  },
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    minify: 'esbuild',
    cssMinify: true,
    sourcemap: false,
    chunkSizeWarningLimit: 500,
    rollupOptions: {
      output: {
        manualChunks(id) {
          if (id.includes('vite/preload-helper') || id.includes('vite/modulepreload-polyfill')) return 'vendor-react';
          if (!id.includes('node_modules')) return undefined;
          if (id.includes('monaco-editor') || id.includes('@monaco-editor')) return 'vendor-monaco';
          if (id.includes('@fluentui') || id.includes('@griffel') || id.includes('@floating-ui')) return 'vendor-fluent';
          if (id.includes('react')) return 'vendor-react';
          return undefined;
        },
      },
    },
  },
});
