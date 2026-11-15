import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// As the assistant-ui view's: a static bundle under the console's CSP, relative paths.
export default defineConfig({
  base: './',
  plugins: [vue()],
  build: { outDir: 'dist', emptyOutDir: true, modulePreload: { polyfill: false }, assetsInlineLimit: 0, sourcemap: false },
});
