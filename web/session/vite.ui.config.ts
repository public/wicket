import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// The UI check (`npm run check:ui`): check/ui.ts with the real App, its components compiled for the
// browser as in the bundle, as one module that check/ui-run.mjs imports under jsdom.
export default defineConfig({
  plugins: [vue()],
  define: { 'process.env.NODE_ENV': '"production"' },
  build: {
    outDir: 'check-dist',
    emptyOutDir: false,
    minify: false,
    sourcemap: false,
    lib: { entry: 'check/ui.ts', formats: ['es'], fileName: () => 'ui.js' },
    rolldownOptions: { output: { codeSplitting: false } },
  },
});
