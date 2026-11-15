import { defineConfig } from 'vite';
import vue from '@vitejs/plugin-vue';

// The console's session view (#327), built in CI and embedded in the wicket binary
// (crates/wicket-cli/build.rs). One script and one stylesheet with fixed names: the binary names them
// by content hash and serves them with Subresource Integrity under the console's CSP (no inline
// script or style, no eval). No source maps, no code splitting, nothing inlined.
export default defineConfig(({ isSsrBuild }) => ({
  base: '/static/',
  plugins: [vue()],
  build: {
    outDir: 'dist',
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
    cssCodeSplit: false,
    // The node check (`npm run check:build`, an SSR build of check/check.ts) keeps its own name.
    rolldownOptions: isSsrBuild ? {} : {
      output: {
        entryFileNames: 'session.js',
        chunkFileNames: 'session-[name].js',
        assetFileNames: 'session[extname]',
        codeSplitting: false,
      },
    },
  },
}));
