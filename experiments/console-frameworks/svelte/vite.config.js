import { defineConfig } from "vite";
import { svelte } from "@sveltejs/vite-plugin-svelte";

// Fixed names (serve.mjs serves dist/app.js and dist/app.css), no source maps, and every style in
// the CSS file: the console's CSP allows no inline style or script.
export default defineConfig({
  plugins: [svelte({ compilerOptions: { css: "external" }, emitCss: true })],
  build: {
    sourcemap: false,
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    modulePreload: { polyfill: false },
    rollupOptions: {
      output: { entryFileNames: "app.js", chunkFileNames: "app-[name].js", assetFileNames: a => (a.names || [a.name]).some(n => /\.css$/.test(n)) ? "app.css" : "[name][extname]" },
    },
  },
});
