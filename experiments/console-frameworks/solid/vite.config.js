import { defineConfig } from "vite";
import solid from "vite-plugin-solid";

// Fixed names (serve.mjs serves dist/app.js and dist/app.css), no source maps, no inline anything.
export default defineConfig({
  plugins: [solid()],
  build: {
    target: "es2022",
    sourcemap: false,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    rolldownOptions: {
      output: {
        entryFileNames: "app.js",
        chunkFileNames: "app-[name].js",
        assetFileNames: a => (a.names || []).some(n => n.endsWith(".css")) ? "app.css" : "[name][extname]",
      },
    },
  },
});
