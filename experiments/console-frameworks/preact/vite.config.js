import { defineConfig } from "vite";

// JSX through Vite's own transform (Oxc), with Preact's automatic runtime: no Babel, no preset.
export default defineConfig({
  oxc: { jsx: { runtime: "automatic", importSource: "preact" } },
  build: {
    sourcemap: false,
    modulePreload: false,
    assetsInlineLimit: 0,
    rolldownOptions: {
      output: { entryFileNames: "app.js", chunkFileNames: "app-[name].js", assetFileNames: "app[extname]" },
    },
  },
});
