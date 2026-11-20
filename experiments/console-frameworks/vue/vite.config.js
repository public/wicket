import { defineConfig } from "vite";
import vue from "@vitejs/plugin-vue";

// One script and one stylesheet with fixed names (serve.mjs serves dist/app.js and dist/app.css), no
// source maps, and Vue's runtime-only build: templates are compiled here, so nothing needs eval.
export default defineConfig({
  plugins: [vue()],
  build: {
    sourcemap: false,
    modulePreload: false,
    cssCodeSplit: false,
    assetsInlineLimit: 0,
    rollupOptions: {
      output: { entryFileNames: "app.js", chunkFileNames: "app-[name].js", assetFileNames: a => (a.names || [a.name]).some(n => n && n.endsWith(".css")) ? "app.css" : "[name][extname]" },
    },
  },
  define: { __VUE_OPTIONS_API__: "false", __VUE_PROD_DEVTOOLS__: "false", __VUE_PROD_HYDRATION_MISMATCH_DETAILS__: "false" },
});
