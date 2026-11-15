import { defineConfig } from "vite";
import react from "@vitejs/plugin-react";

// A static bundle the console could serve under its CSP: no inline script or style, relative asset
// paths (it is mounted under a path of the console's), no module preload polyfill (inline script).
export default defineConfig({
  base: "./",
  plugins: [react()],
  build: {
    outDir: "dist",
    emptyOutDir: true,
    modulePreload: { polyfill: false },
    assetsInlineLimit: 0,
    sourcemap: false,
  },
});
