// Fixed names (serve.mjs serves dist/app.js and dist/app.css), no source maps, no inline polyfill.
export default {
  build: {
    sourcemap: false,
    cssCodeSplit: false,
    modulePreload: { polyfill: false },
    rolldownOptions: { output: { entryFileNames: "app.js", chunkFileNames: "app-[name].js", assetFileNames: "app[extname]" } },
  },
};
