import { defineConfig } from "vite";
export default defineConfig({
  define: { "process.env.NODE_ENV": JSON.stringify("production") },
  build: {
    outDir: "dist/webview",
    emptyOutDir: true,
    lib: {
      entry: "src/ui/main.tsx",
      formats: ["iife"],
      name: "PcapLens",
      cssFileName: "style",
      fileName: () => "main.js",
    },
    cssCodeSplit: false,
    rollupOptions: { output: { assetFileNames: "[name][extname]" } },
  },
});
