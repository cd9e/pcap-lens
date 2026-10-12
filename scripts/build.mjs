import { build } from "esbuild";
import { build as viteBuild } from "vite";
await build({
  entryPoints: {
    extension: "src/extension/extension.ts",
    worker: "src/extension/worker.ts",
  },
  bundle: true,
  platform: "node",
  format: "cjs",
  target: "node20",
  external: ["vscode"],
  outdir: "dist",
  outExtension: { ".js": ".cjs" },
  sourcemap: true,
});
await viteBuild();
