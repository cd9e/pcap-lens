import { readFileSync } from "node:fs";
import { spawnSync } from "node:child_process";
const manifest = JSON.parse(readFileSync("package.json", "utf8"));
if (!manifest.publisher || ["pcap-lens-local", "packet-lens-local"].includes(manifest.publisher)) {
  console.error(
    "Set package.json publisher to your real Marketplace publisher ID first.",
  );
  process.exit(1);
}
const result = spawnSync(
  process.execPath,
  [
    "node_modules/@vscode/vsce/vsce",
    "package",
    "--no-dependencies",
    "--allow-missing-repository",
    "--readme-path",
    "docs/MARKETPLACE.md",
    "--out",
    `${manifest.name}-${manifest.version}-marketplace.vsix`,
  ],
  { stdio: "inherit", shell: false },
);
if (result.error) throw result.error;
process.exit(result.status ?? 1);
