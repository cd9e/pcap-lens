import { runTests } from "@vscode/test-electron";
import { resolve } from "node:path";
await runTests({
  extensionDevelopmentPath: resolve("."),
  extensionTestsPath: resolve("tests/extension-host.cjs"),
  vscodeExecutablePath: process.env.PCAP_LENS_VSCODE_PATH || undefined,
  version: process.env.PCAP_LENS_VSCODE_VERSION || "stable",
  reuseMachineInstall: false,
  launchArgs: [
    "--skip-welcome",
    "--skip-release-notes",
    "--disable-workspace-trust",
    "--disable-telemetry",
    "--disable-gpu",
  ],
});
