import { test } from "node:test";
import assert from "node:assert/strict";
import { build } from "esbuild";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";
import {
  resolveWireshark,
  wiresharkCandidates,
} from "../src/extension/wireshark";
import * as path from "node:path";
const nodeRequire = createRequire(import.meta.url);
async function loadConfigurationUI(remote = false) {
  const changes: any[] = [];
  const info: string[] = [];
  const inputs: any[] = [];
  const errors: any[] = [];
  const config = {
    inspect: () => ({ globalValue: "/not/installed/Wireshark" }),
    update: async (...args: any[]) => {
      changes.push(args);
    },
  };
  const mock = {
    env: { language: "zh-cn", remoteName: remote ? "ssh-remote" : undefined },
    ConfigurationTarget: { Global: 1 },
    workspace: { getConfiguration: () => config },
    window: {
      showQuickPick: async () => ({ id: "input" }),
      showInputBox: async (options: any) => {
        inputs.push(options);
        return process.execPath;
      },
      showInformationMessage: async (message: string) => {
        info.push(message);
      },
      showErrorMessage: async (...args: any[]) => {
        errors.push(args);
        return args[1];
      },
    },
  };
  const output = await build({
    entryPoints: ["src/extension/wireshark-ui.ts"],
    bundle: true,
    write: false,
    platform: "node",
    format: "cjs",
    external: ["vscode"],
  });
  const mod = { exports: {} as any };
  runInNewContext(output.outputFiles[0].text, {
    module: mod,
    exports: mod.exports,
    require: (name: string) => (name === "vscode" ? mock : nodeRequire(name)),
    process,
    console,
  });
  return { api: mod.exports, changes, info, inputs, errors };
}
test("Wireshark configuration validates and saves only to user settings; errors offer configuration", async () => {
  const ui = await loadConfigurationUI();
  await ui.api.configureWireshark();
  assert.equal(ui.changes.length, 1);
  assert.equal(ui.changes[0][0], "wiresharkPath");
  assert.equal(ui.changes[0][1], process.execPath);
  assert.equal(ui.changes[0][2], 1);
  assert.ok(ui.inputs[0].validateInput("/not/a/real/application"));
  assert.equal(ui.inputs[0].validateInput(process.execPath), undefined);
  await ui.api.reportWiresharkFailure(new Error("not installed"));
  assert.equal(ui.errors[0][1], "配置 Wireshark");
  assert.equal(ui.changes.length, 2);
});
test("remote configuration explains the boundary without editing remote executable settings", async () => {
  const ui = await loadConfigurationUI(true);
  await ui.api.configureWireshark();
  assert.equal(ui.changes.length, 0);
  assert.equal(ui.inputs.length, 0);
  assert.match(ui.info[0], /远程模式/);
});
test("Wireshark resolution accepts executables and macOS app bundles but rejects directories", () => {
  assert.equal(resolveWireshark(process.execPath), process.execPath);
  assert.throws(
    () => resolveWireshark(path.dirname(process.execPath)),
    /not found/,
  );
  assert.deepEqual(
    wiresharkCandidates("darwin", {}, "/Applications/My Wireshark.app"),
    ["/Applications/My Wireshark.app/Contents/MacOS/Wireshark"],
  );
});
