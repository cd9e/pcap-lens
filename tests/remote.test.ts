import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, mkdir, writeFile, rm } from "node:fs/promises";
import { tmpdir } from "node:os";
import * as path from "node:path";
import { createRequire } from "node:module";
import { runInNewContext } from "node:vm";
import { build } from "esbuild";
import type { Uri } from "vscode";
import {
  assertCaptureLocation,
  bodyExportUri,
} from "../src/extension/capture-location";
import { pcap, pcapng, tcp } from "./fixtures";

function uri(
  scheme: string,
  authority: string,
  uriPath: string,
  query = "",
  fragment = "",
): Uri {
  const result = {
    scheme,
    authority,
    path: uriPath,
    query,
    fragment,
    get fsPath() {
      return process.platform === "win32" && /^\/[A-Za-z]:/.test(this.path)
        ? this.path.slice(1).replaceAll("/", "\\")
        : this.path;
    },
    with(change: {
      scheme?: string;
      authority?: string;
      path?: string;
      query?: string;
      fragment?: string;
    }) {
      return uri(
        change.scheme ?? scheme,
        change.authority ?? authority,
        change.path ?? uriPath,
        change.query ?? query,
        change.fragment ?? fragment,
      );
    },
    toString() {
      return `${scheme}://${authority}${uriPath}`;
    },
  };
  return result as Uri;
}
const fileUri = (filename: string) =>
  uri(
    "file",
    "",
    process.platform === "win32"
      ? "/" + filename.replaceAll("\\", "/")
      : filename,
  );

test("workspace host accepts mapped SSH files and rejects wrong hosts / virtual URIs", () => {
  assert.doesNotThrow(() => assertCaptureLocation("file", "ssh-remote", true));
  assert.doesNotThrow(() => assertCaptureLocation("file", undefined, true));
  assert.throws(
    () => assertCaptureLocation("file", "ssh-remote", false),
    /Install Pcap Lens/,
  );
  for (const scheme of ["vscode-remote", "https", "git", "untitled"])
    assert.throws(
      () => assertCaptureLocation(scheme, "ssh-remote", true),
      /filesystem/,
    );
});

test("body export preserves remote authority and handles Windows URI paths", () => {
  const source = uri(
    "vscode-remote",
    "ssh-remote+server",
    "/home/user/流量 capture.pcap",
    "q",
    "f",
  );
  const target = bodyExportUri(source);
  assert.equal(target.scheme, source.scheme);
  assert.equal(target.authority, source.authority);
  assert.equal(target.path, "/home/user/body.bin");
  assert.equal(target.query, "");
  assert.equal(target.fragment, "");
  assert.equal(
    bodyExportUri(uri("file", "", "/C:/captures/test.pcap")).path,
    "/C:/captures/body.bin",
  );
});

test("simulated SSH host runs actual provider and Worker, exports remotely and blocks Wireshark", async () => {
  const root = await mkdtemp(path.join(tmpdir(), "pcap-lens-remote-"));
  const nodeRequire = createRequire(import.meta.url);
  const disposals: (() => void)[] = [];
  try {
    await mkdir(path.join(root, "dist"));
    await build({
      entryPoints: ["src/extension/worker.ts"],
      outfile: path.join(root, "dist", "worker.cjs"),
      bundle: true,
      platform: "node",
      format: "cjs",
    });
    const bundled = await build({
      entryPoints: ["src/extension/extension.ts"],
      bundle: true,
      platform: "node",
      format: "cjs",
      external: ["vscode"],
      write: false,
    });
    let provider: any;
    const saveDialogs: any[] = [];
    const writes: any[] = [];
    const notifications: string[] = [];
    const mock = {
      commands: { registerCommand: () => ({ dispose() {} }) },
      ExtensionKind: { UI: 1, Workspace: 2 },
      env: { remoteName: "ssh-remote", language: "zh-cn" },
      Uri: {
        joinPath: (u: Uri, ...parts: string[]) =>
          u.with({ path: path.posix.join(u.path, ...parts) }),
      },
      window: {
        registerCustomEditorProvider: (_id: string, p: any) => {
          provider = p;
          return { dispose() {} };
        },
        showSaveDialog: async (options: any) => {
          saveDialogs.push(options);
          return options.defaultUri;
        },
        showInformationMessage: (text: string) => notifications.push(text),
      },
      workspace: {
        fs: {
          writeFile: async (u: Uri, bytes: Uint8Array) =>
            writes.push({ uri: u, bytes }),
        },
        getConfiguration: () => {
          throw new Error("Remote mode must not resolve a desktop executable");
        },
      },
    };
    const mod = { exports: {} as any };
    runInNewContext(bundled.outputFiles[0].text, {
      module: mod,
      exports: mod.exports,
      require: (name: string) => (name === "vscode" ? mock : nodeRequire(name)),
      process,
      Buffer,
      console,
      setTimeout,
      clearTimeout,
      AbortController,
    });
    mod.exports.activate({
      subscriptions: [],
      extensionPath: root,
      extensionUri: fileUri(root),
      extension: { extensionKind: 2 },
    });
    const packets = [
      tcp("GET /ssh HTTP/1.1\r\nHost: remote\r\n\r\n"),
      tcp("HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nok", 500, true),
    ];
    for (const [extension, content] of [
      ["pcap", pcap(packets)],
      ["pcapng", pcapng(packets)],
    ] as const) {
      const capturePath = path.join(root, `远程 capture.${extension}`);
      await writeFile(capturePath, content);
      const messages: any[] = [];
      let receive: (m: any) => Promise<void> = async () => {};
      const panel = {
        webview: {
          options: {},
          html: "",
          asWebviewUri: (u: Uri) => u.toString(),
          postMessage: async (m: any) => {
            messages.push(m);
            return true;
          },
          onDidReceiveMessage: (handler: any) => {
            receive = handler;
          },
        },
        onDidDispose: (handler: () => void) => disposals.push(handler),
      };
      await provider.resolveCustomEditor({ uri: fileUri(capturePath) }, panel);
      await receive({ type: "ready" });
      assert.equal(
        messages.find((m) => m.type === "init").remoteName,
        "ssh-remote",
      );
      assert.equal(
        messages.find((m) => m.type === "init").canOpenWireshark,
        false,
      );
      assert.ok(
        !messages.some((m) => m.type === "error"),
        JSON.stringify(messages.filter((m) => m.type === "error")),
      );
      const capture = messages.find((m) => m.type === "capture").capture;
      assert.equal(capture.http[0].request.url, "/ssh");
      assert.equal(capture.http[0].response.status, 200);
      await receive({
        type: "export",
        id: capture.http[0].id,
        side: "response",
      });
      assert.equal(
        saveDialogs.at(-1).defaultUri.fsPath,
        path.join(root, "body.bin"),
      );
      assert.equal(Buffer.from(writes.at(-1).bytes).toString(), "ok");
      await receive({ type: "wireshark" });
      assert.match(notifications.at(-1)!, /远程模式/);
    }
  } finally {
    disposals.forEach((dispose) => dispose());
    await rm(root, { recursive: true, force: true });
  }
});
