import * as vscode from "vscode";
import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import * as path from "node:path";
import type { Capture } from "../core/model";
import { readLocalCapture } from "./local-file";
import { AnalysisSession, analyzeInWorker } from "./analysis-session";
import { resolveWireshark } from "./wireshark";
import { assertCaptureLocation, bodyExportUri } from "./capture-location";
import { configureWireshark, reportWiresharkFailure } from "./wireshark-ui";
import { dictionary } from "../ui/i18n";
export function activate(context: vscode.ExtensionContext) {
  context.subscriptions.push(
    vscode.commands.registerCommand(
      "pcapLens.configureWireshark",
      configureWireshark,
    ),
  );
  context.subscriptions.push(
    vscode.window.registerCustomEditorProvider(
      "pcapLens.capture",
      {
        openCustomDocument(uri: vscode.Uri) {
          return { uri, dispose() {} };
        },
        async resolveCustomEditor(
          document: vscode.CustomDocument,
          panel: vscode.WebviewPanel,
        ) {
          const remoteName = vscode.env.remoteName;
          const canOpenWireshark = !remoteName;
          panel.webview.options = {
            enableScripts: true,
            localResourceRoots: [
              vscode.Uri.joinPath(context.extensionUri, "dist", "webview"),
            ],
          };
          const nonce = randomBytes(16).toString("hex");
          const resource = (f: string) =>
            panel.webview.asWebviewUri(
              vscode.Uri.joinPath(context.extensionUri, "dist", "webview", f),
            );
          panel.webview.html = `<!doctype html><html><head><meta charset="UTF-8"><meta name="viewport" content="width=device-width,initial-scale=1"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; style-src ${panel.webview.cspSource}; script-src 'nonce-${nonce}'; img-src ${panel.webview.cspSource};"><link rel="stylesheet" href="${resource("style.css")}"></head><body><div id="root"></div><script nonce="${nonce}" src="${resource("main.js")}"></script></body></html>`;
          let capture: Capture | undefined;
          let disposed = false,
            initializing = false,
            exporting = false;
          let lastLaunch = 0;
          const session = new AnalysisSession(async (signal) => {
            assertCaptureLocation(
              document.uri.scheme,
              remoteName,
              context.extension.extensionKind ===
                vscode.ExtensionKind.Workspace,
            );
            const bytes = await readLocalCapture(document.uri.fsPath);
            signal.throwIfAborted();
            return analyzeInWorker(
              bytes,
              path.join(context.extensionPath, "dist", "worker.cjs"),
              signal,
            );
          });
          panel.onDidDispose(() => {
            disposed = true;
            session.dispose();
          });
          panel.webview.onDidReceiveMessage(async (message) => {
            if (disposed || !message || typeof message !== "object") return;
            try {
              if (message?.type === "ready") {
                if (initializing) return;
                initializing = true;
                try {
                  await panel.webview.postMessage({
                    type: "init",
                    language: vscode.env.language,
                    remoteName,
                    canOpenWireshark,
                    name: path.basename(document.uri.fsPath),
                  });
                  capture = await session.get();
                  if (!disposed)
                    await panel.webview.postMessage({
                      type: "capture",
                      capture,
                    });
                } finally {
                  initializing = false;
                }
              } else if (message?.type === "configureWireshark") {
                await configureWireshark();
              } else if (message?.type === "wireshark") {
                if (!canOpenWireshark) {
                  void vscode.window.showInformationMessage(
                    dictionary(vscode.env.language).remoteWireshark,
                  );
                  return;
                }
                if (
                  document.uri.scheme !== "file" ||
                  Date.now() - lastLaunch < 1000
                )
                  return;
                lastLaunch = Date.now();
                // Workspace settings must never select an executable to run.
                const configured =
                  vscode.workspace
                    .getConfiguration("pcapLens")
                    .inspect<string>("wiresharkPath")?.globalValue ?? "";
                try {
                  const executable = resolveWireshark(configured);
                  const child = spawn(executable, ["-r", document.uri.fsPath], {
                    shell: false,
                    cwd: path.dirname(process.execPath),
                    detached: true,
                    stdio: "ignore",
                  });
                  let reported = false;
                  const reportOnce = (error: unknown) => {
                    if (!reported && !disposed) {
                      reported = true;
                      void reportWiresharkFailure(error);
                    }
                  };
                  child.on("error", reportOnce);
                  child.on("exit", (code) => {
                    if (code !== null && code !== 0)
                      reportOnce(new Error(`Wireshark exit code: ${code}`));
                  });
                  child.unref();
                } catch (error) {
                  await reportWiresharkFailure(error);
                }
              } else if (message?.type === "export" && capture) {
                if (
                  exporting ||
                  typeof message.id !== "string" ||
                  !["request", "response"].includes(message.side)
                )
                  return;
                const exchange = capture.http.find((x) => x.id === message.id);
                const body =
                  message.side === "request"
                    ? exchange?.request?.body
                    : message.side === "response"
                      ? exchange?.response?.body
                      : undefined;
                if (!body) return;
                exporting = true;
                try {
                  const uri = await vscode.window.showSaveDialog({
                    defaultUri: bodyExportUri(document.uri),
                  });
                  if (uri && !disposed)
                    await vscode.workspace.fs.writeFile(
                      uri,
                      Uint8Array.from(body),
                    );
                } finally {
                  exporting = false;
                }
              }
            } catch (error) {
              if (!disposed)
                void panel.webview.postMessage({
                  type: "error",
                  error: String(error),
                });
            }
          });
        },
      },
      {
        webviewOptions: { retainContextWhenHidden: true },
        supportsMultipleEditorsPerDocument: false,
      },
    ),
  );
}
