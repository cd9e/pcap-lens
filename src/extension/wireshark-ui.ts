import * as vscode from "vscode";
import { resolveWireshark } from "./wireshark";
import { dictionary } from "../ui/i18n";
let configuring = false;
export async function configureWireshark(): Promise<void> {
  const t = dictionary(vscode.env.language);
  if (vscode.env.remoteName) {
    await vscode.window.showInformationMessage(t.remoteWireshark);
    return;
  }
  if (configuring) return;
  configuring = true;
  try {
    const configuration = vscode.workspace.getConfiguration("pcapLens");
    const current =
      configuration.inspect<string>("wiresharkPath")?.globalValue ?? "";
    const choice = await vscode.window.showQuickPick(
      [
        { label: t.chooseApplication, id: "browse" },
        { label: t.enterApplicationPath, id: "input" },
      ],
      { title: t.configureWireshark },
    );
    if (!choice) return;
    let selected: string | undefined;
    if (choice.id === "browse") {
      const files = await vscode.window.showOpenDialog({
        title: t.configureWireshark,
        openLabel: t.chooseApplication,
        canSelectFiles: true,
        canSelectFolders: process.platform === "darwin",
        canSelectMany: false,
        ...(process.platform === "win32"
          ? { filters: { Application: ["exe"] } }
          : {}),
      });
      if (!files?.length) return;
      if (files[0].scheme !== "file") throw new Error(t.invalidApplicationPath);
      selected = files[0].fsPath;
    } else {
      selected = await vscode.window.showInputBox({
        title: t.configureWireshark,
        prompt: t.applicationPathHint,
        value: current,
        ignoreFocusOut: true,
        validateInput: (value) => {
          try {
            resolveWireshark(value.trim() || "\0");
            return undefined;
          } catch {
            return t.invalidApplicationPath;
          }
        },
      });
    }
    if (selected === undefined) return;
    const executable = resolveWireshark(selected.trim() || "\0");
    await configuration.update(
      "wiresharkPath",
      executable,
      vscode.ConfigurationTarget.Global,
    );
    await vscode.window.showInformationMessage(
      `${t.applicationPathSaved}: ${executable}`,
    );
  } catch (error) {
    await vscode.window.showErrorMessage(
      `${t.invalidApplicationPath} ${String(error)}`,
    );
  } finally {
    configuring = false;
  }
}
export async function reportWiresharkFailure(error: unknown): Promise<void> {
  const t = dictionary(vscode.env.language);
  const action = await vscode.window.showErrorMessage(
    `${t.wiresharkFailed} ${String(error)}`,
    t.configureWireshark,
  );
  if (action === t.configureWireshark) await configureWireshark();
}
