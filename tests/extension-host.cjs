const assert = require("node:assert/strict");
const path = require("node:path");
const vscode = require("vscode");
exports.run = async function () {
  const root = path.resolve(__dirname, "..");
  const extension = vscode.extensions.getExtension(
    `${require("../package.json").publisher}.${require("../package.json").name}`,
  );
  assert.ok(extension, "Extension is discoverable");
  await extension.activate();
  assert.ok(extension.isActive, "Extension activates");
  assert.deepEqual(extension.packageJSON.extensionKind, ["workspace"]);
  // extensionKind describes actual placement: a standalone local window may
  // report UI even though the manifest requires the remote workspace host.
  if (vscode.env.remoteName)
    assert.equal(extension.extensionKind, vscode.ExtensionKind.Workspace);
  assert.ok(
    (await vscode.commands.getCommands(true)).includes(
      "pcapLens.configureWireshark",
    ),
  );
  for (const filename of ["demo.pcap", "demo.pcapng"]) {
    const uri = vscode.Uri.file(path.join(root, "fixtures", filename));
    await vscode.commands.executeCommand("vscode.open", uri);
    const tab = vscode.window.tabGroups.activeTabGroup.activeTab;
    assert.ok(
      tab.input instanceof vscode.TabInputCustom,
      "Click/open chooses custom editor",
    );
    assert.equal(tab.input.viewType, "pcapLens.capture");
    assert.equal(tab.input.uri.fsPath, uri.fsPath);
  }
  await vscode.commands.executeCommand("workbench.action.closeAllEditors");
  console.log(
    "Extension Host smoke passed: activation and default pcap/pcapng custom editors.",
  );
};
