import type { Uri } from "vscode";
import { posix } from "node:path";

/** VS Code maps the active remote authority to file: URIs inside its remote host.
 * Do not reinterpret arbitrary vscode-remote: or virtual URIs as OS paths.
 */
export function assertCaptureLocation(
  scheme: string,
  remoteName: string | undefined,
  runsInWorkspaceHost: boolean,
): void {
  if (remoteName && !runsInWorkspaceHost) {
    throw new Error(
      "Install Pcap Lens in the SSH / remote workspace and reload the window.",
    );
  }
  if (scheme !== "file") {
    throw new Error(
      "Open a filesystem capture in its workspace extension host. Virtual files and other remote authorities are not supported.",
    );
  }
}

/** Preserve scheme and authority; URI paths always use forward slashes. */
export function bodyExportUri(uri: Uri): Uri {
  return uri.with({
    path: posix.join(posix.dirname(uri.path), "body.bin"),
    query: "",
    fragment: "",
  });
}
