import { accessSync, constants, statSync } from "node:fs";
import * as path from "node:path";
export function wiresharkCandidates(
  platform: NodeJS.Platform,
  env: NodeJS.ProcessEnv,
  configured: string,
): string[] {
  const paths = platform === "win32" ? path.win32 : path.posix;
  if (configured) {
    if (!paths.isAbsolute(configured) || configured.includes("\0"))
      throw new Error("Wireshark path must be absolute");
    return [
      platform === "darwin" && configured.toLowerCase().endsWith(".app")
        ? paths.join(configured, "Contents", "MacOS", "Wireshark")
        : configured,
    ];
  }
  if (platform === "win32")
    return [
      paths.join(
        env.ProgramFiles && paths.isAbsolute(env.ProgramFiles)
          ? env.ProgramFiles
          : "C:\\Program Files",
        "Wireshark",
        "Wireshark.exe",
      ),
    ];
  if (platform === "darwin")
    return ["/Applications/Wireshark.app/Contents/MacOS/Wireshark"];
  return (env.PATH || "/usr/bin:/usr/local/bin")
    .split(":")
    .filter((directory) => paths.isAbsolute(directory))
    .map((directory) => paths.join(directory, "wireshark"));
}
export function resolveWireshark(configured: string): string {
  const executable = wiresharkCandidates(
    process.platform,
    process.env,
    configured,
  ).find((candidate) => {
    try {
      if (!statSync(candidate).isFile()) return false;
      accessSync(candidate, constants.X_OK);
      return true;
    } catch {
      return false;
    }
  });
  if (!executable)
    throw new Error(
      "Wireshark was not found; configure pcapLens.wiresharkPath with an absolute executable path",
    );
  return executable;
}
