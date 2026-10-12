import { constants } from "node:fs";
import { open } from "node:fs/promises";
import { LIMITS } from "../core/limits";
/** Inspect and read the same descriptor; never read devices, FIFOs, or a growing stream. */
export async function readLocalCapture(filename: string): Promise<Uint8Array> {
  const file = await open(
    filename,
    constants.O_RDONLY | (constants.O_NONBLOCK ?? 0),
  );
  try {
    const stat = await file.stat();
    if (!stat.isFile()) throw new Error("Capture must be a regular file");
    if (stat.size > LIMITS.captureBytes)
      throw new Error("Capture exceeds the 8 MB safety limit");
    const bytes = Buffer.alloc(stat.size + 1);
    let offset = 0;
    while (offset < bytes.length) {
      const { bytesRead } = await file.read(
        bytes,
        offset,
        bytes.length - offset,
        offset,
      );
      if (!bytesRead) break;
      offset += bytesRead;
    }
    if (offset > stat.size)
      throw new Error("Capture changed while being read; reopen the file");
    return bytes.subarray(0, offset);
  } finally {
    await file.close();
  }
}
