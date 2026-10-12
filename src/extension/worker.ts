import { parentPort } from "node:worker_threads";
import { analyze } from "../core/analyze";
parentPort!.on("message", (bytes: Uint8Array) => {
  try {
    parentPort!.postMessage({ type: "capture", capture: analyze(bytes) });
  } catch (error) {
    parentPort!.postMessage({ type: "error", error: String(error) });
  }
});
