import { Worker } from "node:worker_threads";
import type { Capture } from "../core/model";
/** Cache the in-flight promise before any asynchronous IO to prevent duplicate workers. */
export class AnalysisSession {
  private pending?: Promise<Capture>;
  private readonly controller = new AbortController();
  constructor(
    private readonly load: (signal: AbortSignal) => Promise<Capture>,
  ) {}
  get(): Promise<Capture> {
    if (this.controller.signal.aborted)
      return Promise.reject(new Error("Analysis cancelled"));
    return (this.pending ??= Promise.resolve().then(() => {
      this.controller.signal.throwIfAborted();
      return this.load(this.controller.signal);
    }));
  }
  dispose(): void {
    this.controller.abort();
  }
}
export function analyzeInWorker(
  bytes: Uint8Array,
  filename: string,
  signal: AbortSignal,
  timeoutMs = 15_000,
): Promise<Capture> {
  signal.throwIfAborted();
  return new Promise((resolve, reject) => {
    const worker = new Worker(filename, {
      resourceLimits: { maxOldGenerationSizeMb: 256 },
    });
    let settled = false;
    const finish = (error?: Error, capture?: Capture) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      signal.removeEventListener("abort", abort);
      void worker.terminate();
      if (error) reject(error);
      else resolve(capture!);
    };
    const abort = () => finish(new Error("Analysis cancelled"));
    const timer = setTimeout(
      () => finish(new Error("Capture analysis exceeded 15 seconds")),
      timeoutMs,
    );
    signal.addEventListener("abort", abort, { once: true });
    worker.once("message", (result) => {
      if (result?.type === "capture") finish(undefined, result.capture);
      else
        finish(
          new Error(
            typeof result?.error === "string"
              ? result.error
              : "Invalid worker result",
          ),
        );
    });
    worker.once("error", (error) =>
      finish(error instanceof Error ? error : new Error(String(error))),
    );
    worker.once("exit", (code) =>
      finish(new Error(`Analysis worker exited without a result (${code})`)),
    );
    worker.postMessage(bytes);
  });
}
