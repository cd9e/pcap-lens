interface SavedState {
  tab?: "http" | "flows" | "packets" | "dns" | "stats";
  selection?: Record<string, string>;
  filter?: string;
  scroll?: Record<string, number>;
}
declare function acquireVsCodeApi(): {
  postMessage(message: unknown): void;
  getState(): SavedState | undefined;
  setState(state: SavedState): void;
};
export const vscode = acquireVsCodeApi();
