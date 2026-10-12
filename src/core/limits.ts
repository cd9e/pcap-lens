/** Shared bounds keep attacker-controlled captures within the desktop viewer's budget. */
export const LIMITS = Object.freeze({
  captureBytes: 8 * 1024 * 1024,
  packets: 20_000,
  interfaces: 1024,
  httpMessages: 2000,
  httpHeaderBytes: 64 * 1024,
  httpHeaders: 128,
  bodyBytes: 4 * 1024 * 1024,
  totalBodyBytes: 8 * 1024 * 1024,
  filterCharacters: 4096,
  filterTokens: 512,
  filterDepth: 32,
});
export class AnalysisBudget {
  private messages = 0;
  private bodyBytes = 0;
  get remainingBodyBytes(): number {
    return LIMITS.totalBodyBytes - this.bodyBytes;
  }
  reserveMessage(): void {
    if (++this.messages > LIMITS.httpMessages)
      throw new Error("HTTP message count exceeds analysis limit");
  }
  retainBody(size: number): void {
    if (size > LIMITS.bodyBytes || size > this.remainingBodyBytes)
      throw new Error("HTTP body data exceeds analysis limit");
    this.bodyBytes += size;
  }
}
