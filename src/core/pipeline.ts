import type { Capture } from "./model";
export interface Analyzer {
  id: string;
  analyze(capture: Capture): void;
}
/** Ordered registration makes dependencies explicit. Extensions register after built-ins. */
export class AnalysisPipeline {
  private readonly analyzers: Analyzer[] = [];
  register(analyzer: Analyzer): this {
    if (this.analyzers.some((existing) => existing.id === analyzer.id))
      throw new Error(`Duplicate analyzer: ${analyzer.id}`);
    this.analyzers.push(analyzer);
    return this;
  }
  run(capture: Capture): Capture {
    for (const analyzer of this.analyzers) analyzer.analyze(capture);
    return capture;
  }
}
