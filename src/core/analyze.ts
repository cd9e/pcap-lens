import { readCapture } from "./capture";
import { decodePacket } from "./protocols";
import { buildFlows } from "./streams";
import { analyzeHttp } from "./http";
import { analyzeDns } from "./dns";
import { AnalysisPipeline } from "./pipeline";
import type { Capture } from "./model";
export function createDefaultPipeline(): AnalysisPipeline {
  return new AnalysisPipeline()
    .register({
      id: "network",
      analyze: (capture) => capture.packets.forEach(decodePacket),
    })
    .register({
      id: "flows",
      analyze: (capture) => {
        capture.flows = buildFlows(capture.packets);
      },
    })
    .register({
      id: "http",
      analyze: (capture) => {
        capture.http = analyzeHttp(capture.flows, capture.packets);
      },
    })
    .register({
      id: "dns",
      analyze: (capture) => {
        capture.dns = analyzeDns(capture.packets, capture.flows);
      },
    });
}
export function analyze(
  bytes: Uint8Array,
  pipeline = createDefaultPipeline(),
): Capture {
  const { format, packets } = readCapture(bytes);
  return pipeline.run({
    format,
    packets,
    flows: [],
    http: [],
    dns: [],
    diagnostics: [],
  });
}
