import type { Packet, Flow, Chunk } from "./model";
const endpoint = (p: Packet, source: boolean) =>
  `[${source ? p.src : p.dst}]:${source ? p.srcPort : p.dstPort}`;
/** Signed modular difference keeps sequence wraparound local to each connection. */
const relative = (seq: number, base: number) => (seq - base) | 0;
export function buildFlows(packets: Packet[]): Flow[] {
  const flows: Flow[] = [];
  const active = new Map<string, Flow>();
  for (const p of packets) {
    if (!p.transport || p.srcPort === undefined) continue;
    const a = endpoint(p, true),
      b = endpoint(p, false),
      key = [p.transport, ...[a, b].sort()].join("|");
    let f = active.get(key);
    const initialSyn =
      p.transport === "TCP" && !!(p.flags! & 2) && !(p.flags! & 16);
    if (f && initialSyn) {
      const prev = packets[f.packetIds[0] - 1];
      if (
        prev.seq !== p.seq ||
        f.packetIds.some((id) => packets[id - 1].flags! & 5)
      )
        f = undefined;
    }
    if (!f) {
      f = {
        id: String(flows.length + 1),
        transport: p.transport,
        endpoints: [a, b],
        packetIds: [],
        chunks: [],
        diagnostics: [],
      };
      flows.push(f);
      active.set(key, f);
    }
    f.packetIds.push(p.id);
    p.flowId = f.id;
  }
  for (const f of flows) {
    if (f.transport !== "TCP") continue;
    for (const direction of [0, 1] as const) {
      const side = f.packetIds
        .map((id) => packets[id - 1])
        .filter((p) => endpoint(p, true) === f.endpoints[direction]);
      if (!side.length) continue;
      if (!side.some((p) => p.flags! & 2))
        f.diagnostics.push({
          code: "tcp.midstream",
          evidence: f.endpoints[direction],
        });
      const first = side[0];
      const base = (first.seq! + (first.flags! & 2 ? 1 : 0)) >>> 0;
      let high: number | undefined;
      const segments: { p: Packet; start: number; bytes: number[] }[] = [];
      for (const p of side) {
        if (p.flags! & 4)
          p.diagnostics.push({
            code: "tcp.reset",
            evidence: `RST; seq=${p.seq}`,
          });
        if (!p.payloadLength) continue;
        const start = relative((p.seq! + (p.flags! & 2 ? 1 : 0)) >>> 0, base),
          bytes = p.bytes.slice(
            p.payloadOffset!,
            p.payloadOffset! + p.payloadLength,
          );
        if (high !== undefined && start < high)
          p.diagnostics.push({
            code: "tcp.overlap",
            evidence: `seq=${p.seq}; ${Math.min(high - start, bytes.length)} overlapping bytes (retransmission/out-of-order suspected)`,
          });
        if (high !== undefined && start > high)
          p.diagnostics.push({
            code: "tcp.outOfOrder",
            evidence: `${start - high} bytes not yet observed`,
          });
        high = Math.max(high ?? start, start + bytes.length);
        segments.push({ p, start, bytes });
      }
      segments.sort((a, b) => a.start - b.start || a.p.id - b.p.id);
      let cursor: number | undefined, chunk: Chunk | undefined;
      const closed = side.some((p) => p.flags! & 1);
      for (const s of segments) {
        if (cursor === undefined || s.start > cursor) {
          const gap = cursor === undefined ? 0 : s.start - cursor;
          chunk = {
            direction,
            spans: [],
            bytes: [],
            packetIds: [],
            time: s.p.time,
            gapBefore: gap,
            closed: false,
          };
          f.chunks.push(chunk);
          if (gap)
            f.diagnostics.push({
              code: "tcp.gap",
              evidence: `${gap} bytes missing before packet ${s.p.id}`,
            });
          cursor = s.start;
        }
        const skip = Math.max(0, cursor! - s.start);
        if (skip < s.bytes.length) {
          chunk!.spans.push({
            start: chunk!.bytes.length,
            length: s.bytes.length - skip,
            packetId: s.p.id,
            packetOffset: s.p.payloadOffset! + skip,
          });
          for (const byte of s.bytes.slice(skip)) chunk!.bytes.push(byte);
          chunk!.packetIds.push(s.p.id);
          cursor = s.start + s.bytes.length;
        }
      }
      if (chunk) chunk.closed = closed;
    }
    f.chunks.sort((a, b) => a.time - b.time);
    f.diagnostics.push(
      ...f.packetIds.flatMap((id) =>
        packets[id - 1].diagnostics.filter((x) => x.code.startsWith("tcp.")),
      ),
    );
  }
  return flows;
}
