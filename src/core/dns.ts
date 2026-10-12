import { LIMITS } from "./limits";
import type { Packet, Flow, DnsMessage, DnsExchange } from "./model";
function parse(bytes: number[], ids: number[], time: number): DnsMessage {
  const b = Buffer.from(bytes);
  const need = (o: number, n: number) => {
    if (o < 0 || o + n > b.length) throw new Error("Truncated DNS");
  };
  const u16 = (o: number) => {
    need(o, 2);
    return b.readUInt16BE(o);
  };
  need(0, 12);
  const name = (start: number): [string, number] => {
    let o = start,
      next = 0;
    const parts: string[] = [];
    let expandedLength = 1;
    const seen = new Set<number>();
    while (true) {
      need(o, 1);
      if (seen.has(o) || seen.size > 128) throw new Error("DNS pointer cycle");
      seen.add(o);
      const n = b[o++];
      if (!n) break;
      if ((n & 192) === 192) {
        need(o, 1);
        if (!next) next = o + 1;
        o = ((n & 63) << 8) | b[o];
        continue;
      }
      expandedLength += n + 1;
      if (expandedLength > 255) throw new Error("DNS name exceeds 255 bytes");
      if (n > 63) throw new Error("Invalid DNS label");
      need(o, n);
      parts.push(b.subarray(o, o + n).toString("utf8"));
      o += n;
    }
    return [parts.join("."), next || o];
  };
  const flags = u16(2),
    m: DnsMessage = {
      id: u16(0),
      response: !!(flags & 0x8000),
      name: "",
      queryType: 0,
      answers: [],
      rcode: flags & 15,
      packetIds: ids,
      time,
    };
  if (u16(4) + u16(6) > 256)
    throw new Error("DNS record count exceeds analysis limit");
  let o = 12;
  for (let i = 0; i < u16(4); i++) {
    const [n, e] = name(o);
    o = e;
    need(o, 4);
    if (i === 0) {
      m.name = n;
      m.queryType = u16(o);
    }
    o += 4;
  }
  for (let i = 0; i < u16(6); i++) {
    const [, e] = name(o);
    o = e;
    need(o, 10);
    const type = u16(o),
      n = u16(o + 8);
    o += 10;
    need(o, n);
    if (type === 1 && n === 4)
      m.answers.push(Array.from(b.subarray(o, o + n)).join("."));
    else if (type === 28 && n === 16)
      m.answers.push(
        Array.from({ length: 8 }, (_, i) => u16(o + i * 2).toString(16)).join(
          ":",
        ),
      );
    else if ([2, 5, 12].includes(type)) m.answers.push(name(o)[0]);
    else if (type === 15 && n >= 3)
      m.answers.push(`${u16(o)} ${name(o + 2)[0]}`);
    else m.answers.push(`TYPE${type}: ${b.subarray(o, o + n).toString("hex")}`);
    o += n;
  }
  return m;
}
export function analyzeDns(packets: Packet[], flows: Flow[]): DnsExchange[] {
  const all: { m: DnsMessage; flow: string }[] = [];
  let messageCount = 0;
  const add = (bytes: number[], ids: number[], flow: string) => {
    if (++messageCount > LIMITS.httpMessages)
      throw new Error("DNS message count exceeds analysis limit");
    try {
      const m = parse(bytes, ids, packets[ids[0] - 1].time);
      all.push({ m, flow });
      for (const id of ids) {
        packets[id - 1].protocol = "DNS";
        packets[id - 1].filter.dns = true;
        packets[id - 1].filter["dns.qry.name"] = m.name;
      }
    } catch (e) {
      packets[ids[0] - 1].diagnostics.push({
        code: "dns.malformed",
        evidence: String(e),
      });
    }
  };
  for (const p of packets)
    if (p.transport === "UDP" && (p.srcPort === 53 || p.dstPort === 53))
      add(
        p.bytes.slice(p.payloadOffset!, p.payloadOffset! + p.payloadLength!),
        [p.id],
        p.flowId!,
      );
  for (const f of flows)
    if (
      f.transport === "TCP" &&
      f.packetIds.some(
        (id) =>
          packets[id - 1].srcPort === 53 || packets[id - 1].dstPort === 53,
      )
    )
      for (const c of f.chunks) {
        for (let o = 0; o + 2 <= c.bytes.length;) {
          const n = c.bytes[o] * 256 + c.bytes[o + 1];
          o += 2;
          if (o + n > c.bytes.length) break;
          const ids = [
            ...new Set(
              c.spans
                .filter(
                  (span) =>
                    span.start < o + n && span.start + span.length > o - 2,
                )
                .map((span) => span.packetId),
            ),
          ];
          add(c.bytes.slice(o, o + n), ids, f.id);
          o += n;
        }
      }
  all.sort((a, b) => a.m.time - b.m.time);
  const out: DnsExchange[] = [];
  const pending = new Map<string, DnsExchange[]>();
  for (const { m, flow } of all) {
    const key = `${flow}|${m.id}|${m.name}|${m.queryType}`;
    const queue = pending.get(key) ?? [];
    if (m.response && queue.length) {
      const x = queue.shift()!;
      x.response = m;
      x.packetIds.push(...m.packetIds);
    } else {
      const x: DnsExchange = {
        id: String(out.length + 1),
        packetIds: [...m.packetIds],
        ...(m.response ? { response: m } : { request: m }),
      };
      out.push(x);
      if (!m.response) queue.push(x);
    }
    pending.set(key, queue);
  }
  return out;
}
