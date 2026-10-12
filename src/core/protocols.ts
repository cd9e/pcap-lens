import type { Packet, Field } from "./model";
export type LinkDecoder = (packet: Packet) => void;
const linkDecoders = new Map<number, LinkDecoder>();
export function registerLinkDecoder(type: number, decode: LinkDecoder) {
  if (linkDecoders.has(type))
    throw new Error(`Duplicate link decoder: ${type}`);
  linkDecoders.set(type, decode);
}
export function decodePacket(p: Packet) {
  try {
    const decode = linkDecoders.get(p.linkType);
    if (decode) decode(p);
    else
      p.diagnostics.push({
        code: "protocol.unsupportedLink",
        evidence: String(p.linkType),
      });
  } catch (e) {
    p.diagnostics.push({ code: "protocol.malformed", evidence: String(e) });
  }
}
registerLinkDecoder(1, (p) => {
  const b = Uint8Array.from(p.bytes),
    d = new DataView(b.buffer);
  let end = b.length;
  const need = (o: number, n: number) => {
    if (o < 0 || o + n > end) throw new Error(`Truncated protocol at ${o}`);
  };
  const u16 = (o: number) => {
      need(o, 2);
      return d.getUint16(o);
    },
    u32 = (o: number) => {
      need(o, 4);
      return d.getUint32(o);
    };
  const field = (
    name: string,
    value: unknown,
    offset: number,
    length: number,
  ): Field => ({ name, value: String(value), offset, length });
  const mac = (o: number) =>
    Array.from(b.slice(o, o + 6), (n) => n.toString(16).padStart(2, "0")).join(
      ":",
    );
  need(0, 14);
  let type = u16(12),
    o = 14;
  p.src = mac(6);
  p.dst = mac(0);
  p.protocol = "Ethernet";
  p.fields.push({
    ...field("Ethernet", `${p.src} → ${p.dst}`, 0, 14),
    children: [
      field("Destination", p.dst, 0, 6),
      field("Source", p.src, 6, 6),
      field("Type", type, 12, 2),
    ],
  });
  let vlanDepth = 0;
  while (type === 0x8100 || type === 0x88a8) {
    if (++vlanDepth > 16) throw new Error("Too many VLAN tags");
    need(o, 4);
    p.fields.push(field("VLAN", u16(o) & 4095, o, 4));
    type = u16(o + 2);
    o += 4;
  }
  let next: number;
  if (type === 0x0800) {
    need(o, 20);
    const len = (b[o] & 15) * 4,
      total = u16(o + 2);
    if (b[o] >> 4 !== 4 || len < 20 || total < len)
      throw new Error("Invalid IPv4 header");
    need(o, len);
    end = Math.min(end, o + total);
    p.src = Array.from(b.slice(o + 12, o + 16)).join(".");
    p.dst = Array.from(b.slice(o + 16, o + 20)).join(".");
    p.protocol = "IPv4";
    p.filter.ip = true;
    p.filter["ip.src"] = p.src;
    p.filter["ip.dst"] = p.dst;
    p.fields.push({
      ...field("IPv4", `${p.src} → ${p.dst}`, o, len),
      children: [
        field("Source", p.src, o + 12, 4),
        field("Destination", p.dst, o + 16, 4),
        field("TTL", b[o + 8], o + 8, 1),
      ],
    });
    next = b[o + 9];
    const frag = u16(o + 6);
    o += len;
    if (frag & 0x3fff) {
      p.diagnostics.push({ code: "protocol.fragmentUnsupported" });
      return;
    }
  } else if (type === 0x86dd) {
    need(o, 40);
    if (b[o] >> 4 !== 6) throw new Error("Invalid IPv6 header");
    const ip = (q: number) =>
      Array.from({ length: 8 }, (_, i) => u16(q + 2 * i).toString(16)).join(
        ":",
      );
    p.src = ip(o + 8);
    p.dst = ip(o + 24);
    p.protocol = "IPv6";
    p.filter.ipv6 = true;
    p.filter["ipv6.src"] = p.src;
    p.filter["ipv6.dst"] = p.dst;
    p.fields.push({
      ...field("IPv6", `${p.src} → ${p.dst}`, o, 40),
      children: [
        field("Source", p.src, o + 8, 16),
        field("Destination", p.dst, o + 24, 16),
      ],
    });
    next = b[o + 6];
    end = Math.min(end, o + 40 + u16(o + 4));
    o += 40;
    let depth = 0;
    while ([0, 43, 60, 44, 51].includes(next)) {
      if (++depth > 16) throw new Error("Too many IPv6 extensions");
      need(o, 8);
      const kind = next;
      next = b[o];
      const n =
        kind === 44 ? 8 : kind === 51 ? (b[o + 1] + 2) * 4 : (b[o + 1] + 1) * 8;
      need(o, n);
      p.fields.push(field("IPv6 extension", kind, o, n));
      if (kind === 44 && u16(o + 2) & 0xfff9) {
        p.diagnostics.push({ code: "protocol.fragmentUnsupported" });
        return;
      }
      o += n;
    }
  } else {
    p.diagnostics.push({
      code: "protocol.unrecognized",
      evidence: `EtherType 0x${type.toString(16)}`,
    });
    return;
  }
  if (next !== 6 && next !== 17) {
    p.diagnostics.push({
      code: "protocol.unrecognized",
      evidence: `IP protocol ${next}`,
    });
    return;
  }
  need(o, next === 6 ? 20 : 8);
  p.transport = next === 6 ? "TCP" : "UDP";
  p.protocol = p.transport;
  p.srcPort = u16(o);
  p.dstPort = u16(o + 2);
  const key = p.transport.toLowerCase();
  p.filter[key] = true;
  p.filter[`${key}.srcport`] = p.srcPort;
  p.filter[`${key}.dstport`] = p.dstPort;
  const children = [
    field("Source port", p.srcPort, o, 2),
    field("Destination port", p.dstPort, o + 2, 2),
  ];
  let length = 8;
  if (next === 6) {
    length = (b[o + 12] >> 4) * 4;
    if (length < 20) throw new Error("Invalid TCP header");
    need(o, length);
    p.seq = u32(o + 4);
    p.ack = u32(o + 8);
    p.flags = b[o + 13];
    children.push(
      field("Sequence", p.seq, o + 4, 4),
      field("Acknowledgment", p.ack, o + 8, 4),
      field("Flags", "0x" + p.flags.toString(16), o + 13, 1),
    );
    for (const [name, mask] of Object.entries({
      fin: 1,
      syn: 2,
      reset: 4,
      push: 8,
      ack: 16,
      urg: 32,
    }))
      p.filter[`tcp.flags.${name}`] = Number(Boolean(p.flags & mask));
    p.filter["tcp.seq"] = p.seq;
    p.filter["tcp.ack"] = p.ack;
  } else {
    const udpLength = u16(o + 4);
    if (udpLength < 8) throw new Error("Invalid UDP length");
    end = Math.min(end, o + udpLength);
    children.push(field("Length", udpLength, o + 4, 2));
  }
  p.fields.push({
    ...field(p.transport, `${p.srcPort} → ${p.dstPort}`, o, length),
    children,
  });
  p.payloadOffset = o + length;
  p.payloadLength = Math.max(0, end - p.payloadOffset);
  if (p.payloadLength)
    p.fields.push(
      field(
        "Payload",
        `${p.payloadLength} bytes`,
        p.payloadOffset,
        p.payloadLength,
      ),
    );
});
