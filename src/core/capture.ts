import { LIMITS } from "./limits";
import type { Packet } from "./model";
export function readCapture(input: Uint8Array): {
  format: string;
  packets: Packet[];
} {
  if (input.byteLength > LIMITS.captureBytes)
    throw new Error("Capture exceeds the 8 MB safety limit");
  const data = new DataView(input.buffer, input.byteOffset, input.byteLength);
  const packets: Packet[] = [];
  const need = (o: number, n: number) => {
    if (o < 0 || n < 0 || o + n > input.length)
      throw new Error(`Truncated capture at byte ${o}`);
  };
  const add = (
    o: number,
    n: number,
    len: number,
    time: number,
    linkType: number,
  ) => {
    need(o, n);
    if (packets.length >= LIMITS.packets)
      throw new Error("Capture packet count exceeds analysis limit");
    packets.push({
      id: packets.length + 1,
      time,
      originalLength: len,
      linkType,
      bytes: Array.from(input.subarray(o, o + n)),
      fields: [],
      diagnostics: n < len ? [{ code: "capture.truncated" }] : [],
      protocol: "Unknown",
      src: "",
      dst: "",
      filter: { "frame.len": len, "frame.number": packets.length + 1 },
    });
  };
  need(0, 4);
  const magic = data.getUint32(0, false);
  if ([0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1].includes(magic)) {
    need(0, 24);
    const le = magic === 0xd4c3b2a1 || magic === 0x4d3cb2a1;
    const nano = magic === 0xa1b23c4d || magic === 0x4d3cb2a1;
    const link = data.getUint32(20, le) & 0xffff;
    if (data.getUint16(4, le) !== 2)
      throw new Error("Unsupported pcap version");
    for (let o = 24; o < input.length;) {
      need(o, 16);
      const n = data.getUint32(o + 8, le);
      add(
        o + 16,
        n,
        data.getUint32(o + 12, le),
        data.getUint32(o, le) + data.getUint32(o + 4, le) / (nano ? 1e9 : 1e6),
        link,
      );
      o += 16 + n;
    }
    return { format: "pcap", packets };
  }
  if (magic !== 0x0a0d0d0a) throw new Error("Unsupported capture format");
  let le = true;
  let section = false;
  let interfaces: {
    link: number;
    resolution: number;
    offset: number;
    snap: number;
  }[] = [];
  for (let o = 0; o < input.length;) {
    need(o, 12);
    const shb = data.getUint32(o, false) === 0x0a0d0d0a;
    if (shb) {
      need(o, 28);
      const bom = data.getUint32(o + 8, false);
      if (bom !== 0x1a2b3c4d && bom !== 0x4d3c2b1a)
        throw new Error("Invalid pcapng byte order");
      le = bom === 0x4d3c2b1a;
      section = true;
      interfaces = [];
    }
    if (!section) throw new Error("Missing pcapng section");
    const type = data.getUint32(o, le),
      size = data.getUint32(o + 4, le);
    if (size < 12 || size % 4)
      throw new Error(`Invalid pcapng block size at ${o}`);
    need(o, size);
    if (shb && size < 28) throw new Error("Invalid section header block");
    if (data.getUint32(o + size - 4, le) !== size)
      throw new Error("Mismatched pcapng block lengths");
    if (type === 1) {
      if (size < 20) throw new Error("Invalid interface block");
      let resolution = 1e-6,
        offset = 0;
      for (let q = o + 16; q + 4 <= o + size - 4;) {
        const code = data.getUint16(q, le),
          n = data.getUint16(q + 2, le);
        q += 4;
        if (q + n > o + size - 4) throw new Error("Invalid interface option");
        if (code === 0) break;
        if (code === 9 && n === 1) {
          const r = data.getUint8(q);
          resolution = r & 128 ? 2 ** -(r & 127) : 10 ** -r;
        }
        if (code === 14 && n === 8) offset = Number(data.getBigInt64(q, le));
        q += Math.ceil(n / 4) * 4;
      }
      if (interfaces.length >= LIMITS.interfaces)
        throw new Error("Capture interface count exceeds analysis limit");
      interfaces.push({
        link: data.getUint16(o + 8, le),
        snap: data.getUint32(o + 12, le),
        resolution,
        offset,
      });
    } else if (type === 6 || type === 2) {
      if (size < 32) throw new Error("Invalid packet block");
      const iface =
        interfaces[
          type === 6 ? data.getUint32(o + 8, le) : data.getUint16(o + 8, le)
        ];
      if (!iface) throw new Error("Unknown capture interface");
      const n = data.getUint32(o + 20, le);
      if (28 + Math.ceil(n / 4) * 4 + 4 > size)
        throw new Error("Packet exceeds block");
      add(
        o + 28,
        n,
        data.getUint32(o + 24, le),
        (data.getUint32(o + 12, le) * 4294967296 + data.getUint32(o + 16, le)) *
          iface.resolution +
          iface.offset,
        iface.link,
      );
    } else if (type === 3) {
      if (size < 16 || !interfaces[0])
        throw new Error("Invalid simple packet block");
      const len = data.getUint32(o + 8, le),
        n = Math.min(len, interfaces[0].snap || len);
      if (Math.ceil(n / 4) * 4 + 16 > size)
        throw new Error("Truncated simple packet");
      add(o + 12, n, len, 0, interfaces[0].link);
      packets.at(-1)!.diagnostics.push({ code: "capture.noTimestamp" });
    }
    o += size;
  }
  return { format: "pcapng", packets };
}
