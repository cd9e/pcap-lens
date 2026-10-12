export function tcp(
  payload: string | Buffer,
  seq = 100,
  reverse = false,
  flags = 0x18,
  port = 80,
) {
  const body = Buffer.from(payload);
  const b = Buffer.alloc(54 + body.length);
  b.fill(0x11, 0, 6);
  b.fill(0x22, 6, 12);
  b.writeUInt16BE(0x800, 12);
  b[14] = 0x45;
  b.writeUInt16BE(40 + body.length, 16);
  b[22] = 64;
  b[23] = 6;
  b.set(reverse ? [10, 0, 0, 2] : [10, 0, 0, 1], 26);
  b.set(reverse ? [10, 0, 0, 1] : [10, 0, 0, 2], 30);
  b.writeUInt16BE(reverse ? port : 50123, 34);
  b.writeUInt16BE(reverse ? 50123 : port, 36);
  b.writeUInt32BE(seq >>> 0, 38);
  b[46] = 0x50;
  b[47] = flags;
  b.writeUInt16BE(65535, 48);
  b.set(body, 54);
  return b;
}
export function udp(payload: Buffer, reverse = false) {
  const b = tcp("", 0, reverse, 0, 53).subarray(0, 42);
  b[23] = 17;
  b.writeUInt16BE(28 + payload.length, 16);
  b.writeUInt16BE(8 + payload.length, 38);
  b.writeUInt16BE(0, 40);
  return Buffer.concat([b, payload]);
}
export function pcap(packets: Buffer[], little = true, nano = false) {
  const h = Buffer.alloc(24);
  const w16 = (b: Buffer, n: number, o: number) =>
    little ? b.writeUInt16LE(n, o) : b.writeUInt16BE(n, o);
  const w32 = (b: Buffer, n: number, o: number) =>
    little ? b.writeUInt32LE(n, o) : b.writeUInt32BE(n, o);
  w32(h, nano ? 0xa1b23c4d : 0xa1b2c3d4, 0);
  w16(h, 2, 4);
  w16(h, 4, 6);
  w32(h, 65535, 16);
  w32(h, 1, 20);
  return Buffer.concat([
    h,
    ...packets.flatMap((b, i) => {
      const r = Buffer.alloc(16);
      w32(r, 1700000000, 0);
      w32(r, i * (nano ? 1000000 : 1000), 4);
      w32(r, b.length, 8);
      w32(r, b.length, 12);
      return [r, b];
    }),
  ]);
}
export function pcapng(packets: Buffer[], le = true) {
  const w = (b: Buffer, n: number, o: number) =>
    le ? b.writeUInt32LE(n, o) : b.writeUInt32BE(n, o);
  const block = (type: number, body: Buffer) => {
    const b = Buffer.alloc(12 + Math.ceil(body.length / 4) * 4);
    w(b, type, 0);
    w(b, b.length, 4);
    body.copy(b, 8);
    w(b, b.length, b.length - 4);
    return b;
  };
  const s = Buffer.alloc(16);
  w(s, 0x1a2b3c4d, 0);
  le ? s.writeUInt16LE(1, 4) : s.writeUInt16BE(1, 4);
  s.fill(255, 8);
  const int = Buffer.alloc(8);
  le ? int.writeUInt16LE(1, 0) : int.writeUInt16BE(1, 0);
  w(int, 65535, 4);
  return Buffer.concat([
    block(0x0a0d0d0a, s),
    block(1, int),
    ...packets.map((p, i) => {
      const b = Buffer.alloc(20 + p.length);
      w(b, i * 1000, 8);
      w(b, p.length, 12);
      w(b, p.length, 16);
      p.copy(b, 20);
      return block(6, b);
    }),
  ]);
}
export function dns(response = false) {
  const b = Buffer.alloc(12);
  b.writeUInt16BE(123, 0);
  b.writeUInt16BE(response ? 0x8180 : 0x0100, 2);
  b.writeUInt16BE(1, 4);
  b.writeUInt16BE(response ? 1 : 0, 6);
  const q = Buffer.from([
    7,
    ...Buffer.from("example"),
    3,
    ...Buffer.from("com"),
    0,
    0,
    1,
    0,
    1,
  ]);
  return Buffer.concat([
    b,
    q,
    ...(response
      ? [
          Buffer.from([
            0xc0, 0x0c, 0, 1, 0, 1, 0, 0, 0, 60, 0, 4, 93, 184, 216, 34,
          ]),
        ]
      : []),
  ]);
}
