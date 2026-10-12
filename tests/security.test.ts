import { test } from "node:test";
import assert from "node:assert/strict";
import { mkdtemp, writeFile, rm, truncate, mkdir } from "node:fs/promises";
import { tmpdir } from "node:os";
import { join } from "node:path";
import { gzipSync } from "node:zlib";
import { analyze } from "../src/core/analyze";
import { readCapture } from "../src/core/capture";
import { compileFilter, FilterError } from "../src/core/filter";
import { LIMITS } from "../src/core/limits";
import { readLocalCapture } from "../src/extension/local-file";
import {
  AnalysisSession,
  analyzeInWorker,
} from "../src/extension/analysis-session";
import { wiresharkCandidates } from "../src/extension/wireshark";
import { pcap, tcp, udp, dns } from "./fixtures";

test("deep and large filters fail with controlled errors, not stack overflows", () => {
  for (const expression of [
    "(".repeat(200) + "http" + ")".repeat(200),
    "!".repeat(200) + "tcp",
    "http || ".repeat(2000) + "http",
  ]) {
    assert.throws(
      () => compileFilter(expression),
      (error) => error instanceof FilterError,
    );
  }
  assert.ok(compileFilter("(".repeat(10) + "tcp" + ")".repeat(10)));
});
test("capture byte and packet budgets are enforced before unbounded allocation", () => {
  assert.throws(
    () => readCapture(Buffer.alloc(LIMITS.captureBytes + 1)),
    /8 MB/,
  );
  assert.throws(
    () =>
      readCapture(
        pcap(Array.from({ length: LIMITS.packets + 1 }, () => Buffer.alloc(0))),
      ),
    /packet count/,
  );
});
test("repeated gzip bodies cannot multiply into unbounded retained data", () => {
  const compressed = gzipSync(Buffer.alloc(3 * 1024 * 1024, 65));
  const response = Buffer.concat([
    Buffer.from(
      `HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: ${compressed.length}\r\n\r\n`,
    ),
    compressed,
  ]);
  const c = analyze(
    pcap(
      Array.from({ length: 4 }, (_, i) =>
        tcp(response, 100 + i * response.length, true),
      ),
    ),
  );
  assert.ok(
    c.http.reduce((total, x) => total + (x.response?.body.length ?? 0), 0) <=
      LIMITS.totalBodyBytes,
  );
  assert.ok(
    c.http.some((x) =>
      x.response?.diagnostics.some((d) => d.code === "http.gzipFailed"),
    ),
  );
});
test("HTTP header and message floods are bounded; large non-HTTP streams still work", () => {
  assert.throws(
    () =>
      analyze(
        pcap([tcp("GET / HTTP/1.1\r\n" + "X: a\r\n".repeat(129) + "\r\n")]),
      ),
    /headers/,
  );
  const message = "GET / HTTP/1.1\r\n\r\n";
  assert.throws(
    () => analyze(pcap([tcp(message.repeat(2001))])),
    /message count/,
  );
  const raw = Array.from({ length: 3 }, (_, i) =>
    tcp(Buffer.alloc(40000, 255), 100 + i * 40000),
  );
  assert.equal(analyze(pcap(raw)).http.length, 0);
});
test("DNS and VLAN expansion are bounded", () => {
  const malicious = dns();
  malicious.writeUInt16BE(257, 4);
  assert.ok(
    analyze(pcap([udp(malicious)])).packets[0].diagnostics.some(
      (d) => d.code === "dns.malformed",
    ),
  );
  const p = tcp("");
  const tags = Buffer.concat(
    Array.from({ length: 17 }, () => Buffer.from([0x81, 0, 0, 1])),
  );
  assert.ok(
    analyze(
      pcap([Buffer.concat([p.subarray(0, 12), tags, p.subarray(12)])]),
    ).packets[0].diagnostics.some((d) => d.code === "protocol.malformed"),
  );
});
test("local reader accepts regular files and rejects oversized files and devices", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pcap-lens-read-"));
  try {
    const file = join(dir, "capture.pcap");
    const input = pcap([tcp("")]);
    await writeFile(file, input);
    assert.deepEqual(Buffer.from(await readLocalCapture(file)), input);
    await truncate(file, LIMITS.captureBytes + 1);
    await assert.rejects(readLocalCapture(file), /8 MB/);
    await mkdir(join(dir, "directory"));
    await assert.rejects(readLocalCapture(join(dir, "directory")));
    if (process.platform !== "win32")
      await assert.rejects(readLocalCapture("/dev/zero"), /regular file/);
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("concurrent initialization uses one analysis; disposal prevents new work", async () => {
  let calls = 0;
  const capture = analyze(pcap([]));
  const session = new AnalysisSession(async () => {
    calls++;
    await new Promise((resolve) => setTimeout(resolve, 5));
    return capture;
  });
  const results = await Promise.all(
    Array.from({ length: 20 }, () => session.get()),
  );
  assert.equal(calls, 1);
  assert.ok(results.every((x) => x === capture));
  session.dispose();
  await assert.rejects(session.get(), /cancelled/);
  const disposed = new AnalysisSession(async () => {
    throw new Error("must not run");
  });
  const pending = disposed.get();
  disposed.dispose();
  await assert.rejects(pending, /abort/i);
});
test("worker timeout and early exit are reported, cancellation terminates work", async () => {
  const dir = await mkdtemp(join(tmpdir(), "pcap-lens-worker-"));
  try {
    const idle = join(dir, "idle.cjs");
    await writeFile(idle, "setInterval(()=>{},1000)");
    await assert.rejects(
      analyzeInWorker(new Uint8Array(), idle, new AbortController().signal, 50),
      /exceeded/,
    );
    const controller = new AbortController();
    const work = analyzeInWorker(new Uint8Array(), idle, controller.signal);
    controller.abort();
    await assert.rejects(work, /cancelled/);
    const early = join(dir, "early.cjs");
    await writeFile(early, "process.exit(0)");
    await assert.rejects(
      analyzeInWorker(new Uint8Array(), early, new AbortController().signal),
      /without a result/,
    );
  } finally {
    await rm(dir, { recursive: true, force: true });
  }
});
test("Wireshark cannot be resolved from relative paths or implicit working-directory search", () => {
  assert.throws(
    () => wiresharkCandidates("win32", {}, "wireshark.exe"),
    /absolute/,
  );
  assert.throws(
    () => wiresharkCandidates("linux", {}, "./wireshark"),
    /absolute/,
  );
  assert.deepEqual(
    wiresharkCandidates("linux", { PATH: ".::bin:/usr/bin" }, ""),
    ["/usr/bin/wireshark"],
  );
  assert.deepEqual(wiresharkCandidates("win32", {}, ""), [
    "C:\\Program Files\\Wireshark\\Wireshark.exe",
  ]);
});

test("fragmented long HTTP field names do not amplify packet metadata", () => {
  const message = "GET / HTTP/1.1\r\n" + "X".repeat(2000) + ": value\r\n\r\n";
  const parts = Array.from({ length: Math.ceil(message.length / 20) }, (_, i) =>
    tcp(message.slice(i * 20, i * 20 + 20), 100 + i * 20),
  );
  const c = analyze(pcap(parts));
  const children = c.packets.flatMap((p) =>
    p.fields
      .filter((f) => f.name === "HTTP (reassembled)")
      .flatMap((f) => f.children ?? []),
  );
  assert.ok(children.length > 50);
  assert.ok(
    children.every((f) => f.name.length <= 128 && f.value.length <= 256),
  );
  assert.ok(
    Object.keys(c.http[0].request!.headers).some(
      (name) => name.length === 2000,
    ),
  );
});
