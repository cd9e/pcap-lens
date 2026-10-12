import { test } from "node:test";
import assert from "node:assert/strict";
import { gzipSync } from "node:zlib";
import { analyze } from "../src/core/analyze";
import { readCapture } from "../src/core/capture";
import {
  compileFilter,
  registerField,
  registerOperator,
  FilterError,
} from "../src/core/filter";
import { pcap, pcapng, tcp, udp, dns } from "./fixtures";
const request = "GET /api HTTP/1.1\r\nHost: example.com\r\n\r\n";
const response =
  'HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: 11\r\n\r\n{"ok":true}';
test("all pcap endian/resolution variants and pcapng sections", () => {
  for (const le of [true, false]) {
    for (const nano of [true, false]) {
      const c = analyze(
        pcap([tcp(request), tcp(response, 500, true)], le, nano),
      );
      assert.equal(c.http.length, 1);
      assert.equal(c.http[0].response?.status, 200);
      assert.ok(
        Math.abs(c.packets[1].time - c.packets[0].time - 0.001) < 0.000001,
      );
    }
    assert.equal(
      analyze(pcapng([tcp(request)], le)).http[0].request?.url,
      "/api",
    );
  }
  assert.equal(
    readCapture(
      Buffer.concat([pcapng([tcp(request)]), pcapng([tcp(request)], false)]),
    ).packets.length,
    2,
  );
});
test("TCP split and reordered HTTP, retransmissions, and exact source packets", () => {
  const first = request.slice(0, 10),
    rest = request.slice(10);
  const c = analyze(
    pcap([
      tcp(rest, 110),
      tcp(first, 100),
      tcp(first, 100),
      tcp(response, 500, true),
      tcp(
        "GET /two HTTP/1.1\r\nHost: example.com\r\n\r\n",
        100 + request.length,
      ),
    ]),
  );
  assert.equal(c.http[0].request?.url, "/api");
  assert.deepEqual(new Set(c.http[0].request?.packetIds), new Set([1, 2]));
  assert.equal(c.http[1].request?.url, "/two");
  assert.deepEqual(c.http[1].packetIds, [5]);
  assert.ok(c.flows[0].diagnostics.some((x) => x.code === "tcp.overlap"));
});
test("sequence wrap, gap, reset and unknown link handling", () => {
  const c = analyze(
    pcap([
      tcp("abcd", 0xfffffffe),
      tcp("ef", 2),
      tcp("gap", 10),
      tcp("", 13, false, 4),
    ]),
  );
  assert.equal(Buffer.from(c.flows[0].chunks[0].bytes).toString(), "abcdef");
  assert.equal(c.flows[0].chunks[1].gapBefore, 6);
  assert.ok(c.flows[0].diagnostics.some((x) => x.code === "tcp.reset"));
  const b = pcap([tcp("")]);
  b.writeUInt32LE(147, 20);
  assert.equal(
    analyze(b).packets[0].diagnostics[0].code,
    "protocol.unsupportedLink",
  );
});
test("chunked gzip HTTP body and truncated body", () => {
  const zipped = gzipSync('{"hello":"world"}');
  const res = Buffer.concat([
    Buffer.from(
      "HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\nContent-Encoding: gzip\r\n\r\n" +
        zipped.length.toString(16) +
        "\r\n",
    ),
    zipped,
    Buffer.from("\r\n0\r\n\r\n"),
  ]);
  const c = analyze(pcap([tcp(request), tcp(res, 500, true)]));
  assert.equal(
    Buffer.from(c.http[0].response!.body).toString(),
    '{"hello":"world"}',
  );
  assert.equal(c.http[0].response?.complete, true);
  const partial = analyze(
    pcap([tcp(request), tcp(response.slice(0, -3), 500, true)]),
  );
  assert.equal(partial.http[0].response?.complete, false);
});
test("HEAD does not consume advertised response body; pipelining pairs", () => {
  const a = "HEAD /a HTTP/1.1\r\nHost: x\r\n\r\n" + request;
  const b = "HTTP/1.1 200 OK\r\nContent-Length: 999\r\n\r\n" + response;
  const c = analyze(pcap([tcp(a), tcp(b, 500, true)]));
  assert.equal(c.http.length, 2);
  assert.equal(c.http[0].response?.body.length, 0);
  assert.equal(c.http[1].response?.body.length, 11);
});
test("DNS compressed answer pairs; hostile pointers stay bounded", () => {
  const c = analyze(pcap([udp(dns()), udp(dns(true), true)]));
  assert.equal(c.dns.length, 1);
  assert.deepEqual(c.dns[0].response?.answers, ["93.184.216.34"]);
  const malformed = dns();
  malformed[12] = 0xc0;
  malformed[13] = 12;
  assert.ok(
    analyze(pcap([udp(malformed)])).packets[0].diagnostics.some(
      (x) => x.code === "dns.malformed",
    ),
  );
});
test("filter precedence, validation and registration", () => {
  const c = analyze(pcap([tcp(request), tcp(response, 500, true)]));
  const p = c.packets[0];
  assert.ok(
    compileFilter(
      "http && (tcp.port == 80 || dns) && http.request.method == GET",
    )(p),
  );
  assert.ok(
    compileFilter('ip.addr == 10.0.0.1 && http.request.uri contains "api"')(p),
  );
  assert.equal(compileFilter("!http || dns")(p), false);
  assert.throws(() => compileFilter("http && ("), FilterError);
  assert.throws(() => compileFilter("unknown == 1"), FilterError);
  registerField("custom.length", (p) => [p.bytes.length]);
  registerOperator("atleast", (a, b) => Number(a) >= Number(b));
  assert.ok(compileFilter("custom.length atleast 10")(p));
});
test("malformed capture boundaries and truncated protocols never escape reads", () => {
  const good = pcapng([tcp(request)]);
  for (let n = 0; n < good.length; n++) {
    try {
      analyze(good.subarray(0, n));
    } catch (e) {
      assert.ok(e instanceof Error);
    }
  }
  const broken = Buffer.from(good);
  broken.writeUInt32LE(0xfffffff0, 4);
  assert.throws(() => readCapture(broken));
  for (let n = 0; n < 54; n++)
    assert.doesNotThrow(() => analyze(pcap([tcp(request).subarray(0, n)])));
});
test("Ethernet VLAN and IPv6 transport", () => {
  const original = tcp(request);
  const vlan = Buffer.concat([
    original.subarray(0, 12),
    Buffer.from([0x81, 0, 0, 42]),
    original.subarray(12),
  ]);
  assert.equal(analyze(pcap([vlan])).http[0].request?.url, "/api");
  const head = Buffer.alloc(54);
  original.copy(head, 0, 0, 14);
  head.writeUInt16BE(0x86dd, 12);
  head[14] = 0x60;
  head.writeUInt16BE(original.length - 34, 18);
  head[20] = 6;
  head[21] = 64;
  head[37] = 1;
  head[53] = 2;
  const c = analyze(pcap([Buffer.concat([head, original.subarray(34)])]));
  assert.equal(c.http[0].request?.url, "/api");
  assert.equal(c.packets[0].filter.ipv6, true);
});

test("partial HTTP headers remain visible and multiple fields in a packet do not overwrite", () => {
  const incomplete = analyze(
    pcap([tcp("GET /partial HTTP/1.1\r\nHost: example")]),
  );
  assert.equal(incomplete.http[0].request?.complete, false);
  assert.equal(incomplete.http[0].request?.url, "/partial");
  const c = analyze(
    pcap([
      tcp(
        request +
          "POST /other HTTP/1.1\r\nHost: x\r\nContent-Length: 0\r\n\r\n",
      ),
    ]),
  );
  assert.ok(compileFilter("http.request.method == GET")(c.packets[0]));
  assert.ok(compileFilter("http.request.method == POST")(c.packets[0]));
  assert.ok(
    c.packets[0].fields
      .find((f) => f.name === "HTTP (reassembled)")
      ?.children?.some((f) => f.name === "Host"),
  );
});

test("full-sized target capture with hundreds of HTTP exchanges", () => {
  const packets: Buffer[] = [];
  let client = 100,
    server = 500;
  for (let i = 0; i < 400; i++) {
    const body = "x".repeat(4000);
    const reply = `HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nContent-Length: ${body.length}\r\n\r\n${body}`;
    packets.push(tcp(request, client), tcp(reply, server, true));
    client += request.length;
    server += reply.length;
  }
  const c = analyze(pcap(packets));
  assert.equal(c.http.length, 400);
  assert.equal(c.http.at(-1)?.response?.body.length, 4000);
});

test("reset cannot prove completion of a close-delimited HTTP body", () => {
  const reply = "HTTP/1.1 200 OK\r\n\r\npartial";
  const c = analyze(
    pcap([
      tcp(request),
      tcp(reply, 500, true),
      tcp("", 500 + reply.length, true, 4),
    ]),
  );
  assert.equal(c.http[0].response?.complete, false);
});

test("nonconforming request target whitespace is retained and paired, with accurate body length diagnostics", () => {
  const target = "/inspect?value=hello world&count=2";
  const req = `POST ${target} HTTP/1.1\r\nHost: example.test\r\nContent-Length: 0\r\n\r\n`;
  const res =
    "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\nConnection: close\r\nContent-Length: 12\r\n\r\n123456789";
  const c = analyze(
    pcap([
      tcp(req),
      tcp(res, 500, true),
      tcp("", 100 + req.length, false, 17),
      tcp("", 500 + res.length, true, 17),
    ]),
  );
  assert.equal(c.http.length, 1);
  const x = c.http[0];
  assert.equal(x.request?.method, "POST");
  assert.equal(x.request?.url, target);
  assert.equal(x.request?.headers.host, "example.test");
  assert.equal(x.request?.complete, true);
  assert.ok(
    x.request?.diagnostics.some(
      (d) => d.code === "http.unescapedTargetWhitespace",
    ),
  );
  assert.equal(x.response?.status, 200);
  assert.equal(x.response?.body.length, 9);
  assert.equal(x.response?.complete, false);
  assert.ok(
    x.response?.diagnostics.some(
      (d) =>
        d.code === "http.bodyLengthMismatch" &&
        d.evidence === "Content-Length=12; captured=9; missing=3",
    ),
  );
  assert.deepEqual(x.packetIds, [1, 2]);
  assert.ok(compileFilter("http.request.method == POST")(c.packets[0]));
});

test("request whitespace tolerance works across segments and does not match arbitrary stream content", () => {
  const req =
    "GET /search?q=first second\tthird HTTP/1.1\r\nHost: example.test\r\n\r\n";
  const split = req.indexOf("second") + 2;
  const c = analyze(
    pcap([tcp(req.slice(0, split)), tcp(req.slice(split), 100 + split)]),
  );
  assert.equal(c.http[0].request?.url, "/search?q=first second\tthird");
  assert.deepEqual(c.http[0].request?.packetIds, [1, 2]);
  for (const raw of [
    "not an HTTP request\r\n\r\n",
    "GET / HTTP/1.1 extra\r\n\r\n",
    "GET / HTTP/2.0\r\n\r\n",
  ])
    assert.equal(analyze(pcap([tcp(raw)])).http.length, 0);
});
