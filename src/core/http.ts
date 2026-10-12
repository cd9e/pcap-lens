import { gunzipSync } from "node:zlib";
import type { Flow, HttpMessage, HttpExchange, Packet, Chunk } from "./model";
import { LIMITS, AnalysisBudget } from "./limits";
const MAX_BODY = LIMITS.bodyBytes;
// Capture analysis must retain malformed request targets rather than silently
// dropping the request. Anchor the version at the end so embedded spaces are
// preserved; no target decoding or execution takes place here.
const REQUEST_LINE = /^([!#$%&'*+.^_`|~0-9A-Za-z-]+) ([^\r\n]+) HTTP\/1\.[01]$/;
const RESPONSE_LINE = /^HTTP\/1\.[01] (\d{3})(?: [^\r\n]*)?$/;
function messages(
  bytes: number[],
  ids: number[],
  packets: Packet[],
  closed: boolean,
  budget: AnalysisBudget,
  requestMethods: string[] = [],
  spans: Chunk["spans"] = [],
): HttpMessage[] {
  const buf = Buffer.from(bytes);
  const result: HttpMessage[] = [];
  let offset = 0;
  while (offset < buf.length) {
    const firstLine = buf
      .subarray(offset, Math.min(buf.length, offset + 8192))
      .toString("latin1")
      .split("\r\n", 1)[0];
    if (!REQUEST_LINE.test(firstLine) && !RESPONSE_LINE.test(firstLine)) break;
    // Search only the bounded header window, rather than scanning arbitrary body data.
    let headerEnd = buf
      .subarray(0, Math.min(buf.length, offset + LIMITS.httpHeaderBytes + 4))
      .indexOf("\r\n\r\n", offset);
    const partialHeader = headerEnd < 0;
    if (partialHeader && buf.length - offset > LIMITS.httpHeaderBytes)
      throw new Error("HTTP header exceeds analysis limit");
    if (partialHeader) headerEnd = buf.length;
    const lines = buf
      .subarray(offset, headerEnd)
      .toString("latin1")
      .split("\r\n");
    const startLine = lines.shift()!;
    const request = REQUEST_LINE.exec(startLine),
      response = RESPONSE_LINE.exec(startLine);
    if (!request && !response) break;
    budget.reserveMessage();
    if (lines.length > LIMITS.httpHeaders)
      throw new Error("Too many HTTP headers");
    const headers: Record<string, string> = Object.create(null);
    const headerRanges = [
      {
        name: "Start line",
        value: startLine.slice(0, 256),
        start: offset,
        length: startLine.length,
      },
    ];
    let headerOffset = offset + startLine.length + 2;
    for (const line of lines) {
      const i = line.indexOf(":");
      if (i > 0) {
        const key = line.slice(0, i).toLowerCase();
        headers[key] = headers[key]
          ? headers[key] + ", " + line.slice(i + 1).trim()
          : line.slice(i + 1).trim();
        headerRanges.push({
          name: line.slice(0, i),
          value: line.slice(i + 1).trim(),
          start: headerOffset,
          length: line.length,
        });
      }
      headerOffset += line.length + 2;
    }
    const m: HttpMessage = {
      startLine,
      headers,
      body: [],
      packetIds: ids,
      time: packets[ids[0] - 1].time,
      endTime: packets[ids.at(-1)! - 1].time,
      complete: !partialHeader,
      diagnostics: [],
      method: request?.[1],
      url: request?.[2],
      status: response ? Number(response[1]) : undefined,
    };
    if (request && /[ \t]/.test(request[2])) {
      m.diagnostics.push({ code: "http.unescapedTargetWhitespace" });
    }
    let pos = Math.min(headerEnd + 4, buf.length),
      body = Buffer.alloc(0);
    const status = m.status ?? 0;
    const method =
      requestMethods[result.filter((x) => (x.status ?? 0) >= 200).length];
    const noBody =
      response &&
      (method === "HEAD" || status < 200 || status === 204 || status === 304);
    if (partialHeader) {
      m.complete = false;
    } else if (noBody) {
      /* RFC bodyless responses do not consume Content-Length bytes. */
    } else if (
      headers["transfer-encoding"]?.toLowerCase().split(",").at(-1)?.trim() ===
      "chunked"
    ) {
      const pieces: Buffer[] = [];
      let total = 0;
      while (true) {
        const e = buf.indexOf("\r\n", pos);
        if (e < 0) {
          m.complete = false;
          pos = buf.length;
          break;
        }
        const line = buf.subarray(pos, e).toString("ascii").split(";")[0];
        if (!/^[0-9a-f]+$/i.test(line)) {
          m.complete = false;
          pos = buf.length;
          break;
        }
        const n = parseInt(line, 16);
        pos = e + 2;
        if (n === 0) {
          if (buf.subarray(pos, pos + 2).toString() === "\r\n") pos += 2;
          else {
            const t = buf.indexOf("\r\n\r\n", pos);
            m.complete = t >= 0;
            pos = t < 0 ? buf.length : t + 4;
          }
          break;
        }
        if (total + n > MAX_BODY) {
          m.complete = false;
          m.diagnostics.push({ code: "http.bodyLimit" });
          pos = buf.length;
          break;
        }
        pieces.push(buf.subarray(pos, Math.min(pos + n, buf.length)));
        total += n;
        if (
          pos + n + 2 > buf.length ||
          buf.subarray(pos + n, pos + n + 2).toString() !== "\r\n"
        ) {
          m.complete = false;
          pos = buf.length;
          break;
        }
        pos += n + 2;
      }
      body = Buffer.concat(pieces);
    } else if (headers["content-length"] !== undefined) {
      const value = headers["content-length"];
      if (!/^\d+$/.test(value) || Number(value) > MAX_BODY) {
        m.complete = false;
        m.diagnostics.push({ code: "http.invalidLength" });
        pos = buf.length;
      } else {
        const n = Number(value);
        body = buf.subarray(pos, Math.min(pos + n, buf.length));
        m.complete = pos + n <= buf.length;
        if (!m.complete)
          m.diagnostics.push({
            code: "http.bodyLengthMismatch",
            evidence: `Content-Length=${n}; captured=${body.length}; missing=${n - body.length}`,
          });
        pos = Math.min(pos + n, buf.length);
      }
    } else if (response) {
      body = buf.subarray(pos);
      pos = buf.length;
      m.complete = closed;
    }
    if (body.length > MAX_BODY)
      throw new Error("HTTP body exceeds analysis limit");
    if (!m.complete) m.diagnostics.push({ code: "http.incomplete" });
    if (headers["content-encoding"]?.toLowerCase() === "gzip" && body.length) {
      try {
        if (budget.remainingBodyBytes <= 0)
          throw new Error("Body budget exhausted");
        body = gunzipSync(body, {
          maxOutputLength: Math.min(MAX_BODY, budget.remainingBodyBytes),
        });
      } catch {
        m.diagnostics.push({ code: "http.gzipFailed" });
      }
    }
    budget.retainBody(body.length);
    const sources = spans.filter(
      (s) => s.start < pos && s.start + s.length > offset,
    );
    m.packetIds = [...new Set(sources.map((s) => s.packetId))];
    if (!m.packetIds.length) m.packetIds = ids;
    m.time = Math.min(...m.packetIds.map((id) => packets[id - 1].time));
    m.endTime = Math.max(...m.packetIds.map((id) => packets[id - 1].time));
    for (const span of sources) {
      const start = Math.max(span.start, offset),
        end = Math.min(span.start + span.length, pos);
      packets[span.packetId - 1].fields.push({
        name: "HTTP (reassembled)",
        value: startLine.slice(0, 256),
        offset: span.packetOffset + start - span.start,
        length: end - start,
        children: headerRanges
          .filter(
            (range) => range.start < end && range.start + range.length > start,
          )
          .map((range) => {
            const first = Math.max(start, range.start);
            const last = Math.min(end, range.start + range.length);
            return {
              name: range.name.slice(0, 128),
              value: range.value.slice(0, 256),
              offset: span.packetOffset + first - span.start,
              length: last - first,
            };
          }),
      });
    }
    m.body = Array.from(body);
    result.push(m);
    if (pos <= offset) break;
    offset = pos;
    if (
      status === 101 ||
      (method === "CONNECT" && status >= 200 && status < 300)
    )
      break;
  }
  return result;
}
export function analyzeHttp(flows: Flow[], packets: Packet[]): HttpExchange[] {
  const out: HttpExchange[] = [];
  const budget = new AnalysisBudget();
  for (const f of flows) {
    if (f.transport !== "TCP") continue;
    const req: HttpMessage[] = [],
      res: HttpMessage[] = [];
    for (const c of f.chunks.filter(
      (c) => !Buffer.from(c.bytes.slice(0, 5)).equals(Buffer.from("HTTP/")),
    )) {
      const m = messages(
        c.bytes,
        c.packetIds,
        packets,
        c.closed,
        budget,
        [],
        c.spans,
      );
      req.push(...m.filter((x) => x.method));
    }
    req.sort((a, b) => a.time - b.time);
    for (const c of f.chunks.filter((c) =>
      Buffer.from(c.bytes.slice(0, 5)).equals(Buffer.from("HTTP/")),
    ))
      res.push(
        ...messages(
          c.bytes,
          c.packetIds,
          packets,
          c.closed,
          budget,
          req.map((r) => r.method!),
          c.spans,
        ).filter((x) => x.status),
      );
    res.sort((a, b) => a.time - b.time);
    let i = 0,
      j = 0;
    while (i < req.length || j < res.length) {
      const request = req[i],
        response = res[j];
      let a: HttpMessage | undefined, b: HttpMessage | undefined;
      if (response && (!request || response.time < request.time)) {
        b = response;
        j++;
      } else {
        a = request;
        i++;
        if (response) {
          b = response;
          j++;
          while (b.status! < 200 && b.status !== 101 && j < res.length)
            b = res[j++];
        }
      }
      const packetIds = [
        ...new Set([...(a?.packetIds ?? []), ...(b?.packetIds ?? [])]),
      ];
      out.push({
        id: String(out.length + 1),
        flowId: f.id,
        request: a,
        response: b,
        packetIds,
      });
      for (const message of [a, b]) {
        if (!message) continue;
        for (const id of message.packetIds) {
          const p = packets[id - 1];
          p.protocol = "HTTP";
          p.filter.http = true;
          const values: Record<string, string | number> = message.method
            ? {
                "http.request.method": message.method,
                "http.request.uri": message.url!,
                "http.host": message.headers.host ?? "",
              }
            : { "http.response.code": message.status! };
          for (const [key, value] of Object.entries(values)) {
            const old = p.filter[key];
            p.filter[key] = [
              ...new Set([
                ...(Array.isArray(old) ? old : old === undefined ? [] : [old]),
                value,
              ]),
            ];
          }
        }
      }
    }
  }
  return out;
}
