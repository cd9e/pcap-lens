import React, { useState } from "react";
import type {
  Capture,
  Packet,
  Field,
  HttpMessage,
  Flow,
  Diagnostic,
} from "../core/model";
import { dictionary, diagnosticText } from "./i18n";
import { vscode } from "./bridge";
import { time, ms } from "./format";
function Diagnostics({
  items,
  language,
}: {
  items: Diagnostic[];
  language: string;
}) {
  return (
    <>
      {items.slice(0, 200).map((d, i) => (
        <div className="diagnostic" key={i}>
          {diagnosticText(d.code, language)}
          {d.evidence && <small> · {d.evidence}</small>}
        </div>
      ))}
    </>
  );
}
function Hex({
  bytes,
  field,
  onByte,
}: {
  bytes: number[];
  field?: Field;
  onByte?: (offset: number) => void;
}) {
  const [limit, setLimit] = useState(4096);
  return (
    <div className="hex">
      {Array.from(
        { length: Math.ceil(Math.min(bytes.length, limit) / 16) },
        (_, i) => (
          <div className="hexrow" key={i}>
            <span className="offset">
              {(i * 16).toString(16).padStart(6, "0")}
            </span>
            <span className="hexbytes">
              {bytes.slice(i * 16, i * 16 + 16).map((b, j) => {
                const o = i * 16 + j;
                return (
                  <button
                    key={o}
                    className={
                      field &&
                      o >= field.offset &&
                      o < field.offset + field.length
                        ? "highlight"
                        : ""
                    }
                    onClick={() => onByte?.(o)}
                  >
                    {b.toString(16).padStart(2, "0")}
                  </button>
                );
              })}
            </span>
            <span className="ascii">
              {bytes
                .slice(i * 16, i * 16 + 16)
                .map((b) => (b >= 32 && b < 127 ? String.fromCharCode(b) : "."))
                .join("")}
            </span>
          </div>
        ),
      )}
      {bytes.length > limit && (
        <button onClick={() => setLimit(limit + 4096)}>+ 4096 bytes</button>
      )}
    </div>
  );
}
export function Message({
  message: m,
  side,
  id,
  language,
}: {
  message?: HttpMessage;
  side: "request" | "response";
  id: string;
  language: string;
}) {
  const t = dictionary(language),
    [view, setView] = useState("headers");
  if (!m)
    return (
      <article>
        <h3>{t[side]}</h3>
        <p>{t.missing}</p>
      </article>
    );
  const mime = m.headers["content-type"] ?? "";
  const binary =
    !!mime && !/text|json|xml|javascript|form-urlencoded/i.test(mime);
  const previewBytes = m.body.slice(0, 256 * 1024);
  const textView = !binary && (view === "body" || view === "json");
  let text = textView
    ? new TextDecoder().decode(Uint8Array.from(previewBytes))
    : "";
  if (view === "json" && m.body.length <= 256 * 1024)
    try {
      text = JSON.stringify(JSON.parse(text), null, 2);
    } catch {}
  return (
    <article>
      <h3>
        {t[side]}{" "}
        <span className="badge">{m.complete ? t.complete : t.incomplete}</span>
      </h3>
      <strong className="startline">{m.startLine}</strong>
      <div className="actions">
        {["headers", "body", "hex", ...(!binary ? ["json"] : [])].map((v) => (
          <button
            className={view === v ? "active" : ""}
            key={v}
            onClick={() => setView(v)}
          >
            {t[v as "headers"]}
          </button>
        ))}
        <button
          onClick={() => vscode.postMessage({ type: "export", id, side })}
        >
          {t.export}
        </button>
      </div>
      <Diagnostics items={m.diagnostics} language={language} />
      {view === "headers" ? (
        <dl>
          {Object.entries(m.headers).map(([k, v]) => (
            <React.Fragment key={k}>
              <dt>{k}</dt>
              <dd>{v}</dd>
            </React.Fragment>
          ))}
        </dl>
      ) : view === "hex" || binary ? (
        <Hex bytes={m.body} />
      ) : (
        <pre>{text}</pre>
      )}
      {textView && m.body.length > previewBytes.length && (
        <p>{t.previewLimit}</p>
      )}
      <small>
        {t.duration}: {ms(m.endTime - m.time)} · {t.packets}:{" "}
        {m.packetIds.join(", ")}
      </small>
    </article>
  );
}
export function Stream({
  flow,
  packets,
  language,
}: {
  flow: Flow;
  packets: Packet[];
  language: string;
}) {
  const t = dictionary(language),
    [direction, setDirection] = useState("all"),
    [hex, setHex] = useState(false),
    [segmentLimit, setSegmentLimit] = useState(200);
  return (
    <>
      <div className="actions">
        <select
          value={direction}
          onChange={(e) => setDirection(e.target.value)}
        >
          <option value="all">{t.all}</option>
          <option value="0">{t.client}</option>
          <option value="1">{t.server}</option>
        </select>
        <button onClick={() => setHex(!hex)}>{hex ? t.text : t.hex}</button>
      </div>
      <Diagnostics items={flow.diagnostics} language={language} />
      {flow.chunks
        .flatMap((c) =>
          c.spans.map((s, i) => ({
            ...c,
            bytes: c.bytes.slice(s.start, s.start + s.length),
            time: packets[s.packetId - 1].time,
            packetIds: [s.packetId],
            gapBefore: i === 0 ? c.gapBefore : 0,
          })),
        )
        .sort((a, b) => (direction === "all" ? a.time - b.time : 0))
        .filter((c) => direction === "all" || String(c.direction) === direction)
        .slice(0, segmentLimit)
        .map((c, i) => (
          <article className={"chunk direction" + c.direction} key={i}>
            <h3>
              {c.direction === 0 ? t.client : t.server} · {time(c.time)}
            </h3>
            {c.gapBefore > 0 && (
              <div className="diagnostic">
                {t.gap}: {c.gapBefore}
              </div>
            )}
            {hex ? (
              <Hex bytes={c.bytes} />
            ) : (
              <pre>{new TextDecoder().decode(Uint8Array.from(c.bytes))}</pre>
            )}
            <small>
              {t.packets}: {c.packetIds.join(", ")}
            </small>
          </article>
        ))}
      {flow.chunks.reduce((sum, c) => sum + c.spans.length, 0) >
        segmentLimit && (
        <button onClick={() => setSegmentLimit(segmentLimit + 200)}>
          {t.more} (+200)
        </button>
      )}
    </>
  );
}
export function PacketDetail({
  packet,
  language,
}: {
  packet: Packet;
  language: string;
}) {
  const t = dictionary(language),
    [field, setField] = useState<Field>();
  const flatten = (fs: Field[]): Field[] =>
    fs.flatMap((f) => [f, ...flatten(f.children ?? [])]);
  const list = flatten(packet.fields);
  const render = (fs: Field[]) =>
    fs.map((f, i) => (
      <li key={i}>
        <button
          className={field === f ? "highlight" : ""}
          onClick={() => setField(f)}
        >
          {f.name}: {f.value}
        </button>
        {f.children && <ul>{render(f.children)}</ul>}
      </li>
    ));
  return (
    <>
      <Diagnostics items={packet.diagnostics} language={language} />
      <small>{t.hint}</small>
      <div className="packet-detail">
        <div>
          <h3>{t.fields}</h3>
          <ul>{render(packet.fields)}</ul>
        </div>
        <div>
          <h3>{t.raw}</h3>
          <Hex
            bytes={packet.bytes}
            field={field}
            onByte={(o) =>
              setField(
                list
                  .filter((f) => o >= f.offset && o < f.offset + f.length)
                  .sort((a, b) => a.length - b.length)[0],
              )
            }
          />
        </div>
      </div>
    </>
  );
}
export function Statistics({
  capture,
  visible,
  language,
}: {
  capture: Capture;
  visible: Set<number>;
  language: string;
}) {
  const t = dictionary(language);
  const [flowLimit, setFlowLimit] = useState(200);
  const all = capture.packets,
    filtered = all.filter((p) => visible.has(p.id));
  return (
    <div className="statistics">
      <h2>{t.overview}</h2>
      <div className="cards">
        {[
          [t.total, all],
          [t.filtered, filtered],
        ].map(([label, ps]) => (
          <article key={String(label)}>
            <h3>{String(label)}</h3>
            <strong>{(ps as Packet[]).length.toLocaleString()}</strong>{" "}
            {t.count}
            <p>
              {(ps as Packet[])
                .reduce((n, p) => n + p.bytes.length, 0)
                .toLocaleString()}{" "}
              {t.bytes}
            </p>
          </article>
        ))}
      </div>
      <table>
        <thead>
          <tr>
            {[
              t.source,
              t.destination,
              t.protocol,
              "A → B " + t.count,
              "A → B " + t.bytes,
              "B → A " + t.count,
              "B → A " + t.bytes,
              t.duration,
            ].map((x) => (
              <th key={x}>{x}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {capture.flows
            .filter((f) => f.packetIds.some((id) => visible.has(id)))
            .slice(0, flowLimit)
            .map((f) => {
              const ps = f.packetIds
                .map((id) => all[id - 1])
                .filter((p) => visible.has(p.id));
              if (!ps.length) return null;
              const a = ps.filter(
                  (p) => `[${p.src}]:${p.srcPort}` === f.endpoints[0],
                ),
                b = ps.filter(
                  (p) => `[${p.src}]:${p.srcPort}` !== f.endpoints[0],
                );
              return (
                <tr key={f.id}>
                  <td>{f.endpoints[0]}</td>
                  <td>{f.endpoints[1]}</td>
                  <td>{f.transport}</td>
                  <td>{a.length}</td>
                  <td>{a.reduce((n, p) => n + p.bytes.length, 0)}</td>
                  <td>{b.length}</td>
                  <td>{b.reduce((n, p) => n + p.bytes.length, 0)}</td>
                  <td>
                    {ms(
                      Math.max(...ps.map((p) => p.time)) -
                        Math.min(...ps.map((p) => p.time)),
                    )}
                  </td>
                </tr>
              );
            })}
        </tbody>
      </table>
      {capture.flows.length > flowLimit && (
        <button onClick={() => setFlowLimit(flowLimit + 200)}>
          {t.more} (+200)
        </button>
      )}
    </div>
  );
}
