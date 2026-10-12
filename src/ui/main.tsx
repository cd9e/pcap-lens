import React, { useEffect, useMemo, useState } from "react";
import { createRoot } from "react-dom/client";
import type {
  Capture,
  Packet,
  Field,
  HttpMessage,
  HttpExchange,
  Flow,
  DnsExchange,
  Diagnostic,
} from "../core/model";
import { compileFilter, fields, FilterError } from "../core/filter";
import { dictionary, diagnosticText } from "./i18n";
import "./style.css";
import { vscode } from "./bridge";
import { time, ms } from "./format";
import { Message, Stream, PacketDetail, Statistics } from "./components";
type Tab = "http" | "flows" | "packets" | "dns" | "stats";
const saved = vscode.getState() ?? {};
function App() {
  const [language, setLanguage] = useState("en"),
    [name, setName] = useState(""),
    [remoteName, setRemoteName] = useState<string>(),
    [canOpenWireshark, setCanOpenWireshark] = useState(true),
    [capture, setCapture] = useState<Capture>(),
    [error, setError] = useState("");
  const [tab, setTab] = useState<Tab>(saved.tab ?? "http"),
    [selection, setSelection] = useState<Record<string, string>>(
      saved.selection ?? {},
    ),
    [input, setInput] = useState(saved.filter ?? ""),
    [filter, setFilter] = useState(saved.filter ?? ""),
    [filterError, setFilterError] = useState(""),
    [scope, setScope] = useState<number[] | null>(null),
    [history, setHistory] = useState<{ tab: Tab; scope: number[] | null }[]>(
      [],
    );
  const t = dictionary(language);
  useEffect(() => {
    const listener = (event: MessageEvent) => {
      const m = event.data;
      if (m.type === "init") {
        setLanguage(m.language);
        setName(m.name);
        setRemoteName(m.remoteName);
        setCanOpenWireshark(m.canOpenWireshark ?? !m.remoteName);
      }
      if (m.type === "capture") setCapture(m.capture);
      if (m.type === "error") setError(m.error);
    };
    window.addEventListener("message", listener);
    vscode.postMessage({ type: "ready" });
    return () => window.removeEventListener("message", listener);
  }, []);
  useEffect(() => {
    vscode.setState({ tab, selection, filter });
  }, [tab, selection, filter]);
  const visible = useMemo(() => {
    if (!capture) return new Set<number>();
    let predicate;
    try {
      predicate = compileFilter(filter);
    } catch {
      predicate = () => true;
    }
    return new Set(capture.packets.filter(predicate).map((p) => p.id));
  }, [capture, filter]);
  const jump = (next: Tab, ids?: number[], id?: string) => {
    setHistory((h) => [...h, { tab, scope }]);
    setScope(ids ?? null);
    setTab(next);
    if (id) setSelection((s) => ({ ...s, [next]: id }));
  };
  const apply = () => {
    try {
      compileFilter(input);
      setFilter(input);
      setScope(null);
      setFilterError("");
    } catch (e) {
      setFilterError(
        e instanceof FilterError
          ? `${e.message} (${e.position + 1})`
          : String(e),
      );
    }
  };
  const matches = (ids: number[]) =>
    ids.some((id) => visible.has(id)) &&
    (!scope || ids.some((id) => scope.includes(id)));
  const [rowLimit, setRowLimit] = useState(200);
  useEffect(() => setRowLimit(200), [tab, filter, scope]);
  const selected = selection[tab];
  let rows: { id: string; cells: React.ReactNode[] }[] = [],
    columns: string[] = [];
  let detail: React.ReactNode = <div className="empty">{t.select}</div>;
  if (capture) {
    if (tab === "http") {
      columns = [
        "#",
        t.time,
        t.method,
        t.host,
        t.url,
        t.status,
        t.latency,
        t.size,
      ];
      rows = capture.http
        .filter((x) => matches(x.packetIds))
        .map((x) => ({
          id: x.id,
          cells: [
            x.id,
            time(x.request?.time ?? x.response!.time),
            x.request?.method ?? "—",
            x.request?.headers.host ?? "—",
            x.request?.url ?? "—",
            x.response?.status ?? t.noResponse,
            x.request && x.response
              ? ms(x.response.time - x.request.time)
              : "—",
            x.response?.body.length ?? "—",
          ],
        }));
      const x = capture.http.find((x) => x.id === selected);
      if (x)
        detail = (
          <>
            <div className="detailbar">
              <strong>{x.request?.url ?? x.response?.startLine}</strong>
              <button onClick={() => jump("flows", undefined, x.flowId)}>
                {t.stream}
              </button>
              <button onClick={() => jump("packets", x.packetIds)}>
                {t.related}
              </button>
            </div>
            <div className="pair">
              <Message
                key={x.id + "req"}
                message={x.request}
                side="request"
                id={x.id}
                language={language}
              />
              <Message
                key={x.id + "res"}
                message={x.response}
                side="response"
                id={x.id}
                language={language}
              />
            </div>
          </>
        );
    }
    if (tab === "flows") {
      columns = [
        "#",
        t.protocol,
        t.source,
        t.destination,
        t.count,
        t.bytes,
        t.duration,
      ];
      rows = capture.flows
        .filter((x) => matches(x.packetIds))
        .map((f) => {
          const ps = f.packetIds.map((id) => capture.packets[id - 1]);
          return {
            id: f.id,
            cells: [
              f.id,
              f.transport,
              ...f.endpoints,
              ps.length,
              ps.reduce((n, p) => n + p.bytes.length, 0),
              ms(
                Math.max(...ps.map((p) => p.time)) -
                  Math.min(...ps.map((p) => p.time)),
              ),
            ],
          };
        });
      const f = capture.flows.find((f) => f.id === selected);
      if (f)
        detail = (
          <>
            <div className="detailbar">
              <strong>{f.endpoints.join(" ⇄ ")}</strong>
              <button onClick={() => jump("packets", f.packetIds)}>
                {t.related}
              </button>
            </div>
            <Stream
              key={f.id}
              flow={f}
              packets={capture.packets}
              language={language}
            />
          </>
        );
    }
    if (tab === "packets") {
      columns = [
        "#",
        t.time,
        t.source,
        t.destination,
        t.protocol,
        t.bytes,
        t.diagnostics,
      ];
      rows = capture.packets
        .filter((p) => matches([p.id]))
        .map((p) => ({
          id: String(p.id),
          cells: [
            p.id,
            time(p.time),
            p.src + (p.srcPort !== undefined ? ":" + p.srcPort : ""),
            p.dst + (p.dstPort !== undefined ? ":" + p.dstPort : ""),
            p.protocol,
            p.bytes.length,
            p.diagnostics
              .map((d) => diagnosticText(d.code, language))
              .join("; "),
          ],
        }));
      const p = capture.packets.find((p) => String(p.id) === selected);
      if (p)
        detail = (
          <>
            <div className="detailbar">
              <strong>
                #{p.id} · {p.protocol}
              </strong>
              {p.flowId && (
                <button onClick={() => jump("flows", undefined, p.flowId)}>
                  {t.stream}
                </button>
              )}
            </div>
            <PacketDetail key={p.id} packet={p} language={language} />
          </>
        );
    }
    if (tab === "dns") {
      columns = ["#", t.name, t.type, t.answer, t.status, t.latency];
      rows = capture.dns
        .filter((x) => matches(x.packetIds))
        .map((x) => ({
          id: x.id,
          cells: [
            x.id,
            (x.request ?? x.response)!.name,
            (x.request ?? x.response)!.queryType,
            x.response?.answers.join(", ") ?? "—",
            x.response ? `RCODE ${x.response.rcode}` : t.noResponse,
            x.request && x.response
              ? ms(x.response.time - x.request.time)
              : "—",
          ],
        }));
      const x = capture.dns.find((x) => x.id === selected);
      if (x)
        detail = (
          <>
            <div className="detailbar">
              <button onClick={() => jump("packets", x.packetIds)}>
                {t.related}
              </button>
            </div>
            <pre>{JSON.stringify(x, null, 2)}</pre>
          </>
        );
    }
  }
  return (
    <main>
      <header>
        <div>
          <span className="brand">◈ PCAP LENS</span>
          <span className="filename">{name}</span>
          {remoteName && (
            <span className="badge">
              {t.remoteAnalysis} · {remoteName}
            </span>
          )}
        </div>
        <div className="actions">
          <button
            onClick={() => vscode.postMessage({ type: "configureWireshark" })}
          >
            {t.configureWireshark}
          </button>
          <button
            disabled={!canOpenWireshark}
            title={canOpenWireshark ? t.wireshark : t.remoteWireshark}
            onClick={() => vscode.postMessage({ type: "wireshark" })}
          >
            {t.wireshark} ↗
          </button>
        </div>
      </header>
      <form
        className="filter"
        onSubmit={(e) => {
          e.preventDefault();
          apply();
        }}
      >
        <span>⌕</span>
        <input
          aria-label={t.filter}
          list="filter-fields"
          placeholder={t.filter}
          value={input}
          onChange={(e) => setInput(e.target.value)}
        />
        <datalist id="filter-fields">
          {[...fields.keys()].map((f) => (
            <option key={f} value={input.replace(/[\w.]*$/, f)} />
          ))}
        </datalist>
        <button type="submit">{t.apply}</button>
      </form>
      {filterError && (
        <div role="alert" className="error">
          {filterError}
        </div>
      )}
      <nav>
        {(["http", "flows", "packets", "dns", "stats"] as Tab[]).map((key) => (
          <button
            className={tab === key ? "active" : ""}
            key={key}
            onClick={() => {
              setTab(key);
              setScope(null);
            }}
          >
            {t[key]}
          </button>
        ))}
        <span className="nav-meta">
          {capture?.format.toUpperCase()} · {visible.size} /{" "}
          {capture?.packets.length ?? 0} {t.count}
        </span>
      </nav>
      {error && (
        <div role="alert" className="error">
          {error}
        </div>
      )}
      {!capture ? (
        <div className="empty">{error ? "" : t.loading}</div>
      ) : tab === "stats" ? (
        <Statistics capture={capture} visible={visible} language={language} />
      ) : (
        <>
          {history.length > 0 && (
            <div className="detailbar">
              <button
                onClick={() => {
                  const h = history.at(-1)!;
                  setTab(h.tab);
                  setScope(h.scope);
                  setHistory(history.slice(0, -1));
                }}
              >
                ← {t.back}
              </button>
              {scope && (
                <span>
                  {t.related} · {scope.length}
                </span>
              )}
            </div>
          )}
          <div
            className="listing"
            key={tab}
            ref={(el) => {
              if (el) el.scrollTop = saved.scroll?.[tab] ?? 0;
            }}
            onScroll={(e) => {
              saved.scroll = {
                ...saved.scroll,
                [tab]: e.currentTarget.scrollTop,
              };
              vscode.setState({ ...vscode.getState(), scroll: saved.scroll });
            }}
          >
            <table>
              <thead>
                <tr>
                  {columns.map((c, i) => (
                    <th key={i}>{c}</th>
                  ))}
                </tr>
              </thead>
              <tbody>
                {rows.slice(0, rowLimit).map((r) => (
                  <tr
                    key={r.id}
                    tabIndex={0}
                    aria-selected={selected === r.id}
                    className={selected === r.id ? "selected" : ""}
                    onClick={() => setSelection((s) => ({ ...s, [tab]: r.id }))}
                    onKeyDown={(e) => {
                      if (e.key === "Enter")
                        setSelection((s) => ({ ...s, [tab]: r.id }));
                    }}
                  >
                    {r.cells.map((c, i) => (
                      <td key={i} title={typeof c === "string" ? c : undefined}>
                        {c}
                      </td>
                    ))}
                  </tr>
                ))}
              </tbody>
            </table>
            {rows.length > rowLimit && (
              <button onClick={() => setRowLimit(rowLimit + 200)}>
                {t.more} (+200)
              </button>
            )}
            {!rows.length && <div className="empty">{t.empty}</div>}
          </div>
          <section className="details">
            {rows.some((r) => r.id === selected) ? (
              detail
            ) : (
              <div className="empty">{t.select}</div>
            )}
          </section>
        </>
      )}
    </main>
  );
}
createRoot(document.getElementById("root")!).render(<App />);
