import { LIMITS } from "./limits";
import type { Packet } from "./model";
type Value = string | number | boolean;
type Getter = (p: Packet) => Value[];
type Operator = (a: Value, b: Value) => boolean;
export const fields = new Map<string, Getter>();
export const operators = new Map<string, Operator>();
export function registerField(name: string, get: Getter) {
  if (fields.has(name)) throw new Error(`Duplicate field ${name}`);
  fields.set(name, get);
}
export function registerOperator(name: string, op: Operator) {
  if (operators.has(name)) throw new Error(`Duplicate operator ${name}`);
  operators.set(name, op);
}
for (const name of [
  "http",
  "tcp",
  "udp",
  "dns",
  "ip",
  "ipv6",
  "frame.len",
  "frame.number",
  "ip.src",
  "ip.dst",
  "ipv6.src",
  "ipv6.dst",
  "tcp.srcport",
  "tcp.dstport",
  "udp.srcport",
  "udp.dstport",
  "tcp.seq",
  "tcp.ack",
  "tcp.flags.syn",
  "tcp.flags.ack",
  "tcp.flags.reset",
  "tcp.flags.fin",
  "tcp.flags.push",
  "tcp.flags.urg",
  "http.request.method",
  "http.request.uri",
  "http.response.code",
  "http.host",
  "dns.qry.name",
])
  registerField(name, (p) =>
    p.filter[name] === undefined
      ? []
      : Array.isArray(p.filter[name])
        ? p.filter[name]
        : [p.filter[name]],
  );
for (const [name, members] of Object.entries({
  "ip.addr": ["ip.src", "ip.dst"],
  "ipv6.addr": ["ipv6.src", "ipv6.dst"],
  "tcp.port": ["tcp.srcport", "tcp.dstport"],
  "udp.port": ["udp.srcport", "udp.dstport"],
}))
  registerField(name, (p) => members.flatMap((x) => fields.get(x)!(p)));
for (const [name, fn] of Object.entries<Operator>({
  "==": (a, b) => a === b,
  "!=": (a, b) => a !== b,
  ">": (a, b) => typeof a === "number" && typeof b === "number" && a > b,
  ">=": (a, b) => typeof a === "number" && typeof b === "number" && a >= b,
  "<": (a, b) => typeof a === "number" && typeof b === "number" && a < b,
  "<=": (a, b) => typeof a === "number" && typeof b === "number" && a <= b,
  contains: (a, b) => String(a).includes(String(b)),
}))
  registerOperator(name, fn);
export class FilterError extends Error {
  constructor(
    public position: number,
    message: string,
  ) {
    super(message);
  }
}
export function compileFilter(source: string): (p: Packet) => boolean {
  if (source.length > LIMITS.filterCharacters)
    throw new FilterError(LIMITS.filterCharacters, "Filter is too long");
  let depth = 0;
  const tokens: { text: string; pos: number; quoted: boolean }[] = [];
  const re =
    /\s+|"(?:\\.|[^"\\])*"|'(?:\\.|[^'\\])*'|&&|\|\||==|!=|>=|<=|[()!<>]|[\w.:/\-]+/gy;
  let o = 0;
  while (o < source.length) {
    re.lastIndex = o;
    const m = re.exec(source);
    if (!m) throw new FilterError(o, "Unexpected character");
    if (!/^\s/.test(m[0]))
      tokens.push({ text: m[0], pos: o, quoted: /^["']/.test(m[0]) });
    if (tokens.length > LIMITS.filterTokens)
      throw new FilterError(o, "Too many filter tokens");
    o = re.lastIndex;
  }
  let i = 0;
  const peek = () => tokens[i]?.text;
  const fail = (msg: string): never => {
    throw new FilterError(tokens[i]?.pos ?? source.length, msg);
  };
  const take = () => tokens[i++];
  type Predicate = (p: Packet) => boolean;
  const atom = (): Predicate => {
    if (++depth > LIMITS.filterDepth) fail("Filter nesting limit exceeded");
    try {
      return parseAtom();
    } finally {
      depth--;
    }
  };
  const parseAtom = (): Predicate => {
    if (peek() === "!" || peek() === "not") {
      take();
      const a = atom();
      return (p) => !a(p);
    }
    if (peek() === "(") {
      take();
      const a = or();
      if (peek() !== ")") fail("Expected )");
      take();
      return a;
    }
    const t = take();
    if (!t) fail("Expected field");
    const get = fields.get(t.text);
    if (!get) throw new FilterError(t.pos, `Unknown field: ${t.text}`);
    const op = operators.get(peek());
    if (!op) return (p) => get!(p).some(Boolean);
    take();
    const v = take();
    if (!v) fail("Expected value");
    let value: Value = v.text;
    if (v.quoted) {
      try {
        value =
          v.text[0] === '"'
            ? JSON.parse(v.text)
            : v.text.slice(1, -1).replace(/\\'/g, "'");
      } catch {
        throw new FilterError(v.pos, "Invalid string");
      }
    } else if (/^\d+(\.\d+)?$/.test(v.text)) value = Number(v.text);
    else if (v.text === "true" || v.text === "false") value = v.text === "true";
    return (p) => get!(p).some((x) => op(x, value));
  };
  const and = (): Predicate => {
    let a = atom();
    while (peek() === "&&" || peek() === "and") {
      take();
      const left = a,
        right = atom();
      a = (p) => left(p) && right(p);
    }
    return a;
  };
  const or = (): Predicate => {
    let a = and();
    while (peek() === "||" || peek() === "or") {
      take();
      const left = a,
        right = and();
      a = (p) => left(p) || right(p);
    }
    return a;
  };
  if (!tokens.length) return () => true;
  const result = or();
  if (i < tokens.length) fail("Unexpected token");
  return result;
}
