/** Offsets always refer to bytes in one original packet, never rendered text. */
export interface Field {
  name: string;
  value: string;
  offset: number;
  length: number;
  children?: Field[];
}
export interface Diagnostic {
  code: string;
  evidence?: string;
}
export interface Packet {
  id: number;
  time: number;
  originalLength: number;
  bytes: number[];
  linkType: number;
  fields: Field[];
  diagnostics: Diagnostic[];
  protocol: string;
  src: string;
  dst: string;
  srcPort?: number;
  dstPort?: number;
  transport?: "TCP" | "UDP";
  seq?: number;
  ack?: number;
  flags?: number;
  payloadOffset?: number;
  payloadLength?: number;
  flowId?: string;
  filter: Record<
    string,
    string | number | boolean | (string | number | boolean)[]
  >;
}
export interface Chunk {
  direction: 0 | 1;
  spans: {
    start: number;
    length: number;
    packetId: number;
    packetOffset: number;
  }[];
  bytes: number[];
  packetIds: number[];
  time: number;
  gapBefore: number;
  closed: boolean;
}
export interface Flow {
  id: string;
  transport: string;
  endpoints: [string, string];
  packetIds: number[];
  chunks: Chunk[];
  diagnostics: Diagnostic[];
}
export interface HttpMessage {
  startLine: string;
  headers: Record<string, string>;
  body: number[];
  packetIds: number[];
  time: number;
  endTime: number;
  complete: boolean;
  diagnostics: Diagnostic[];
  method?: string;
  url?: string;
  status?: number;
}
export interface HttpExchange {
  id: string;
  flowId: string;
  request?: HttpMessage;
  response?: HttpMessage;
  packetIds: number[];
}
export interface DnsMessage {
  id: number;
  response: boolean;
  name: string;
  queryType: number;
  answers: string[];
  rcode: number;
  packetIds: number[];
  time: number;
}
export interface DnsExchange {
  id: string;
  request?: DnsMessage;
  response?: DnsMessage;
  packetIds: number[];
}
export interface Capture {
  format: string;
  packets: Packet[];
  flows: Flow[];
  http: HttpExchange[];
  dns: DnsExchange[];
  diagnostics: Diagnostic[];
}
