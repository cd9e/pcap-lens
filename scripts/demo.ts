import { writeFileSync } from "node:fs";
import { pcap, pcapng, tcp, udp, dns } from "../tests/fixtures";
const requests = [
  "GET /api/users HTTP/1.1\r\nHost: api.example.com\r\nAccept: application/json\r\n\r\n",
  'POST /api/login HTTP/1.1\r\nHost: api.example.com\r\nContent-Type: application/json\r\nContent-Length: 16\r\n\r\n{"user":"alice"}',
];
const bodies = [
  '{"users":[{"id":1,"name":"Alice"}],"total":1}',
  '{"error":"invalid credentials"}',
];
let client = 100,
  server = 900;
const packets = [];
for (let i = 0; i < requests.length; i++) {
  const r = requests[i];
  packets.push(tcp(r, client));
  client += Buffer.byteLength(r);
  const status = i ? "401 Unauthorized" : "200 OK";
  const reply = `HTTP/1.1 ${status}\r\nContent-Type: application/json\r\nContent-Length: ${Buffer.byteLength(bodies[i])}\r\n\r\n${bodies[i]}`;
  packets.push(tcp(reply, server, true));
  server += Buffer.byteLength(reply);
}
packets.push(udp(dns()), udp(dns(true), true));
writeFileSync("fixtures/demo.pcap", pcap(packets));
writeFileSync("fixtures/demo.pcapng", pcapng(packets));
