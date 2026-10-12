# Pcap Lens 使用说明

A lightweight, offline, HTTP-first capture viewer for VS Code. Click a `.pcap` or `.pcapng` file in the Explorer to open its analysis editor. No TShark, Python, capture driver, or network service is required.

## 当前能力 / Features

- HTTP/1.0 and HTTP/1.1 request/response list, headers, bodies, JSON formatting, chunked transfer decoding and bounded gzip decompression.
- TCP stream reconstruction with directional text/hex views, packet provenance, sequence wrap handling, and evidence for suspected overlap, reordering, capture gaps and RST.
- Ethernet, VLAN, IPv4/IPv6, TCP and UDP decoding, field tree and byte highlighting.
- DNS over UDP and TCP, query/response pairing, common answer types and latency.
- Expandable display-filter field/operator registry, connection totals and filtered statistics.
- Chinese and English UI following VS Code's language. Images and binary bodies are shown as hex; bodies can be exported.
- Open the original file in an existing Wireshark installation. Set `pcapLens.wiresharkPath` if it is not detected.

## 本地安装 / Install locally

完整打包流程见 [VSIX 打包说明](PACKAGING.md)。

Run `npm ci`, `npm run typecheck`, `npm test`, then `npm run package`. In VS Code, run **Extensions: Install from VSIX…** and choose `pcap-lens-0.1.3.vsix`.

Open `fixtures/demo.pcap` or `fixtures/demo.pcapng` to try HTTP and DNS views. In the source workspace, press F5 to start an Extension Development Host.

The package contains JavaScript only and is designed for Windows, macOS and Linux desktop VS Code. Native Windows/Linux Extension Host validation is still required before Marketplace release. Remote SSH is supported through the workspace extension host. Live capture remains out of scope. See [Remote SSH 使用说明](REMOTE_SSH.md).

## Filters

Press Enter to apply. Invalid expressions retain the previous valid result. HTTP and DNS rows retain both sides of a pair if either side matches. Packet and byte statistics count only packets that match the filter, not context retained in paired rows.

```text
http && tcp.port == 80
http.response.code >= 400
http.request.uri contains "/api"
ip.addr == 10.0.0.1 && !dns
tcp.flags.reset == 1
dns.qry.name contains "example.com"
```

Supported: `==`, `!=`, `>`, `>=`, `<`, `<=`, `contains`, `&&` / `and`, `||` / `or`, `!` / `not`, parentheses, quoted strings and numeric literals. Field-only expressions test for a present nonzero value. Repeated fields use any-value matching, including `!=`. This is a documented subset, not complete Wireshark expression compatibility. IPv6 literals currently use the full eight-group representation displayed by the parser.

## Boundaries of this first development build

- Offline cleartext HTTP/1.x only; no TLS decryption, HTTP/2, WebSocket decoding or IP fragment reassembly. Fragmented IP packets are explicitly marked and retained as raw bytes.
- Overlap and reordering are conservative observations, not proof of network packet loss. Missing handshakes and capture gaps remain visible. Conflicting overlapping bytes use the reconstruction policy described in the architecture document.
- HTTP pairing is FIFO within a TCP connection; gaps or missing entire messages can make pairing uncertain. Informational responses are skipped when a final response follows. Capture timestamps are observations, not server processing time.
- Incomplete identifiable HTTP headers/bodies are retained. Bytes that begin midway through an unrecognizable HTTP message remain available in the TCP stream.
- DNS shows the first question and answer section; uncommon RDATA is hex. It does not perform live name resolution.
- Individual captures are limited to 8 MB / 20,000 packets, individual HTTP bodies to 4 MB, and retained HTTP bodies to 8 MB per capture. Analysis workers time out after 15 seconds. The intended everyday input is approximately 10–2000 KB. Lists initially render 200 records and expand on demand. Text/JSON body previews are limited to 256 KB; full retained bodies remain exportable.
- Every byte export is user initiated. Traffic content is rendered as text, never executable HTML. No telemetry or online traffic processing is included.

## Development

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run test:ui    # Requires locally installed Google Chrome
npm run package
```

See [架构与扩展指南](ARCHITECTURE.md) and [验证记录](VALIDATION.md). Publisher `pcap-lens-local` is a local packaging placeholder; a real Marketplace publisher and release metadata must be configured before publication. This repository does not publish automatically.

## Wireshark 路径入口

本机窗口中，点击工具栏“配置 Wireshark”或命令面板的“Pcap Lens: 配置 Wireshark 应用路径”，选择应用或输入路径。macOS 支持 `.app`。路径校验成功后保存到用户设置；启动失败的通知也提供配置入口。SSH 模式下请先下载抓包，再使用本机窗口打开 Wireshark。
