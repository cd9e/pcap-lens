# Pcap Lens

**在 VS Code 中直接查看 pcap / pcapng，从 HTTP 请求追踪到 TCP 流和原始字节。**

Pcap Lens 是一个轻量的离线流量分析扩展，适合 HTTP 接口排障、TCP 连接检查和 DNS 查询分析。安装后点击抓包文件即可使用，无需另行安装 TShark、Python 或抓包驱动。

## 功能

- **HTTP 请求与响应**：支持明文 HTTP/1.0、HTTP/1.1，展示方法、主机、路径、状态码、首字节耗时和正文大小；查看头部、JSON 正文及二进制字节。
- **正文处理**：chunked 解码、受资源预算限制的 gzip 解压、JSON 格式化和正文导出。图片以十六进制展示。
- **TCP 流追踪**：双向文本或十六进制内容，保留相关数据包编号；提示疑似重传、乱序、缺失字节和连接重置。
- **协议解析**：Ethernet、VLAN、IPv4/IPv6、TCP、UDP；协议字段树与原始字节联动。
- **DNS**：配对 UDP/TCP DNS 请求与响应，查看域名、查询类型、常见解析结果、响应状态及耗时。
- **统计**：整体流量概况及每条连接双方的包数、字节数和持续时间。
- **中文和英文界面**：自动跟随 VS Code 的语言设置。

## 使用方法

1. 在 VS Code 文件列表中点击 `.pcap` 或 `.pcapng`。
2. 在 HTTP 列表中选择请求，对照查看请求与响应。
3. 使用“追踪 TCP 流”或“相关数据包”进入详细分析。
4. 在顶部输入过滤表达式，按 Enter 应用。语法错误不会覆盖上一次有效结果。

```text
http.response.code >= 400
http.request.method == "POST"
http.request.uri contains "/api"
tcp.port == 80 && !dns
tcp.flags.reset == 1
dns.qry.name contains "example.com"
```

过滤器实现常用 Wireshark 风格语法子集，并非完整兼容。HTTP/DNS 任意一侧匹配时保留配对上下文，统计只计算实际匹配的包。

## 可选 Wireshark 集成

本机窗口可以点击“配置 Wireshark”选择应用或输入路径，macOS 支持 `.app`。SSH 模式需先下载抓包后在本机打开 Wireshark。

点击“用 Wireshark 打开”可交给本机已有的 Wireshark 继续分析。如果无法自动发现，请在 VS Code 用户设置中配置 `pcapLens.wiresharkPath`，填写 Wireshark 可执行文件的绝对路径。仅此功能需要安装 Wireshark。

## 隐私与范围

本机窗口在本机解析，Remote SSH 窗口在远程宿主解析；分析结果（包括正文和原始字节）通过 VS Code 通道显示在本机，不发送到第三方服务，不包含遥测。HTTP 凭据和正文原样显示，不自动脱敏。流量内容仅作为文本/字节展示，不执行其中的 HTML 或脚本。

当前支持本机桌面端和 Remote SSH。SSH 模式需将扩展安装到远程主机；正文导出默认使用远程目录。暂不支持实时抓包、TLS 解密、HTTP/2、WebSocket 解码或 IP 分片重组。TCP 异常是基于抓包的观察，不能单独证明网络丢包；缺失消息也可能影响 HTTP FIFO 配对。

目标输入为约 10–2000 KB 的抓包。当前上限为 8 MiB / 20,000 个包；每条 HTTP 正文最多保留 4 MiB，累计最多保留 8 MiB；后台解析超时为 15 秒。文本预览限制为 256 KiB，完整保留正文可以导出。

本版本面向 Windows、macOS、Linux 构建；macOS 扩展宿主验证已通过，Windows/Linux 实机验证尚未完成。

## License

MIT。第三方许可证随扩展安装包一同分发。
