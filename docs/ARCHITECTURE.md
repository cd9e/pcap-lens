# 架构与源码扩展指南

## 分层

`src/core` 不依赖 VS Code 或 React。`capture.ts` 读取容器，`protocols.ts` 解码数据包，`streams.ts` 建立连接和重组，`http.ts` / `dns.ts` 做应用协议分析，`filter.ts` 编译过滤表达式。`pipeline.ts` 将这些步骤按明确顺序连接。

`src/extension` 管理只读自定义编辑器、文件读取、Worker 生命周期、正文导出和 Wireshark 启动。解析在 Node Worker 内执行，编辑器关闭时终止 Worker。Webview 不获取文件系统能力，导出请求只允许引用已解析记录的 ID，由扩展端定位正文。

`src/ui` 只消费可序列化分析结果。每个文件独立保存视图、选择、过滤和滚动状态。安全预算集中定义在 `src/core/limits.ts`；扩展宿主通过 `AnalysisSession` 缓存进行中的任务，使用有界文件读取和带超时的 Worker。`main.tsx` 组织会话导航，`components.tsx` 提供详情组件，`i18n.ts` 集中维护文案，`bridge.ts` 封装 VS Code 消息接口。

## 数据与证据

- Packet ID 是数组索引加一，在一个 Capture 内稳定。
- `Field.offset/length` 始终指向单个原始数据包，绝不指向解压后文本。HTTP 跨包字段树中的名称/值采用有界预览，完整头部仍保存在 HTTP 消息详情中，以避免字符串随分片数量放大。
- TCP Chunk 记录无缺口的字节区间，以及每段字节对应的数据包和原始偏移。缺口创建新 Chunk，不填充伪造字节。
- HTTP 请求、响应保留实际覆盖它们的数据包编号；UI 从记录跳转至包列表，并保留返回入口。
- 连接方向使用端点 A/B。缺少握手时不虚构客户端身份。
- TCP 序号使用有符号模 2³² 差，适用于单方向跨度小于 2³¹ 的目标文件。重叠段按序号起点、同起点按包编号排序，已消费前缀不重复拼接；矛盾重叠数据暂不单独分类。不要将这套启发式视为 TCP 端系统的精确仿真。
- 包字段上的过滤与 UI 请求/响应上下文分离。相同包包含多个应用消息时，过滤字段保存多个值。
- 首字节耗时从请求的最早捕获时间计算到响应的最早捕获时间。正文完整接收时长在详情中单独展示。

## 增加解析能力

1. 在 `src/core` 创建独立分析模块，输入已有模型，输出协议记录/诊断，保留 packetIds。
2. 在 `createDefaultPipeline()` 中按依赖顺序注册 `Analyzer`。纯应用层解析应位于 flow 重组后。
3. 新链路层用 `registerLinkDecoder(linkType, decoder)` 注册；新的 EtherType/传输协议目前在 Ethernet 解码器的明确分支中加入，扩展数量增加时再拆专用注册表。
4. 在 `model.ts` 定义明确类型，避免将解析器内部可变状态传入 UI。
5. 加入最小正常、截断、跨包/重复数据测试；为新诊断补充中英文文案。

这是源码扩展机制，不是公开的跨 VS Code 扩展 API；无需维护首版未承诺的外部兼容层。

## 增加过滤字段或运算符

```ts
registerField("http.custom", (packet) => {
  const value = packet.filter["http.custom"];
  return value === undefined ? [] : Array.isArray(value) ? value : [value];
});
registerOperator("starts_with", (left, right) =>
  String(left).startsWith(String(right)),
);
```

字段注册在 UI 使用的共享 `filter.ts`（或其导入模块），解析模块负责填充值。命名运算符可直接注册；新的符号运算符也需扩展词法规则。表达式不使用 `eval`，输入错误携带字符位置。新增字段会出现在补全中。

## 新增正文视图或统计

正文组件接收 `HttpMessage`，不要重新读取文件或渲染捕获内容为 HTML。统计只消费统一的 matched packet IDs。新增 UI 类型需同时补充字典、窄屏布局和消息参数校验。

## 官方参考

- [VS Code Custom Editor API](https://code.visualstudio.com/api/extension-guides/custom-editors)
- [VS Code API](https://code.visualstudio.com/api/references/vscode-api)
- [pcap / pcapng format specifications](https://github.com/pcapng/pcapng)
- [HTTP/1.1 messaging, RFC 9112](https://www.rfc-editor.org/rfc/rfc9112)
- [DNS, RFC 1035](https://www.rfc-editor.org/rfc/rfc1035)

## Remote SSH（0.1.2）

扩展声明 `extensionKind: ["workspace"]`，因此文件读取和 Worker 跟随工作区运行。VS Code 远程宿主将所属远程资源映射为宿主内 `file:` URI；不直接解释任意 `vscode-remote:` URI 为本地路径。Webview 资源继续通过 `asWebviewUri` 转换，正文导出通过原 URI 的 `with` 保留资源身份。传递给 Webview 的远程能力标记只控制界面，宿主仍独立阻止远程桌面程序启动。详见 [Remote SSH 使用说明](REMOTE_SSH.md)。
