# 验证记录

本地验证日期：2026-09-09。

## 已完成

- TypeScript strict 类型检查。
- 12 项功能测试：pcap 四种魔数、pcapng 大小端及多 section；Ethernet/VLAN/IPv6；TCP 跨包、乱序、重叠、序号回绕、缺口和 RST；HTTP 配对、HEAD、流水线、chunked、gzip、截断头部/正文、字段来源；DNS 指针和配对；过滤器扩展及错误输入；损坏文件边界。
- 约 1.6 MB、400 组 HTTP 请求/响应的构造抓包解析测试。
- Chrome 中的真实生产 Webview bundle：HTTP 正文、视图跳转与返回、字段/字节高亮、过滤、无效过滤保留结果、DNS、统计、中英文切换、700px 窄屏布局。启用 CSP，检查未捕获浏览器错误。
- macOS 本机 VS Code 扩展宿主：扩展发现/激活，`vscode.open` 对 pcap 和 pcapng 选择默认自定义编辑器，关闭编辑器。
- VSIX 本地打包及资源检查：只包含构建产物、清单、许可证和文档；无 node_modules、抓包内容、测试输出或 native dependency。

## 0.1.1 安全回归

新增 10 项安全回归，共 22 项测试通过；类型检查、包含恶意 HTML 和表格分批展示的浏览器交互回归、macOS 扩展宿主测试通过。`npm audit --json` 报告 0 项已知漏洞。详见 [安全检查记录](SECURITY.md)。

## 尚未完成的发布验证

- Windows 和 Linux 上实际运行扩展宿主，以及三平台 Wireshark 发现/启动、文件导出对话框的人工验证。
- 用户真实抓包回归、与 Wireshark 的逐流对照；当前样例主要为可复现的合成抓包。
- Marketplace 发布者、正式仓库 URL 和发布元数据配置。

已加入三平台 CI 配置，但本地没有远程仓库，也没有执行或声称通过远程 CI。此版本可用于本地试用，不应将这些检查记录理解为完整 Wireshark 兼容性认证。

## 复现

```sh
npm ci
npm run typecheck
npm test
npm run build
npm run test:ui
npm run test:extension
npm run package
```

`test:ui` 使用本机 Google Chrome；`test:extension` 默认由官方测试工具下载隔离版 VS Code。可通过 `PCAP_LENS_VSCODE_PATH` 指定已有可执行文件，或通过 `PCAP_LENS_VSCODE_VERSION` 指定版本。测试不发布插件，也不写入日常 VS Code 用户配置。

## 0.1.2 Remote SSH 与 Wireshark 配置（2026-09-21）

28 项测试通过，新增远程 URI/宿主边界、模拟 SSH provider + 真实 Worker、远程正文导出、Wireshark 配置保存和路径验证测试。SSH 标记、Wireshark 禁用说明及配置入口纳入浏览器回归。未连接真实 SSH 服务器，实际 SSH 环境仍需用户侧验证。

## 0.1.3 HTTP 请求识别修复（2026-09-23）

用户报告的 11 包抓包已复现并验证：请求在第 4 包，响应在第 6 包。旧请求行规则不接受目标地址中的未转义空格，导致请求被静默丢弃；修复后可配对，并保留格式异常提示。响应声明 12 字节，实际 9 字节，仍应标记不完整并明确少 3 字节。FIN 不覆盖 Content-Length 约束。

30 项自动测试通过，包含新增的异常目标空白、跨包请求和长度差异回归。用户抓包未加入仓库，自动测试使用合成的普通搜索参数复现相同解析条件。
