# 在 VS Code Remote SSH 中使用

从 0.1.2 起，Pcap Lens 声明为工作区扩展。普通窗口在本机运行；Remote SSH 窗口在远程扩展宿主运行，使用服务器上的 Node Worker 读取和解析抓包。

## 安装

1. 在 VS Code 中通过 **Remote-SSH: Connect to Host…** 连接目标服务器并打开远程目录。
2. 在该窗口执行 **Extensions: Install from VSIX…**，选择 `pcap-lens-0.1.3.vsix`。
3. 在扩展面板确认 Pcap Lens 位于 **SSH: 你的主机** 的已安装列表。如果仅安装在 Local，请点击 **Install in SSH: 你的主机**。
4. 按提示重新加载窗口，在远程资源管理器点击 `.pcap` 或 `.pcapng`。

只需要安装扩展，不需要在服务器额外安装 Node.js、TShark 或 Python。运行时使用 VS Code Server 提供的扩展宿主；VS Code Server 本身仍需满足 Remote SSH 的系统要求。

## 运行位置与数据

- 抓包读取、协议解析和 TCP 重组在远程服务器执行，沿用普通文件检查、8 MiB 文件限制、资源预算与超时。
- 界面会标记“远程解析 · ssh-remote”。HTTP、DNS、过滤、追踪流和统计仍在同一个编辑器内使用。
- Webview 在本机显示。分析结果通过 VS Code 的远程通道传到本机，其中包含展示所需的正文和原始数据包字节；当前实现发送完整分析模型，不是按需分页传输。
- “导出正文”的保存对话框默认定位到远程抓包所在目录。最终保存位置由用户在对话框中选择，扩展保留 URI 的协议和 authority，不将远程路径改写为本机路径。
- 关闭编辑器会取消对应解析任务。SSH 断线和重连由 VS Code 管理；必要时重新打开文件。

## Wireshark

本版本不会从远程宿主启动本机桌面应用，也不会把远程抓包静默下载到本机。

因此 SSH 下“用 Wireshark 打开”禁用并说明原因，“配置 Wireshark”入口会提示使用本机窗口。需要 Wireshark 时，先通过 VS Code 的远程文件下载功能或自己的文件传输工具把抓包下载到本机，再在本机窗口打开、配置 Wireshark 并启动。

## 排查

- 若扩展提示安装到 SSH：检查安装位置，移除旧的 `remote.extensionKind` 强制本机运行覆盖，重新加载窗口。
- 文件必须属于当前工作区宿主的真实文件系统。虚拟文件系统、其他远程 authority 的 URI 不会直接转成 OS 路径读取。
- 检查当前 SSH 用户对文件的读取权限，以及文件是否超过资源上限。
- 本版本以 Remote SSH 为目标；WSL / Dev Containers 可能使用同样的宿主架构，但尚未单独验证，不作为已验证支持项。

## 验证边界

已运行模拟 SSH 宿主的集成测试，调用真实扩展 provider、文件读取和 Worker，覆盖 pcap/pcapng、Unicode/空格路径、正文导出及 Wireshark 隔离；另有 URI、配置和界面回归测试。本次未提供可用 SSH 测试服务器，因此尚未完成真实 SSH 会话端到端验证。

架构依据：[VS Code Remote Extension Guide](https://code.visualstudio.com/api/advanced-topics/remote-extensions)。
