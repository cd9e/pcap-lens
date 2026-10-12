# 发布到 VS Code 扩展市场

扩展显示名称为 **Pcap Lens**，扩展短标识为 `pcap-lens`。完整市场标识由 `publisher.pcap-lens` 组成。

## 当前准备状态

- 名称、界面、配置键和源码文档已统一。
- `pcapLens.wiresharkPath` 是当前配置键；此前本地 Packet Lens 试用版的 `packetLens.wiresharkPath` 需手动迁移。
- GitHub 首页使用根目录 README；市场详情页使用自包含的 `docs/MARKETPLACE.md`，不依赖尚未配置的仓库链接。
- `package.json` 中的 `pcap-lens-local` 只是占位 publisher，必须替换为本人有权管理的真实发布者 ID，不能直接发布占位身份。

## 发布者身份

在 [Marketplace 发布者管理页面](https://marketplace.visualstudio.com/manage) 登录，选择已有发布者或创建发布者。将其 **ID** 填入 `package.json` 的 `publisher`。显示名称和 ID 不是同一字段。

如果已有 GitHub 仓库，还应补充真实的 `repository`、`homepage` 和问题反馈地址。没有 GitHub 仓库也可以通过管理页面上传 VSIX。

## 验证和生成市场安装包

填写真实 publisher 后运行：

```sh
npm run typecheck
npm test
npm run package:marketplace
```

输出：`pcap-lens-0.1.3-marketplace.vsix`。脚本会拒绝占位 publisher，构建过程自动执行。

`npm run package` 仍用于本地试用包，使用 GitHub README；`package:marketplace` 使用市场详情页文案。

## 发布方式

### 网页上传

登录发布者管理页面，选择目标发布者，创建 Visual Studio Code 扩展并上传上述市场 VSIX。按页面完成发布，随后检查扫描状态和扩展详情页。这种方式不需要把访问令牌交给聊天工具。

### 本机 CLI

也可以在自己的终端执行 `npx vsce login YOUR_PUBLISHER_ID`（将占位文字替换为你的发布者 ID），在交互提示中输入凭据；随后通过 `npx vsce publish --packagePath pcap-lens-0.1.3-marketplace.vsix` 发布。认证方式与凭据权限以官方文档为准；不要把密码或令牌写入源码、README、聊天或命令行参数。

## 发布后验证

- 检查市场页面显示名称、版本和发布者是否正确。
- 在干净的 VS Code 环境从市场安装，打开合成 pcap/pcapng 验证。
- 补充 Windows/Linux 实机与真实抓包回归；当前已有三平台 CI 配置，但不应将配置存在视为运行通过。
- 确认上线后，再把 README 的“未发布”状态改成真实市场链接。

官方依据：[Publishing Extensions](https://code.visualstudio.com/api/working-with-extensions/publishing-extension)。
