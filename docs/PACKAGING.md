# VSIX 打包说明

本文中的命令均在项目根目录执行，适用于 Windows PowerShell、macOS 和 Linux 终端。

## 环境准备

使用与项目 CI 一致的 Node.js 22，并确保可以运行 `node` 和 `npm`。首次安装依赖需要访问 npm registry；本地生成 VSIX 不需要 Marketplace 账号或发布令牌。

```sh
node --version
npm --version
npm ci
```

`npm ci` 按 `package-lock.json` 安装依赖。项目已包含 `@vscode/vsce`，无需全局安装打包工具。

## 打包步骤

```sh
npm run typecheck
npm test
npm run package
```

生成的文件位于项目根目录，名称由 `package.json` 的 `name` 和 `version` 决定。当前版本输出：

```text
pcap-lens-0.1.3.vsix
```

依赖已经安装、只需重新打包时，执行 `npm run package` 即可。不过该命令不会自动执行类型检查和测试。

## 构建与打包的关系

`npm run package` 执行 `vsce package --no-dependencies --no-rewrite-relative-links`。VSCE 会先触发 `vscode:prepublish`，自动执行 `npm run build`，因此无需手动提前构建。

构建产物包括：

- `dist/extension.cjs`：VS Code 扩展入口。
- `dist/worker.cjs`：后台解析 Worker。
- `dist/webview/main.js`：React 界面及其运行依赖。
- `dist/webview/style.css`：界面样式。

`--no-dependencies` 不把 `node_modules` 装入 VSIX。当前所需运行依赖已经打进上述产物，`vscode` 模块由 VS Code 宿主提供。以后新增依赖时，也应确认它已被打包；如果引入必须在运行时单独加载的文件或原生组件，需要同步调整构建和打包规则。

`.vscodeignore` 排除源码、测试、样例抓包、开发配置和测试缓存；`docs`、许可证及第三方声明保留在安装包中。

GitHub 首页 README 使用仓库内的相对链接和截图。当前尚未配置正式仓库，因此本地打包使用 `--no-rewrite-relative-links` 保留这些引用，避免 VSCE 因无法推导仓库 URL 而失败。GitHub 上可正常浏览；Marketplace 发布前需填写真实 `repository` 并移除此参数，让 VSCE 重写资源地址，同时检查扩展详情页的图片和文档链接。

## 自定义输出位置

通过 npm 的参数透传指定路径，例如输出到已有的 `dist` 目录：

```sh
npm run package -- --out dist/pcap-lens.vsix
```

默认输出位置仍为项目根目录，此命令仅对本次打包生效。

## 本地安装验证

1. 打开 VS Code 命令面板。
2. 执行 **Extensions: Install from VSIX…**。
3. 选择生成的 VSIX，按界面提示重新加载窗口。
4. 在项目文件列表中打开 `fixtures/demo.pcap` 或 `fixtures/demo.pcapng`，检查是否自动显示分析界面。

也可以在已配置 `code` 命令的终端中安装：

```sh
code --install-extension pcap-lens-0.1.3.vsix
```

更多验证步骤见 [验证记录](VALIDATION.md)，功能使用见 [使用说明](USAGE.md)。

## 版本更新与常见问题

- 更新版本时，可运行 `npm version patch --no-git-tag-version`，同步修改 `package.json` 和锁文件；再更新 `CHANGELOG.md` 并重新打包。输出文件名会随版本改变。
- 如果提示 `@types/vscode` 高于 `engines.vscode`，需让类型依赖与声明支持的最低 VS Code 版本一致；当前使用 `@types/vscode@1.95.0`。
- 当前清单尚未配置正式仓库，打包会提示缺少 `repository`；本地打包可以成功。正式发布前应填入真实仓库地址，避免使用占位链接。
- 安装依赖遇到网络错误时，检查 npm registry 和本机代理配置后重试，不要手动删除锁文件来绕过问题。

本流程只生成本地安装包，不会发布到 VS Code 扩展市场。当前 `publisher` 为本地占位值，正式发布前还需配置真实发布者并完成发布验证。
