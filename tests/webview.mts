import { chromium } from "@playwright/test";
import { readFileSync, writeFileSync, mkdirSync } from "node:fs";
import { resolve } from "node:path";
import { analyze } from "../src/core/analyze";
const capture = analyze(readFileSync("fixtures/demo.pcap"));
const directory = resolve(".test-output");
mkdirSync(directory, { recursive: true });
const script = resolve("dist/webview/main.js");
const css = resolve("dist/webview/style.css");
writeFileSync(
  resolve(directory, "preview.html"),
  `<!doctype html><html><head><meta charset="utf-8"><meta http-equiv="Content-Security-Policy" content="default-src 'none'; script-src 'nonce-test'; style-src file:;"><link rel="stylesheet" href="file://${css}"></head><body><div id="root"></div><script nonce="test">let state={};window.sent=[];window.acquireVsCodeApi=()=>({getState:()=>state,setState:s=>state=s,postMessage:m=>{sent.push(m);if(m.type==='ready')setTimeout(()=>{window.postMessage({type:'init',name:'demo.pcap',language:'zh-cn'},'*');window.postMessage({type:'capture',capture:${JSON.stringify(capture)}},'*');},0)}});</script><script nonce="test" src="file://${script}"></script></body></html>`,
);
const browser = await chromium.launch({ channel: "chrome", headless: true });
try {
  const page = await browser.newPage({
    viewport: { width: 1440, height: 1000 },
  });
  const errors: string[] = [];
  page.on("pageerror", (e) => errors.push(e.message));
  await page.goto("file://" + resolve(directory, "preview.html"));
  await page.getByText("/api/users", { exact: true }).click();
  await page
    .getByRole("button", { name: "格式化 JSON", exact: true })
    .last()
    .click();
  await page.getByText('"Alice"', { exact: false }).waitFor();
  await page.screenshot({
    path: resolve(directory, "http.png"),
    fullPage: true,
  });
  await page.getByRole("button", { name: "相关数据包", exact: true }).click();
  await page.getByText("协议字段", { exact: true }).count();
  await page.getByRole("button", { name: "返回", exact: false }).click();
  await page.getByRole("button", { name: "追踪 TCP 流", exact: true }).click();
  await page
    .getByRole("heading", { name: "端点 A → B", exact: false })
    .first()
    .waitFor();
  await page.getByRole("button", { name: "数据包", exact: true }).click();
  await page.locator("tbody tr").first().click();
  await page
    .getByRole("button", { name: "Source port: 50123", exact: true })
    .click();
  if ((await page.locator(".hexbytes .highlight").count()) !== 2)
    throw new Error("Field-byte highlight failed");
  const input = page.getByPlaceholder("显示过滤器 · 按 Enter 应用");
  await input.fill("http.response.code >= 400");
  await input.press("Enter");
  await page.getByRole("button", { name: "HTTP", exact: true }).click();
  if ((await page.locator("tbody tr").count()) !== 1)
    throw new Error("HTTP filter failed");
  await input.fill("http && (");
  await input.press("Enter");
  await page.getByRole("alert").waitFor();
  if ((await page.locator("tbody tr").count()) !== 1)
    throw new Error("Invalid filter changed results");
  await input.fill("");
  await input.press("Enter");
  await page.getByRole("button", { name: "DNS", exact: true }).click();
  await page.getByText("93.184.216.34", { exact: true }).waitFor();
  await page.getByRole("button", { name: "统计", exact: true }).click();
  await page.getByText("流量概况", { exact: true }).waitFor();
  await page.evaluate(() =>
    window.postMessage(
      { type: "init", name: "demo.pcap", language: "en" },
      "*",
    ),
  );
  await page.getByText("Capture overview", { exact: true }).waitFor();
  await page.setViewportSize({ width: 700, height: 850 });
  await page.getByRole("button", { name: "HTTP", exact: true }).click();
  await page.locator("tbody tr").first().click();
  await page.screenshot({
    path: resolve(directory, "narrow.png"),
    fullPage: true,
  });
  await page.evaluate(() =>
    window.postMessage(
      {
        type: "init",
        name: "remote.pcap",
        language: "en",
        remoteName: "ssh-remote",
        canOpenWireshark: false,
      },
      "*",
    ),
  );
  await page
    .getByText("Remote analysis · ssh-remote", { exact: true })
    .waitFor();
  const remoteWireshark = page.getByRole("button", {
    name: "Open in Wireshark",
    exact: false,
  });
  if (await remoteWireshark.isEnabled())
    throw new Error("Remote Wireshark must be disabled");
  if (!(await remoteWireshark.getAttribute("title"))?.includes("Download"))
    throw new Error("Missing remote Wireshark explanation");
  await page.evaluate(() =>
    window.postMessage(
      {
        type: "init",
        name: "demo.pcap",
        language: "en",
        canOpenWireshark: true,
      },
      "*",
    ),
  );
  await page.waitForFunction(
    () => !document.querySelector("header button")?.hasAttribute("disabled"),
  );
  await page
    .getByRole("button", { name: "Configure Wireshark", exact: true })
    .click();
  if (
    !(await page.evaluate(() =>
      (window as any).sent.some((m: any) => m.type === "configureWireshark"),
    ))
  )
    throw new Error("Wireshark configuration action missing");
  const hostile = structuredClone(capture);
  hostile.http[0].response!.headers["content-type"] = "text/html";
  hostile.http[0].response!.body = Array.from(
    Buffer.from(
      '<img src="https://example.invalid/secret" onerror="window.compromised=true"><script>window.compromised=true</script>',
    ),
  );
  await page.evaluate(
    (c) => window.postMessage({ type: "capture", capture: c }, "*"),
    hostile,
  );
  await page.getByRole("button", { name: "Body", exact: true }).last().click();
  await page.getByText("<img src=", { exact: false }).waitFor();
  if ((await page.locator("img").count()) !== 0)
    throw new Error("Capture HTML became DOM");
  if (await page.evaluate(() => Boolean((window as any).compromised)))
    throw new Error("Capture script executed");
  const large = structuredClone(capture);
  large.http = Array.from({ length: 300 }, (_, i) => ({
    ...capture.http[0],
    id: String(i + 1),
  }));
  await page.evaluate(
    (c) => window.postMessage({ type: "capture", capture: c }, "*"),
    large,
  );
  await page.waitForFunction(
    () => document.querySelectorAll("tbody tr").length === 200,
  );
  await page
    .getByRole("button", { name: "Show more (+200)", exact: true })
    .click();
  if ((await page.locator("tbody tr").count()) !== 300)
    throw new Error("Bounded table expansion failed");
  if (errors.length) throw new Error(errors.join("\n"));
  console.log(
    "Webview smoke tests passed: render, HTTP body, navigation, byte mapping, filter retention, DNS, statistics, locales, narrow layout, hostile HTML escaping, bounded table expansion.",
  );
} finally {
  await browser.close();
}
