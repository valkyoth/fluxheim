#!/usr/bin/env node
import { mkdir, readFile, rm, writeFile } from "node:fs/promises";
import { existsSync } from "node:fs";
import { spawn } from "node:child_process";
import { tmpdir } from "node:os";
import { join } from "node:path";

async function main() {
const baseUrl = env("FLUXHEIM_BROWSER_BASE_URL", "https://example.test").replace(/\/+$/, "");
const username = requiredEnv("FLUXHEIM_BROWSER_USER");
const password = requiredEnv("FLUXHEIM_BROWSER_PASSWORD");
const chrome = env("FLUXHEIM_BROWSER_CHROME", findChrome());
const artifactRoot = env("FLUXHEIM_BROWSER_ARTIFACT_DIR", tmpdir());
const keepProfile = env("FLUXHEIM_BROWSER_KEEP_PROFILE", "0") === "1";
const waitAfterSubmitMs = Number(env("FLUXHEIM_BROWSER_WAIT_AFTER_SUBMIT_MS", "2500"));
const loginPath = env(
  "FLUXHEIM_BROWSER_LOGIN_PATH",
  "/wp-login.php?redirect_to=%2Fwp-admin%2F&reauth=1",
);
const expectedPath = env("FLUXHEIM_BROWSER_EXPECT_PATH", "/wp-admin/");
const expectedText = env("FLUXHEIM_BROWSER_EXPECT_TEXT", "Dashboard");

if (!chrome) {
  throw new Error(
    "missing Chrome/Chromium. Set FLUXHEIM_BROWSER_CHROME=/path/to/chrome or install google-chrome/chromium.",
  );
}

const runId = new Date().toISOString().replace(/[-:.TZ]/g, "");
const artifacts = join(artifactRoot, `fluxheim-browser-wordpress-${runId}`);
const profile = join(tmpdir(), `fluxheim-browser-profile-${process.pid}`);
await mkdir(artifacts, { recursive: true, mode: 0o700 });
await mkdir(profile, { recursive: true, mode: 0o700 });

const chromeProcess = spawn(chrome, [
  "--headless=new",
  "--disable-gpu",
  "--no-first-run",
  "--no-default-browser-check",
  "--disable-background-networking",
  "--disable-sync",
  "--ignore-certificate-errors",
  "--remote-debugging-address=127.0.0.1",
  "--remote-debugging-port=0",
  `--user-data-dir=${profile}`,
  "about:blank",
], {
  stdio: ["ignore", "ignore", "pipe"],
});

let chromeStderr = "";
chromeProcess.stderr.on("data", (chunk) => {
  chromeStderr += chunk.toString();
});

try {
  const portFile = join(profile, "DevToolsActivePort");
  const port = await waitForDevToolsPort(portFile);
  const target = await createTarget(port, `${baseUrl}/`);
  const client = new CdpClient(target.webSocketDebuggerUrl);
  await client.open();

  const events = [];
  const network = [];
  const cookieExtra = [];

  client.on("Runtime.exceptionThrown", (event) => {
    events.push(`pageerror:${event.exceptionDetails?.text || "exception"}`);
  });
  client.on("Runtime.consoleAPICalled", (event) => {
    const args = (event.args || [])
      .map((arg) => arg.value ?? arg.description ?? "")
      .join(" ");
    events.push(`console:${event.type}:${args}`);
  });
  client.on("Network.loadingFailed", (event) => {
    network.push(`failed:${event.requestId}:${event.errorText || ""}`);
  });
  client.on("Network.requestWillBeSent", (event) => {
    if (!interestingUrl(event.request?.url)) {
      return;
    }
    const post = sanitizePostData(event.request?.postData || "");
    const cookie = event.request?.headers?.Cookie || event.request?.headers?.cookie || "";
    network.push(
      `request:${event.request?.method || ""}:${event.request?.url || ""}:post=${post}:cookie=${cookieNames(cookie)}`,
    );
  });
  client.on("Network.responseReceived", (event) => {
    if (!interestingUrl(event.response?.url)) {
      return;
    }
    network.push(
      `response:${event.response?.status || ""}:${event.response?.url || ""}:mime=${event.response?.mimeType || ""}`,
    );
  });
  client.on("Network.responseReceivedExtraInfo", (event) => {
    const headers = event.headers || {};
    const setCookie = headers["set-cookie"] || headers["Set-Cookie"] || "";
    if (setCookie || (event.blockedCookies || []).length > 0) {
      cookieExtra.push(
        `set-cookie=${setCookieNames(setCookie)}:blocked=${blockedCookieSummary(event.blockedCookies || [])}:raw=${sanitizeSetCookie(setCookie)}`,
      );
    }
  });

  await client.send("Network.enable", { maxPostDataSize: 4096 });
  await client.send("Page.enable");
  await client.send("Runtime.enable");

  await navigate(client, `${baseUrl}${loginPath}`);
  await delay(500);
  await client.send("Runtime.evaluate", {
    expression: fillAndSubmitExpression(username, password, `${baseUrl}${expectedPath}`),
    awaitPromise: true,
  });
  await delay(waitAfterSubmitMs);

  const finalUrl = await evaluateValue(client, "window.location.href");
  const title = await evaluateValue(client, "document.title");
  const html = await evaluateValue(client, "document.documentElement.outerHTML");
  const cookies = await client.send("Network.getAllCookies");
  const cookieLines = (cookies.cookies || [])
    .filter((cookie) => cookie.domain.includes(new URL(baseUrl).hostname))
    .map((cookie) => `${cookie.name}\t${cookie.domain}\t${cookie.path}\tsecure=${cookie.secure}\thttpOnly=${cookie.httpOnly}`);

  await writeFile(join(artifacts, "final-url.txt"), `${finalUrl}\n`);
  await writeFile(join(artifacts, "title.txt"), `${title}\n`);
  await writeFile(join(artifacts, "page.html"), html);
  await writeFile(join(artifacts, "events.txt"), events.join("\n"));
  await writeFile(join(artifacts, "network.txt"), network.join("\n"));
  await writeFile(join(artifacts, "cookie-extra.txt"), cookieExtra.join("\n"));
  await writeFile(join(artifacts, "cookies.txt"), cookieLines.join("\n"));

  const ok = finalUrl.includes(expectedPath) && html.includes(expectedText);
  console.log(`artifact_dir=${artifacts}`);
  console.log(`final_url=${finalUrl}`);
  console.log(`title=${title}`);
  console.log(`cookies=${cookieLines.map((line) => line.split("\t")[0]).join(",")}`);
  console.log(`events=${events.slice(0, 20).join(" | ")}`);
  console.log(`network=${network.slice(0, 40).join(" | ")}`);
  console.log(`cookie_extra=${cookieExtra.slice(0, 20).join(" | ")}`);
  console.log(`status=${ok ? "ok" : "failed"}`);

  await client.close();
  process.exitCode = ok ? 0 : 1;
} finally {
  chromeProcess.kill("SIGTERM");
  await delay(250);
  if (!chromeProcess.killed) {
    chromeProcess.kill("SIGKILL");
  }
  await writeFile(join(artifacts, "chrome-stderr.txt"), chromeStderr).catch(() => {});
  if (!keepProfile) {
    await rm(profile, { recursive: true, force: true }).catch(() => {});
  }
}
}

function env(name, fallback) {
  return process.env[name] && process.env[name].trim() ? process.env[name].trim() : fallback;
}

function requiredEnv(name) {
  const value = process.env[name];
  if (!value) {
    throw new Error(`missing required environment variable ${name}`);
  }
  return value;
}

function findChrome() {
  for (const path of [
    "/usr/bin/google-chrome",
    "/usr/bin/google-chrome-stable",
    "/usr/bin/chromium",
    "/usr/bin/chromium-browser",
  ]) {
    if (existsSync(path)) {
      return path;
    }
  }
  return "";
}

async function waitForDevToolsPort(path) {
  const deadline = Date.now() + 10_000;
  while (Date.now() < deadline) {
    if (existsSync(path)) {
      const [port] = (await readFile(path, "utf8")).split(/\r?\n/);
      if (port) {
        return port;
      }
    }
    await delay(100);
  }
  throw new Error("Chrome did not expose a DevTools port");
}

async function createTarget(port, url) {
  const response = await fetch(`http://127.0.0.1:${port}/json/new?${encodeURIComponent(url)}`, {
    method: "PUT",
  });
  if (!response.ok) {
    throw new Error(`failed to create Chrome target: HTTP ${response.status}`);
  }
  return response.json();
}

async function navigate(client, url) {
  await client.send("Page.navigate", { url });
  await delay(1000);
}

async function evaluateValue(client, expression) {
  const result = await client.send("Runtime.evaluate", {
    expression,
    returnByValue: true,
  });
  return result.result?.value ?? "";
}

function fillAndSubmitExpression(user, pass, redirectTo) {
  return `
(() => {
  const user = ${JSON.stringify(user)};
  const pass = ${JSON.stringify(pass)};
  const redirectTo = ${JSON.stringify(redirectTo)};
  document.querySelector('#user_login').value = user;
  document.querySelector('#user_pass').value = pass;
  const redirect = document.querySelector('input[name="redirect_to"]');
  if (redirect) redirect.value = redirectTo;
  const testcookie = document.querySelector('input[name="testcookie"]');
  if (testcookie) testcookie.value = '1';
  document.querySelector('#loginform').submit();
})()
`;
}

function interestingUrl(url) {
  return /wp-login\.php|\/wp-admin\/|\/wp-includes\/js\//.test(url || "");
}

function sanitizePostData(value) {
  return value.replace(/pwd=[^&]*/g, "pwd=<redacted>");
}

function cookieNames(value) {
  return String(value)
    .split(/;\s*/)
    .map((part) => part.split("=")[0])
    .filter(Boolean)
    .join("|");
}

function setCookieNames(value) {
  return String(value)
    .split(/\n|, (?=[^ ;]+=)/)
    .map((part) => part.split("=")[0])
    .filter(Boolean)
    .join("|");
}

function sanitizeSetCookie(value) {
  return String(value).replace(/=([^;\n,]*)/g, "=<v>");
}

function blockedCookieSummary(blockedCookies) {
  return blockedCookies
    .map((cookie) => `${cookie.cookie?.name || "?"}:${(cookie.blockedReasons || []).join("+")}`)
    .join("|");
}

function delay(ms) {
  return new Promise((resolve) => setTimeout(resolve, ms));
}

class CdpClient {
  constructor(url) {
    this.url = url;
    this.nextId = 1;
    this.pending = new Map();
    this.handlers = new Map();
  }

  async open() {
    this.socket = new WebSocket(this.url);
    this.socket.addEventListener("message", (event) => this.handleMessage(event.data));
    await new Promise((resolve, reject) => {
      this.socket.addEventListener("open", resolve, { once: true });
      this.socket.addEventListener("error", reject, { once: true });
    });
  }

  async close() {
    this.socket?.close();
  }

  on(method, handler) {
    const handlers = this.handlers.get(method) || [];
    handlers.push(handler);
    this.handlers.set(method, handlers);
  }

  send(method, params = {}) {
    const id = this.nextId++;
    this.socket.send(JSON.stringify({ id, method, params }));
    return new Promise((resolve, reject) => {
      this.pending.set(id, { resolve, reject });
      setTimeout(() => {
        if (this.pending.has(id)) {
          this.pending.delete(id);
          reject(new Error(`CDP command timed out: ${method}`));
        }
      }, 15_000);
    });
  }

  handleMessage(data) {
    const message = JSON.parse(data);
    if (message.id) {
      const pending = this.pending.get(message.id);
      if (!pending) {
        return;
      }
      this.pending.delete(message.id);
      if (message.error) {
        pending.reject(new Error(message.error.message || "CDP error"));
      } else {
        pending.resolve(message.result || {});
      }
      return;
    }
    for (const handler of this.handlers.get(message.method) || []) {
      handler(message.params || {});
    }
  }
}

main().catch((error) => {
  console.error(error.stack || error.message || String(error));
  process.exitCode = 1;
});
