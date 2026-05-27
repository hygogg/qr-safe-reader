import dns from "node:dns/promises";
import net from "node:net";
import { domainToASCII, domainToUnicode } from "node:url";

const REDIRECT_PARAMS = new Set([
  "continue",
  "dest",
  "destination",
  "next",
  "redirect",
  "redirect_uri",
  "return",
  "return_to",
  "target",
  "to",
  "url"
]);

const SHORTENER_HOSTS = new Set([
  "bit.ly",
  "buff.ly",
  "cutt.ly",
  "goo.gl",
  "is.gd",
  "lnkd.in",
  "ow.ly",
  "rebrand.ly",
  "shorturl.at",
  "s.id",
  "t.co",
  "tiny.cc",
  "tinyurl.com",
  "x.gd"
]);

const RISKY_TLDS = new Set(["zip", "mov", "top", "xyz", "click", "country", "kim", "quest"]);
const EXECUTABLE_EXTENSIONS = /\.(apk|appx|bat|cmd|com|dmg|exe|hta|iso|jar|js|msi|pkg|ps1|scr|vb|vbs|wsf)(?:$|[?#])/i;
const ARCHIVE_EXTENSIONS = /\.(7z|ace|gz|rar|tar|zip)(?:$|[?#])/i;

function add(checks, severity, title, detail) {
  checks.push({ severity, title, detail });
}

function sanitizeInput(input) {
  return input
    .trim()
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
}

function addDefaultScheme(value) {
  if (/^[a-z][a-z0-9+.-]*:/i.test(value)) return value;
  if (value.startsWith("//")) return `https:${value}`;
  if (/^[^\s/:?#]+\.[^\s/:?#]{2,}(?:[/:?#].*)?$/i.test(value)) return `https://${value}`;
  return value;
}

function isPrivateIpv4(address) {
  const parts = address.split(".").map(Number);
  if (parts.length !== 4 || parts.some((part) => Number.isNaN(part))) return false;
  const [a, b] = parts;
  return (
    a === 0 ||
    a === 10 ||
    a === 127 ||
    (a === 100 && b >= 64 && b <= 127) ||
    (a === 169 && b === 254) ||
    (a === 172 && b >= 16 && b <= 31) ||
    (a === 192 && b === 0) ||
    (a === 192 && b === 168) ||
    (a === 198 && (b === 18 || b === 19)) ||
    a >= 224
  );
}

function isPrivateIpv6(address) {
  const value = address.toLowerCase();
  return (
    value === "::" ||
    value === "::1" ||
    value.startsWith("fc") ||
    value.startsWith("fd") ||
    value.startsWith("fe80:") ||
    value.startsWith("::ffff:0:") ||
    value.startsWith("2001:db8:")
  );
}

function isPrivateAddress(address) {
  const family = net.isIP(address);
  if (family === 4) return isPrivateIpv4(address);
  if (family === 6) return isPrivateIpv6(address);
  return false;
}

function isLocalHostname(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return (
    host === "localhost" ||
    host.endsWith(".localhost") ||
    host.endsWith(".local") ||
    host.endsWith(".internal") ||
    host.endsWith(".test") ||
    host.endsWith(".invalid") ||
    host.endsWith(".example")
  );
}

function hasMixedScripts(value) {
  const letters = [...value].filter((char) => /\p{Letter}/u.test(char));
  const scripts = new Set();

  for (const char of letters) {
    if (/\p{Script=Latin}/u.test(char)) scripts.add("latin");
    else if (/\p{Script=Cyrillic}/u.test(char)) scripts.add("cyrillic");
    else if (/\p{Script=Greek}/u.test(char)) scripts.add("greek");
    else if (/\p{Script=Han}/u.test(char)) scripts.add("han");
    else if (/\p{Script=Hiragana}/u.test(char)) scripts.add("hiragana");
    else if (/\p{Script=Katakana}/u.test(char)) scripts.add("katakana");
  }

  return scripts.has("latin") && (scripts.has("cyrillic") || scripts.has("greek"));
}

function scoreFor(checks) {
  const penalties = { info: 0, low: 7, medium: 18, high: 35, critical: 100 };
  return Math.max(0, 100 - checks.reduce((total, check) => total + penalties[check.severity], 0));
}

function verdictFor(checks, score) {
  if (checks.some((check) => check.severity === "critical")) return "blocked";
  if (checks.some((check) => check.severity === "high")) return "dangerous";
  if (score >= 82) return "safe";
  if (score >= 45) return "caution";
  return "dangerous";
}

function executableContentType(contentType) {
  return /application\/(x-msdownload|x-msdos-program|x-sh|x-shellscript|java-archive|vnd\.android\.package-archive|octet-stream)/i.test(
    contentType
  );
}

async function resolveSafeHost(url, checks) {
  const hostname = url.hostname;

  if (isLocalHostname(hostname)) {
    add(checks, "critical", "ローカル宛先", "ローカルまたは内部向けのホスト名です。");
    return [];
  }

  if (net.isIP(hostname)) {
    if (isPrivateAddress(hostname)) {
      add(checks, "critical", "内部IPアドレス", "端末や社内ネットワークへ向く可能性があるためブロックしました。");
    }
    return [hostname];
  }

  try {
    const answers = await dns.lookup(hostname, { all: true, verbatim: false });
    const addresses = [...new Set(answers.map((answer) => answer.address))];
    if (addresses.length === 0) {
      add(checks, "high", "DNS未解決", "ホスト名のIPアドレスを確認できませんでした。");
    }
    for (const address of addresses) {
      if (isPrivateAddress(address)) {
        add(checks, "critical", "内部IPへ解決", `${hostname} は内部アドレス ${address} に解決されました。`);
      }
    }
    return addresses;
  } catch {
    add(checks, "high", "DNS未解決", "ホスト名のIPアドレスを確認できませんでした。");
    return [];
  }
}

async function fetchMetadata(url) {
  const controller = new AbortController();
  const timeout = setTimeout(() => controller.abort(), 7000);

  try {
    const head = await fetch(url, {
      method: "HEAD",
      redirect: "manual",
      signal: controller.signal,
      headers: { "user-agent": "QR-Guard-Safety-Probe/0.1" }
    });
    if (![405, 501].includes(head.status)) return head;
  } finally {
    clearTimeout(timeout);
  }

  const getController = new AbortController();
  const getTimeout = setTimeout(() => getController.abort(), 7000);
  try {
    return await fetch(url, {
      method: "GET",
      redirect: "manual",
      signal: getController.signal,
      headers: {
        "range": "bytes=0-2048",
        "user-agent": "QR-Guard-Safety-Probe/0.1"
      }
    });
  } finally {
    clearTimeout(getTimeout);
  }
}

async function inspectNetwork(startUrl, checks) {
  const redirects = [];
  const resolvedAddresses = new Set();
  let current = new URL(startUrl.href);

  for (let index = 0; index < 6; index += 1) {
    const addresses = await resolveSafeHost(current, checks);
    addresses.forEach((address) => resolvedAddresses.add(address));
    if (checks.some((check) => check.severity === "critical")) break;

    let response;
    try {
      response = await fetchMetadata(current);
    } catch {
      add(checks, "medium", "接続確認失敗", "URLへ安全確認用の接続を行えませんでした。");
      break;
    }

    const contentType = response.headers.get("content-type") ?? "";
    const disposition = response.headers.get("content-disposition") ?? "";

    if (response.status >= 400) {
      add(checks, "medium", "HTTPエラー", `確認先が ${response.status} を返しました。`);
    }
    if (contentType && executableContentType(contentType)) {
      add(checks, "high", "実行ファイル形式", `Content-Type が ${contentType} です。`);
    }
    if (/attachment/i.test(disposition)) {
      add(checks, "medium", "ダウンロード誘導", "ページ表示ではなくファイル保存を促す応答です。");
    }

    if (response.status >= 300 && response.status < 400) {
      const location = response.headers.get("location");
      if (!location) {
        add(checks, "medium", "不完全なリダイレクト", "Locationヘッダーのないリダイレクト応答です。");
        break;
      }

      const next = new URL(location, current);
      redirects.push({ from: current.href, to: next.href, status: response.status });
      if (!["http:", "https:"].includes(next.protocol)) {
        add(checks, "critical", "危険なリダイレクト", `${next.protocol} へ移動しようとしています。`);
        break;
      }
      current = next;
      continue;
    }

    break;
  }

  if (redirects.length > 5) {
    add(checks, "high", "過剰なリダイレクト", "6回以上の転送が発生しました。");
  }

  return { effectiveUrl: current, redirects, resolvedAddresses: [...resolvedAddresses] };
}

function inspectUrlShape(url, checks) {
  const asciiHost = domainToASCII(url.hostname);
  const displayHost = domainToUnicode(asciiHost);
  const labels = asciiHost.split(".");
  const tld = labels.at(-1)?.toLowerCase() ?? "";

  if (url.protocol !== "https:") {
    add(checks, "medium", "HTTPSではありません", "通信内容や移動先が改ざんされるリスクがあります。");
  }
  if (url.username || url.password) {
    add(checks, "high", "認証情報入りURL", "本物のドメインを隠すフィッシングで使われやすい形式です。");
  }
  if (asciiHost !== displayHost) {
    add(checks, "medium", "国際化ドメイン", `表示名 ${displayHost} は内部的に ${asciiHost} として扱われます。`);
  }
  if (hasMixedScripts(displayHost)) {
    add(checks, "high", "紛らわしい文字", "ラテン文字と似た別文字が混在しています。");
  }
  if (SHORTENER_HOSTS.has(asciiHost.toLowerCase())) {
    add(checks, "medium", "短縮URL", "最終的な行き先が隠れています。");
  }
  if (RISKY_TLDS.has(tld)) {
    add(checks, "low", "注意が必要なTLD", `.${tld} ドメインです。URL全体を確認してください。`);
  }
  if (labels.length >= 5) {
    add(checks, "low", "サブドメインが多い", "正規サービスに似せた長いホスト名の可能性があります。");
  }
  if (url.href.length > 240) {
    add(checks, "low", "長いURL", "追跡情報や難読化されたパラメータが多い可能性があります。");
  }
  if (url.port && !["80", "443"].includes(url.port)) {
    add(checks, "medium", "標準外ポート", `ポート ${url.port} が指定されています。`);
  }
  if (EXECUTABLE_EXTENSIONS.test(url.pathname)) {
    add(checks, "high", "実行ファイルへのリンク", "アプリやスクリプトを直接ダウンロードさせるURLです。");
  } else if (ARCHIVE_EXTENSIONS.test(url.pathname)) {
    add(checks, "medium", "圧縮ファイルへのリンク", "中身を確認しづらいファイルへのURLです。");
  }

  for (const [key, value] of url.searchParams.entries()) {
    if (REDIRECT_PARAMS.has(key.toLowerCase()) && /^https?:\/\//i.test(value)) {
      add(checks, "medium", "リダイレクトパラメータ", `${key}= に別URLが含まれています。`);
    }
  }
}

export async function analyzeUrl(input, networkProbe = true) {
  const checks = [];
  const sanitizedInput = sanitizeInput(String(input ?? ""));

  if (sanitizedInput !== String(input ?? "").trim()) {
    add(checks, "low", "不可視文字を除去", "制御文字またはゼロ幅文字を削除しました。");
  }

  let parsed;
  try {
    parsed = new URL(addDefaultScheme(sanitizedInput));
  } catch {
    add(checks, "critical", "URLではありません", "読み取った内容をURLとして解釈できません。");
    const score = scoreFor(checks);
    return {
      input,
      sanitizedInput,
      normalizedUrl: null,
      openUrl: null,
      effectiveUrl: null,
      displayHost: null,
      asciiHost: null,
      verdict: "blocked",
      score,
      canOpen: false,
      requiresConfirmation: false,
      checks,
      redirects: [],
      resolvedAddresses: [],
      generatedAt: new Date().toISOString()
    };
  }

  if (!["http:", "https:"].includes(parsed.protocol)) {
    add(checks, "critical", "開けないスキーム", `${parsed.protocol} はブラウザ遷移の対象外です。`);
  }

  inspectUrlShape(parsed, checks);

  const openUrl = new URL(parsed.href);
  openUrl.username = "";
  openUrl.password = "";

  let effectiveUrl = new URL(openUrl.href);
  let redirects = [];
  let resolvedAddresses = [];

  if (networkProbe && ["http:", "https:"].includes(openUrl.protocol)) {
    const inspection = await inspectNetwork(openUrl, checks);
    effectiveUrl = inspection.effectiveUrl;
    redirects = inspection.redirects;
    resolvedAddresses = inspection.resolvedAddresses;
    if (effectiveUrl.protocol === "http:" && parsed.protocol !== "http:") {
      add(checks, "medium", "最終URLがHTTP", "リダイレクト後のURLがHTTPSではありません。");
    }
  } else if (!networkProbe) {
    add(checks, "info", "ネットワーク確認なし", "URL文字列だけを検査しました。");
  }

  if (checks.length === 0) {
    add(checks, "info", "主要チェック通過", "危険度の高い兆候は見つかりませんでした。");
  }

  const score = scoreFor(checks);
  const verdict = verdictFor(checks, score);
  const canOpen = verdict === "safe" || verdict === "caution";

  return {
    input,
    sanitizedInput,
    normalizedUrl: parsed.href,
    openUrl: canOpen ? effectiveUrl.href : openUrl.href,
    effectiveUrl: effectiveUrl.href,
    displayHost: domainToUnicode(domainToASCII(parsed.hostname)),
    asciiHost: domainToASCII(parsed.hostname),
    verdict,
    score,
    canOpen,
    requiresConfirmation: verdict === "caution",
    checks,
    redirects,
    resolvedAddresses,
    generatedAt: new Date().toISOString()
  };
}
