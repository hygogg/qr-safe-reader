export type UrlSafetyLevel = "safe" | "caution" | "danger" | "unknown";

export type UrlSafetyResult = {
  level: UrlSafetyLevel;
  reasons: string[];
  normalizedUrl: string;
  hostname: string;
  isUrl: boolean;
  scheme: string;
  registrableDomain: string;
  path: string;
  query: string;
};

type KnownService = {
  name: string;
  officialDomains: string[];
};

const DYNAMIC_DNS_DOMAINS = new Set(["duckdns.org", "ddns.net", "no-ip.org", "hopto.org", "dynu.net"]);

const SHORTENER_DOMAINS = new Set([
  "bit.ly",
  "tinyurl.com",
  "t.co",
  "is.gd",
  "goo.gl",
  "ow.ly",
  "buff.ly",
  "cutt.ly",
  "rebrand.ly",
  "shorturl.at",
  "s.id",
  "tiny.cc",
  "x.gd"
]);

const KNOWN_SERVICES: KnownService[] = [
  { name: "so-net", officialDomains: ["so-net.ne.jp"] },
  { name: "sony", officialDomains: ["sony.jp", "sony.com"] },
  { name: "amazon", officialDomains: ["amazon.co.jp", "amazon.com"] },
  { name: "rakuten", officialDomains: ["rakuten.co.jp", "rakuten.com"] },
  { name: "yahoo", officialDomains: ["yahoo.co.jp", "yahoo.com"] },
  { name: "google", officialDomains: ["google.com", "google.co.jp"] },
  { name: "microsoft", officialDomains: ["microsoft.com", "live.com", "office.com"] },
  { name: "apple", officialDomains: ["apple.com"] },
  { name: "paypal", officialDomains: ["paypal.com"] },
  { name: "line", officialDomains: ["line.me", "line.naver.jp"] },
  { name: "mercari", officialDomains: ["mercari.com", "mercari.jp"] }
];

const IPV4_PATTERN = /^(?:\d{1,3}\.){3}\d{1,3}$/;

function sanitizeInput(value: unknown): string {
  return String(value ?? "")
    .trim()
    .replace(/[\u0000-\u001F\u007F]/g, "")
    .replace(/[\u200B-\u200D\u2060\uFEFF]/g, "");
}

function hasScheme(value: string): boolean {
  return /^[a-z][a-z0-9+.-]*:/i.test(value);
}

function addDefaultScheme(value: string): string {
  if (hasScheme(value)) return value;
  if (value.startsWith("//")) return `https:${value}`;
  if (/^[^\s/:?#]+\.[^\s/:?#]{2,}(?:[/:?#].*)?$/i.test(value)) return `https://${value}`;
  return value;
}

function parseHttpUrl(value: unknown): URL | null {
  const sanitized = sanitizeInput(value);
  if (!sanitized || /\s/.test(sanitized)) return null;

  let url: URL;
  try {
    url = new URL(addDefaultScheme(sanitized));
  } catch {
    return null;
  }

  if (!["http:", "https:"].includes(url.protocol)) return null;
  if (!url.hostname || (!url.hostname.includes(".") && !IPV4_PATTERN.test(url.hostname))) return null;
  return url;
}

type RelaxedHttpParts = {
  protocol: string;
  hostname: string;
  href: string;
  pathname: string;
  search: string;
};

function parseRelaxedHttpParts(value: unknown): RelaxedHttpParts | null {
  const sanitized = sanitizeInput(value);
  const match = /^(https?):\/\/([^/?#\s]+)([^?#\s]*)?(\?[^#\s]*)?/i.exec(sanitized);
  if (!match) return null;
  const [, scheme, rawHost, rawPath = "/", rawQuery = ""] = match;
  if (!rawHost.toLowerCase().includes("xn--")) return null;

  const hostname = rawHost.toLowerCase().replace(/:\d+$/, "");
  return {
    protocol: `${scheme.toLowerCase()}:`,
    hostname,
    href: `${scheme.toLowerCase()}://${rawHost}${rawPath || "/"}${rawQuery}`,
    pathname: rawPath || "/",
    search: rawQuery
  };
}

function isIpv4(hostname: string): boolean {
  if (!IPV4_PATTERN.test(hostname)) return false;
  return hostname.split(".").every((part) => {
    const value = Number(part);
    return Number.isInteger(value) && value >= 0 && value <= 255;
  });
}

function isIpv6(hostname: string): boolean {
  return hostname.includes(":");
}

function isIpAddress(hostname: string): boolean {
  return isIpv4(hostname) || isIpv6(hostname);
}

export function getRegistrableDomain(hostname: string): string {
  const host = hostname.toLowerCase().replace(/^\[|\]$/g, "").replace(/\.$/, "");
  if (isIpAddress(host)) return host;

  const labels = host.split(".").filter(Boolean);
  if (labels.length <= 2) return labels.join(".");

  const lastTwo = labels.slice(-2).join(".");
  const jpSecondLevel = new Set(["co.jp", "ne.jp", "or.jp", "ac.jp", "go.jp"]);
  if (jpSecondLevel.has(lastTwo) && labels.length >= 3) {
    return labels.slice(-3).join(".");
  }

  return lastTwo;
}

function isSubdomainOf(hostname: string, domain: string): boolean {
  const host = hostname.toLowerCase();
  const base = domain.toLowerCase();
  return host === base || host.endsWith(`.${base}`);
}

function includesKnownService(hostname: string): KnownService | undefined {
  const normalizedHost = hostname.toLowerCase();
  return KNOWN_SERVICES.find((service) => normalizedHost.includes(service.name));
}

function officialServiceDomain(hostname: string, service: KnownService): boolean {
  return service.officialDomains.some((domain) => isSubdomainOf(hostname, domain));
}

function rankLevel(current: UrlSafetyLevel, next: UrlSafetyLevel): UrlSafetyLevel {
  const order: Record<UrlSafetyLevel, number> = { safe: 0, unknown: 1, caution: 2, danger: 3 };
  return order[next] > order[current] ? next : current;
}

export function analyzeLocalUrlSafety(input: unknown): UrlSafetyResult {
  const url = parseHttpUrl(input) ?? parseRelaxedHttpParts(input);
  if (!url) {
    return {
      level: "unknown",
      reasons: ["URLではないため、安全性判定の対象外です。"],
      normalizedUrl: sanitizeInput(input),
      hostname: "",
      isUrl: false,
      scheme: "",
      registrableDomain: "",
      path: "",
      query: ""
    };
  }

  const hostname = url.hostname.toLowerCase();
  const registrableDomain = getRegistrableDomain(hostname);
  const reasons: string[] = [];
  let level: UrlSafetyLevel = "safe";

  if (url.protocol === "http:") {
    level = rankLevel(level, "caution");
    reasons.push("HTTP通信のため、通信内容や遷移先が改ざんされる可能性があります。");
  }

  if (isIpAddress(hostname)) {
    level = rankLevel(level, "caution");
    reasons.push("IPアドレス直打ちのURLです。正規サービスのドメインか確認しづらい形式です。");
  }

  if (DYNAMIC_DNS_DOMAINS.has(registrableDomain)) {
    level = rankLevel(level, "danger");
    reasons.push(`${registrableDomain} は動的DNSです。フィッシングや一時的な不審サイトで悪用されることがあります。`);
  }

  if (SHORTENER_DOMAINS.has(registrableDomain)) {
    level = rankLevel(level, "caution");
    reasons.push("短縮URLです。最終的な行き先が隠れている可能性があります。");
  }

  if (hostname.includes("xn--")) {
    level = rankLevel(level, "caution");
    reasons.push("Punycodeを含むホスト名です。見た目が似た別ドメインの可能性があります。");
  }

  const matchedService = includesKnownService(hostname);
  if (matchedService && !officialServiceDomain(hostname, matchedService)) {
    level = rankLevel(level, "danger");
    reasons.push(
      `${matchedService.name} を含むホスト名ですが、公式ドメイン（${matchedService.officialDomains.join(", ")}）ではありません。`
    );
  }

  if (url.href.length >= 180) {
    level = rankLevel(level, "caution");
    reasons.push("URLが非常に長く、追跡情報や難読化されたパラメータを含む可能性があります。");
  }

  if (reasons.length === 0) {
    reasons.push("ローカルチェックでは明確な危険信号は見つかりませんでした。");
  }

  return {
    level,
    reasons,
    normalizedUrl: url.href,
    hostname,
    isUrl: true,
    scheme: url.protocol.replace(":", ""),
    registrableDomain,
    path: url.pathname,
    query: url.search
  };
}
