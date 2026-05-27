import assert from "node:assert/strict";
import test from "node:test";
import { analyzeLocalUrlSafety } from "../public/urlSafety.js";

test("official So-net URL is safe or unknown", () => {
  const result = analyzeLocalUrlSafety("https://www.so-net.ne.jp/");
  assert.equal(result.isUrl, true);
  assert.ok(["safe", "unknown"].includes(result.level));
});

test("service-like dynamic DNS URL is danger", () => {
  const result = analyzeLocalUrlSafety("https://services-so-net.duckdns.org/");
  assert.equal(result.level, "danger");
  assert.equal(result.registrableDomain, "duckdns.org");
});

test("http URL is caution", () => {
  const result = analyzeLocalUrlSafety("http://example.com/");
  assert.equal(result.level, "caution");
});

test("short URL is caution", () => {
  const result = analyzeLocalUrlSafety("https://bit.ly/xxxx");
  assert.equal(result.level, "caution");
});

test("IP address URL is caution", () => {
  const result = analyzeLocalUrlSafety("https://192.168.1.1/login");
  assert.equal(result.level, "caution");
});

test("punycode hostname is caution", () => {
  const result = analyzeLocalUrlSafety("https://xn--example.com/");
  assert.equal(result.level, "caution");
});

test("plain QR text is not treated as URL", () => {
  const result = analyzeLocalUrlSafety("ただのテキスト");
  assert.equal(result.isUrl, false);
  assert.equal(result.level, "unknown");
});
