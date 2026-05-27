import assert from "node:assert/strict";
import test from "node:test";
import { buildWebRiskLookupUrl, checkWebRisk, mergeWebRiskResult, normalizeWebRiskResponse } from "../server/webRisk.mjs";

test("builds Web Risk lookup URL without exposing the key to clients", () => {
  const endpoint = buildWebRiskLookupUrl("https://example.com/", "test-key");
  assert.equal(endpoint.origin, "https://webrisk.googleapis.com");
  assert.equal(endpoint.pathname, "/v1/uris:search");
  assert.equal(endpoint.searchParams.get("uri"), "https://example.com/");
  assert.equal(endpoint.searchParams.get("key"), "test-key");
  assert.ok(endpoint.searchParams.getAll("threatTypes").includes("SOCIAL_ENGINEERING"));
});

test("normalizes Web Risk empty response as no match", () => {
  const result = normalizeWebRiskResponse({});
  assert.equal(result.enabled, true);
  assert.equal(result.checked, true);
  assert.equal(result.matched, false);
  assert.deepEqual(result.threatTypes, []);
});

test("normalizes Web Risk threat response as matched", () => {
  const result = normalizeWebRiskResponse({
    threat: {
      threatTypes: ["MALWARE", "SOCIAL_ENGINEERING"],
      expireTime: "2026-05-27T00:00:00Z"
    }
  });
  assert.equal(result.matched, true);
  assert.deepEqual(result.threatTypes, ["MALWARE", "SOCIAL_ENGINEERING"]);
});

test("returns disabled result when API key is missing", async () => {
  const result = await checkWebRisk("https://example.com/", { apiKey: "" });
  assert.equal(result.enabled, false);
  assert.equal(result.checked, false);
});

test("uses supplied fetch implementation", async () => {
  const result = await checkWebRisk("https://example.com/", {
    apiKey: "test-key",
    fetchImpl: async () => ({
      ok: true,
      json: async () => ({ threat: { threatTypes: ["MALWARE"] } })
    })
  });
  assert.equal(result.matched, true);
  assert.deepEqual(result.threatTypes, ["MALWARE"]);
});

test("Web Risk match upgrades local result to danger", () => {
  const localResult = {
    level: "safe",
    reasons: ["ローカルチェックでは明確な危険信号は見つかりませんでした。"]
  };
  const result = mergeWebRiskResult(localResult, {
    enabled: true,
    checked: true,
    matched: true,
    threatTypes: ["SOCIAL_ENGINEERING"]
  });
  assert.equal(result.level, "danger");
  assert.match(result.reasons.at(-1), /SOCIAL_ENGINEERING/);
});
