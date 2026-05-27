export const WEB_RISK_THREAT_TYPES = [
  "MALWARE",
  "SOCIAL_ENGINEERING",
  "UNWANTED_SOFTWARE",
  "SOCIAL_ENGINEERING_EXTENDED_COVERAGE"
];

export function buildWebRiskLookupUrl(url, apiKey) {
  const endpoint = new URL("https://webrisk.googleapis.com/v1/uris:search");
  for (const threatType of WEB_RISK_THREAT_TYPES) {
    endpoint.searchParams.append("threatTypes", threatType);
  }
  endpoint.searchParams.set("uri", url);
  endpoint.searchParams.set("key", apiKey);
  return endpoint;
}

export function normalizeWebRiskResponse(payload) {
  const threat = payload?.threat;
  const threatTypes = Array.isArray(threat?.threatTypes) ? threat.threatTypes : [];

  return {
    enabled: true,
    checked: true,
    matched: threatTypes.length > 0,
    threatTypes,
    expireTime: typeof threat?.expireTime === "string" ? threat.expireTime : null
  };
}

export function mergeWebRiskResult(localResult, webRiskResult) {
  if (!webRiskResult?.enabled || !webRiskResult.checked) {
    return localResult;
  }

  if (!webRiskResult.matched) {
    return {
      ...localResult,
      reasons: [
        ...localResult.reasons,
        "Google Web Riskでは既知の脅威として検出されませんでした。"
      ]
    };
  }

  return {
    ...localResult,
    level: "danger",
    reasons: [
      ...localResult.reasons,
      `Google Web Riskで既知の脅威として検出されました: ${webRiskResult.threatTypes.join(", ")}`
    ]
  };
}

export async function checkWebRisk(url, options = {}) {
  const apiKey = options.apiKey ?? process.env.GOOGLE_WEB_RISK_API_KEY;
  const fetchImpl = options.fetchImpl ?? fetch;

  if (!apiKey) {
    return {
      enabled: false,
      checked: false,
      matched: false,
      threatTypes: [],
      expireTime: null,
      message: "GOOGLE_WEB_RISK_API_KEY is not configured."
    };
  }

  const endpoint = buildWebRiskLookupUrl(url, apiKey);
  const response = await fetchImpl(endpoint, {
    method: "GET",
    headers: {
      "user-agent": "QR-Guard-WebRisk/0.1"
    }
  });

  if (!response.ok) {
    throw new Error(`Web Risk API returned ${response.status}`);
  }

  return normalizeWebRiskResponse(await response.json());
}
