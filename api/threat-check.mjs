import { checkWebRisk } from "../server/webRisk.mjs";

const maxJsonBytes = 32 * 1024;

async function readJson(request) {
  if (typeof request.body === "string") {
    return JSON.parse(request.body || "{}");
  }

  if (request.body && typeof request.body === "object" && !Buffer.isBuffer(request.body)) {
    return request.body;
  }

  let size = 0;
  const chunks = [];

  for await (const chunk of request) {
    size += chunk.length;
    if (size > maxJsonBytes) {
      throw new Error("Request body is too large.");
    }
    chunks.push(chunk);
  }

  const text = Buffer.concat(chunks).toString("utf8");
  return JSON.parse(text || "{}");
}

export default async function handler(request, response) {
  if (request.method !== "POST") {
    response.setHeader("Allow", "POST");
    response.status(405).json({ error: "Method Not Allowed" });
    return;
  }

  try {
    const body = await readJson(request);
    if (typeof body.url !== "string" || body.url.trim().length === 0 || body.url.length > 4096) {
      response.status(400).json({ error: "Invalid URL value." });
      return;
    }

    const parsed = new URL(body.url);
    if (!["http:", "https:"].includes(parsed.protocol)) {
      response.status(400).json({ error: "Only http and https URLs can be checked." });
      return;
    }

    const result = await checkWebRisk(parsed.href);
    response.status(200).json(result);
  } catch (error) {
    response.status(500).json({
      error: error instanceof Error ? error.message : "Unknown error"
    });
  }
}
