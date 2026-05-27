import { analyzeLocalUrlSafety } from "./urlSafety.js";

const levelCopy = {
  safe: {
    label: "安全そうです",
    icon: "✓",
    message: "安全そうです。ただし最終判断はご自身で行ってください"
  },
  caution: {
    label: "注意",
    icon: "!",
    message: "注意が必要なURLです"
  },
  danger: {
    label: "危険",
    icon: "!",
    message: "危険な可能性が高いURLです"
  },
  unknown: {
    label: "不明",
    icon: "?",
    message: "安全性を確認できませんでした"
  }
};

const severityLabel = {
  info: "情報",
  low: "低",
  medium: "中",
  high: "高",
  critical: "重大"
};

const elements = {
  statusPill: document.querySelector("#status-pill"),
  statusIcon: document.querySelector("#status-icon"),
  statusText: document.querySelector("#status-text"),
  modeCamera: document.querySelector("#mode-camera"),
  modeImage: document.querySelector("#mode-image"),
  modeManual: document.querySelector("#mode-manual"),
  video: document.querySelector("#video"),
  scannerEmpty: document.querySelector("#scanner-empty"),
  scanPreview: document.querySelector("#scan-preview"),
  cameraButton: document.querySelector("#camera-button"),
  imageInput: document.querySelector("#image-input"),
  manualForm: document.querySelector("#manual-form"),
  manualUrl: document.querySelector("#manual-url"),
  score: document.querySelector("#score"),
  emptyResult: document.querySelector("#empty-result"),
  resultStack: document.querySelector("#result-stack"),
  verdictBlock: document.querySelector("#verdict-block"),
  verdictIcon: document.querySelector("#verdict-icon"),
  verdictLabel: document.querySelector("#verdict-label"),
  verdictHost: document.querySelector("#verdict-host"),
  displayHost: document.querySelector("#display-host"),
  effectiveUrl: document.querySelector("#effective-url"),
  registrableDomain: document.querySelector("#registrable-domain"),
  scheme: document.querySelector("#scheme"),
  path: document.querySelector("#path"),
  query: document.querySelector("#query"),
  confirmLine: document.querySelector("#confirm-line"),
  confirmCaution: document.querySelector("#confirm-caution"),
  openButton: document.querySelector("#open-button"),
  copyButton: document.querySelector("#copy-button"),
  checkList: document.querySelector("#check-list"),
  redirects: document.querySelector("#redirects"),
  redirectList: document.querySelector("#redirect-list")
};

let detector = null;
let currentMode = "camera";
let currentResult = null;
let stream = null;
let scanTimer = null;
let lastScan = "";
let detectorWarningShown = false;
let analysisRequestId = 0;

async function getDetector() {
  if (!("BarcodeDetector" in window)) {
    throw new Error("このブラウザではQR検出を使用できません");
  }
  if (!detector) {
    detector = new BarcodeDetector({ formats: ["qr_code"] });
  }
  return detector;
}

function decodeCanvas(canvas) {
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context || typeof window.jsQR !== "function") return null;

  const imageData = context.getImageData(0, 0, canvas.width, canvas.height);
  const code = window.jsQR(imageData.data, imageData.width, imageData.height, {
    inversionAttempts: "attemptBoth"
  });
  return code?.data || null;
}

function drawVideoToCanvas(video) {
  if (!video.videoWidth || !video.videoHeight) return null;
  const canvas = document.createElement("canvas");
  canvas.width = video.videoWidth;
  canvas.height = video.videoHeight;
  const context = canvas.getContext("2d", { willReadFrequently: true });
  if (!context) return null;
  context.drawImage(video, 0, 0, canvas.width, canvas.height);
  return canvas;
}

async function fileToCanvas(file) {
  const image = new Image();
  image.decoding = "async";
  image.src = URL.createObjectURL(file);

  try {
    await image.decode();
    const canvas = document.createElement("canvas");
    canvas.width = image.naturalWidth;
    canvas.height = image.naturalHeight;
    const context = canvas.getContext("2d", { willReadFrequently: true });
    if (!context) throw new Error("画像を処理できません");
    context.drawImage(image, 0, 0, canvas.width, canvas.height);
    return canvas;
  } finally {
    URL.revokeObjectURL(image.src);
  }
}

function setMode(mode) {
  currentMode = mode;
  for (const [name, button] of [
    ["camera", elements.modeCamera],
    ["image", elements.modeImage],
    ["manual", elements.modeManual]
  ]) {
    button.classList.toggle("active", name === mode);
  }
}

function setStatus(text, verdict = "idle", icon = "▣") {
  elements.statusPill.className = `status-pill ${verdict}`;
  elements.statusIcon.textContent = icon;
  elements.statusText.textContent = text;
}

function stopCamera() {
  if (scanTimer) {
    clearTimeout(scanTimer);
    scanTimer = null;
  }
  stream?.getTracks().forEach((track) => track.stop());
  stream = null;
  elements.video.srcObject = null;
  elements.video.classList.remove("active");
  elements.scannerEmpty.classList.remove("hidden");
  elements.cameraButton.textContent = "□ カメラ";
  elements.cameraButton.className = "primary";
}

async function scanVideoFrame() {
  if (!stream) return;

  let value = null;

  try {
    if (detector) {
      const codes = await detector.detect(elements.video);
      value = codes[0]?.rawValue || null;
    }
  } catch {
    detector = null;
  }

  if (!value) {
    const canvas = drawVideoToCanvas(elements.video);
    value = canvas ? decodeCanvas(canvas) : null;
  }

  if (value && value !== lastScan) {
    lastScan = value;
    stopCamera();
    await analyze(value);
    return;
  }

  scanTimer = setTimeout(scanVideoFrame, 250);
}

async function startCamera() {
  setMode("camera");
  setStatus("カメラ起動中", "idle", "□");
  clearResult();

  try {
    try {
      await getDetector();
    } catch {
      if (!detectorWarningShown) {
        detectorWarningShown = true;
      }
    }
    stopCamera();
    stream = await navigator.mediaDevices.getUserMedia({
      audio: false,
      video: { facingMode: { ideal: "environment" } }
    });
    elements.video.srcObject = stream;
    elements.video.classList.add("active");
    elements.scannerEmpty.classList.add("hidden");
    elements.cameraButton.textContent = "■ 停止";
    elements.cameraButton.className = "danger";
    await elements.video.play();
    setStatus("読み取り中", "idle", "▣");
    await scanVideoFrame();
  } catch (error) {
    stopCamera();
    setStatus(error.message || "カメラを使用できません", "blocked", "×");
  }
}

async function scanImage(file) {
  setMode("image");
  stopCamera();
  clearResult();
  setStatus("画像解析中", "idle", "▤");

  try {
    let value = null;

    try {
      const qrDetector = await getDetector();
      const bitmap = await createImageBitmap(file);
      const codes = await qrDetector.detect(bitmap);
      bitmap.close();
      value = codes[0]?.rawValue || null;
    } catch {
      detector = null;
    }

    if (!value) {
      const canvas = await fileToCanvas(file);
      value = decodeCanvas(canvas);
    }

    if (!value) {
      setStatus("QRコードが見つかりません", "caution", "!");
      return;
    }
    await analyze(value);
  } catch (error) {
    setStatus(error.message || "画像解析に失敗しました", "blocked", "×");
  }
}

function clearResult() {
  analysisRequestId += 1;
  currentResult = null;
  elements.score.classList.add("hidden");
  elements.emptyResult.classList.remove("hidden");
  elements.resultStack.classList.add("hidden");
  elements.openButton.disabled = true;
  elements.openButton.className = "primary";
  elements.openButton.textContent = "↗ 開く";
  elements.confirmCaution.checked = false;
}

async function analyze(value) {
  const trimmed = String(value || "").trim();
  if (!trimmed) {
    setStatus("入力が空です", "caution", "!");
    return;
  }

  setStatus("検査中", "idle", "…");
  elements.scanPreview.textContent = trimmed;
  elements.openButton.disabled = true;
  const requestId = ++analysisRequestId;
  currentResult = analyzeLocalUrlSafety(trimmed);

  if (!currentResult.isUrl) {
    renderTextResult(currentResult);
    return;
  }

  renderResult(currentResult);
  await enrichWithWebRisk(requestId, currentResult);
}

async function enrichWithWebRisk(requestId, localResult) {
  if (!localResult.isUrl) return;

  setStatus("Web Risk照合中", localResult.level, levelCopy[localResult.level].icon);

  try {
    const response = await fetch("/api/threat-check", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ url: localResult.normalizedUrl })
    });

    if (requestId !== analysisRequestId) return;

    if (!response.ok) {
      const failedResult = appendReason(localResult, "Google Web Risk照合に失敗しました。ローカル判定のみを表示しています。");
      currentResult = failedResult;
      renderResult(failedResult);
      return;
    }

    const webRisk = await response.json();
    if (requestId !== analysisRequestId) return;

    const merged = mergeWebRiskResult(localResult, webRisk);
    currentResult = merged;
    renderResult(merged);
  } catch {
    if (requestId !== analysisRequestId) return;
    const failedResult = appendReason(localResult, "Google Web Risk照合に失敗しました。ローカル判定のみを表示しています。");
    currentResult = failedResult;
    renderResult(failedResult);
  }
}

function appendReason(result, reason) {
  return {
    ...result,
    reasons: [...result.reasons, reason]
  };
}

function mergeWebRiskResult(localResult, webRisk) {
  if (!webRisk?.enabled || !webRisk.checked) {
    return appendReason(localResult, "Google Web Risk APIは未設定です。ローカル判定のみを表示しています。");
  }

  if (!webRisk.matched) {
    return appendReason(localResult, "Google Web Riskでは既知の脅威として検出されませんでした。");
  }

  return {
    ...localResult,
    level: "danger",
    reasons: [
      ...localResult.reasons,
      `Google Web Riskで既知の脅威として検出されました: ${webRisk.threatTypes.join(", ")}`
    ]
  };
}

function renderTextResult(result) {
  setStatus("テキスト", "unknown", "□");
  elements.score.classList.add("hidden");
  elements.emptyResult.classList.add("hidden");
  elements.resultStack.classList.remove("hidden");

  elements.verdictBlock.className = "verdict-block unknown";
  elements.verdictIcon.textContent = "□";
  elements.verdictLabel.textContent = "URLではありません";
  elements.verdictHost.textContent = result.normalizedUrl || "テキスト";
  elements.displayHost.textContent = "-";
  elements.effectiveUrl.textContent = result.normalizedUrl || "-";
  elements.registrableDomain.textContent = "-";
  elements.scheme.textContent = "-";
  elements.path.textContent = "-";
  elements.query.textContent = "-";
  elements.confirmLine.classList.add("hidden");
  elements.confirmCaution.checked = false;
  elements.openButton.disabled = true;
  elements.openButton.className = "primary";
  elements.openButton.textContent = "↗ 開く";

  renderReasons(result.reasons, "info");
  elements.redirects.classList.add("hidden");
}

function renderResult(result) {
  const level = levelCopy[result.level];
  setStatus(level.label, result.level, level.icon);

  elements.score.classList.add("hidden");
  elements.emptyResult.classList.add("hidden");
  elements.resultStack.classList.remove("hidden");

  elements.verdictBlock.className = `verdict-block ${result.level}`;
  elements.verdictIcon.textContent = level.icon;
  elements.verdictLabel.textContent = level.message;
  elements.verdictHost.textContent = result.hostname || "URLなし";
  elements.displayHost.textContent = result.hostname || "-";
  elements.effectiveUrl.textContent = result.normalizedUrl || "-";
  elements.registrableDomain.textContent = result.registrableDomain || "-";
  elements.scheme.textContent = result.scheme || "-";
  elements.path.textContent = result.path || "-";
  elements.query.textContent = result.query || "-";

  elements.confirmLine.classList.toggle("hidden", result.level === "safe" || result.level === "danger");
  elements.confirmCaution.checked = false;
  elements.openButton.className = result.level === "danger" ? "secondary danger-open" : "primary";
  elements.openButton.textContent = result.level === "danger" ? "確認して開く" : "↗ 開く";
  updateOpenButton();
  renderReasons(result.reasons, result.level === "danger" ? "critical" : result.level === "caution" ? "medium" : "info");

  elements.redirects.classList.add("hidden");
  elements.redirectList.replaceChildren();
}

function renderReasons(reasons, severity) {
  elements.checkList.replaceChildren(
    ...reasons.map((reason) => {
      const isWebRiskReason = reason.includes("Google Web Risk");
      const item = document.createElement("article");
      item.className = `check ${severity}`;
      item.innerHTML = `
        <span>${severityLabel[severity]}</span>
        <div>
          <strong></strong>
          <p></p>
        </div>
      `;
      item.querySelector("strong").textContent = isWebRiskReason ? "Google Web Risk判定" : "ローカル判定";
      item.querySelector("p").textContent = reason;
      return item;
    })
  );
}

function updateOpenButton() {
  if (!currentResult?.isUrl) {
    elements.openButton.disabled = true;
    return;
  }
  elements.openButton.disabled = Boolean(currentResult.level === "caution" && !elements.confirmCaution.checked);
}

elements.cameraButton.addEventListener("click", () => {
  if (stream) stopCamera();
  else void startCamera();
});

elements.imageInput.addEventListener("change", (event) => {
  const file = event.currentTarget.files?.[0];
  if (file) void scanImage(file);
  event.currentTarget.value = "";
});

elements.manualForm.addEventListener("submit", (event) => {
  event.preventDefault();
  setMode("manual");
  stopCamera();
  void analyze(elements.manualUrl.value);
});

elements.confirmCaution.addEventListener("change", updateOpenButton);

elements.openButton.addEventListener("click", () => {
  if (!currentResult?.normalizedUrl || elements.openButton.disabled) return;

  if (currentResult.level === "danger") {
    const firstConfirmed = window.confirm("危険な可能性が高いURLです。本当に開く準備をしますか？");
    if (!firstConfirmed) return;

    const secondConfirmed = window.confirm("フィッシングや不正サイトの可能性があります。それでも外部URLを開きますか？");
    if (!secondConfirmed) return;
  }

  window.open(currentResult.normalizedUrl, "_blank", "noopener,noreferrer");
});

elements.copyButton.addEventListener("click", async () => {
  const value = currentResult?.normalizedUrl ?? elements.scanPreview.textContent;
  if (!value) return;
  await navigator.clipboard.writeText(value);
  setStatus("コピーしました", currentResult?.level ?? "idle", currentResult ? levelCopy[currentResult.level].icon : "□");
});

elements.modeCamera.addEventListener("click", () => setMode("camera"));
elements.modeImage.addEventListener("click", () => setMode("image"));
elements.modeManual.addEventListener("click", () => setMode("manual"));

if (!("BarcodeDetector" in window) && typeof window.jsQR !== "function") {
  setStatus("QR検出機能なし", "caution", "!");
}
