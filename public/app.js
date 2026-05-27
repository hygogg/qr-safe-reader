const verdictCopy = {
  safe: { label: "安全", icon: "✓" },
  caution: { label: "注意", icon: "!" },
  dangerous: { label: "危険", icon: "!" },
  blocked: { label: "ブロック", icon: "×" }
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
  resolvedAddresses: document.querySelector("#resolved-addresses"),
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
  currentResult = null;
  elements.score.classList.add("hidden");
  elements.emptyResult.classList.remove("hidden");
  elements.resultStack.classList.add("hidden");
  elements.openButton.disabled = true;
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

  try {
    const response = await fetch("/api/analyze", {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ value: trimmed, networkProbe: true })
    });

    if (!response.ok) throw new Error("検査に失敗しました");
    currentResult = await response.json();
    renderResult(currentResult);
  } catch (error) {
    setStatus(error.message || "検査に失敗しました", "blocked", "×");
  }
}

function renderResult(result) {
  const verdict = verdictCopy[result.verdict];
  setStatus(verdict.label, result.verdict, verdict.icon);

  elements.score.textContent = String(result.score);
  elements.score.className = `score ${result.verdict}`;
  elements.emptyResult.classList.add("hidden");
  elements.resultStack.classList.remove("hidden");

  elements.verdictBlock.className = `verdict-block ${result.verdict}`;
  elements.verdictIcon.textContent = verdict.icon;
  elements.verdictLabel.textContent = verdict.label;
  elements.verdictHost.textContent = result.displayHost || "URLなし";
  elements.displayHost.textContent = result.displayHost || "-";
  elements.effectiveUrl.textContent = result.effectiveUrl || "-";
  elements.resolvedAddresses.textContent = result.resolvedAddresses.length ? result.resolvedAddresses.join(", ") : "-";

  elements.confirmLine.classList.toggle("hidden", !result.requiresConfirmation);
  elements.confirmCaution.checked = false;
  updateOpenButton();

  elements.checkList.replaceChildren(
    ...result.checks.map((check) => {
      const item = document.createElement("article");
      item.className = `check ${check.severity}`;
      item.innerHTML = `
        <span>${severityLabel[check.severity]}</span>
        <div>
          <strong></strong>
          <p></p>
        </div>
      `;
      item.querySelector("strong").textContent = check.title;
      item.querySelector("p").textContent = check.detail;
      return item;
    })
  );

  elements.redirects.classList.toggle("hidden", result.redirects.length === 0);
  elements.redirectList.replaceChildren(
    ...result.redirects.map((hop) => {
      const row = document.createElement("div");
      row.className = "redirect-hop";
      row.innerHTML = `<span>${hop.status}</span><p></p>`;
      row.querySelector("p").textContent = hop.to;
      return row;
    })
  );
}

function updateOpenButton() {
  if (!currentResult?.canOpen) {
    elements.openButton.disabled = true;
    return;
  }
  elements.openButton.disabled = Boolean(currentResult.requiresConfirmation && !elements.confirmCaution.checked);
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
  if (!currentResult?.openUrl || elements.openButton.disabled) return;
  window.open(currentResult.openUrl, "_blank", "noopener,noreferrer");
});

elements.copyButton.addEventListener("click", async () => {
  const value = currentResult?.effectiveUrl ?? currentResult?.normalizedUrl ?? elements.scanPreview.textContent;
  if (!value) return;
  await navigator.clipboard.writeText(value);
  setStatus("コピーしました", currentResult?.verdict ?? "idle", currentResult ? verdictCopy[currentResult.verdict].icon : "□");
});

elements.modeCamera.addEventListener("click", () => setMode("camera"));
elements.modeImage.addEventListener("click", () => setMode("image"));
elements.modeManual.addEventListener("click", () => setMode("manual"));

if (!("BarcodeDetector" in window) && typeof window.jsQR !== "function") {
  setStatus("QR検出機能なし", "caution", "!");
}
