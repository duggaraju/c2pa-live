import { createC2pa } from "https://esm.sh/@contentauth/c2pa-web/inline";

const video = document.getElementById("video");
const manifestInput = document.getElementById("manifest");
const playBtn = document.getElementById("playBtn");
const c2paBtn = document.getElementById("c2paBtn");
const stateEl = document.getElementById("state");
const fragmentEl = document.getElementById("fragment");
const detailsEl = document.getElementById("details");
const c2paStateEl = document.getElementById("c2paState");
const c2paDetailsEl = document.getElementById("c2paDetails");

let player = null;
const c2paPromise = initializeC2pa();
let latestValidationContext = null;
const initBlobCache = new Map();

async function initializeC2pa() {
  const res = await fetch("/api/c2pa/cert-chain.pem", { cache: "no-store" });
  if (!res.ok) {
    throw new Error(`trust anchors request failed: ${res.status}`);
  }

  const trustAnchorsPem = await res.text();
  return createC2pa({
    settings: {
      trust: {
        // c2pa-web supports PEM text or URL values; use PEM text directly to avoid
        // worker URL resolution edge cases in blob-worker environments.
        trustAnchors: trustAnchorsPem,
        userAnchors: trustAnchorsPem
      },
      verify: {
        verifyTrust: true,
        verifyAfterReading: true
      }
    }
  });
}

function setState(kind, text) {
  stateEl.textContent = text;
  stateEl.classList.remove("ok", "bad");
  if (kind === "ok") stateEl.classList.add("ok");
  if (kind === "bad") stateEl.classList.add("bad");
}

function setC2paState(kind, text) {
  c2paStateEl.textContent = text;
  c2paStateEl.classList.remove("ok", "bad");
  if (kind === "ok") c2paStateEl.classList.add("ok");
  if (kind === "bad") c2paStateEl.classList.add("bad");
}

function setC2paButtonEnabled(enabled) {
  c2paBtn.disabled = !enabled;
}

function getManifestValidationState(manifestStore) {
  if (!manifestStore || typeof manifestStore !== "object") {
    return "Unknown";
  }

  const state = manifestStore.validation_state
    || manifestStore.validationState
    || manifestStore.active_manifest?.validation_state
    || manifestStore.active_manifest?.validationState;

  if (!state) {
    return "Unknown";
  }

  return String(state);
}

function getManifestFailures(manifestStore) {
  if (!manifestStore || typeof manifestStore !== "object") {
    return [];
  }

  const failures = [];
  if (Array.isArray(manifestStore.validation_status)) {
    failures.push(...manifestStore.validation_status);
  }

  const resultsFailure = manifestStore.validation_results?.active_manifest?.failure;
  if (Array.isArray(resultsFailure)) {
    failures.push(...resultsFailure);
  }

  return failures;
}

function hasManifestStore(manifestStore) {
  const activeManifest = manifestStore?.active_manifest;
  return Boolean(activeManifest && manifestStore?.manifests?.[activeManifest]);
}

function startPlayer() {
  if (player) {
    player.reset();
  }

  player = dashjs.MediaPlayer().create();
  player.updateSettings({
    streaming: {
      delay: { liveDelay: 6 }
    }
  });

  player.on(dashjs.MediaPlayer.events.FRAGMENT_LOADING_COMPLETED, onFragmentLoadingCompleted);
  player.initialize(video, manifestInput.value.trim(), true);
}

function isInitializationRequest(request) {
  if (!request) {
    return false;
  }

  if (typeof request.isInitializationRequest === "function") {
    try {
      return request.isInitializationRequest();
    } catch {
      return false;
    }
  }

  return request.type === "InitializationSegment" || request.type === "Initialization";
}

function toBlob(response, mimeType) {
  if (response instanceof Blob) {
    return response;
  }

  if (response instanceof ArrayBuffer) {
    return new Blob([response], { type: mimeType });
  }

  if (ArrayBuffer.isView(response)) {
    return new Blob([response.buffer], { type: mimeType });
  }

  return new Blob([response], { type: mimeType });
}

function normalizeMediaFormat(value, fallback = "video/mp4") {
  if (!value) {
    return fallback;
  }

  const cleaned = String(value)
    .split(";")[0]
    .trim()
    .replace(/[.,]+$/, "")
    .toLowerCase();

  if (cleaned === "video" || cleaned === "audio") {
    return "video/mp4";
  }

  if (cleaned.startsWith("video/") || cleaned.startsWith("audio/")) {
    return cleaned === "audio/mp4" || cleaned === "video/mp4"
      ? cleaned
      : "video/mp4";
  }

  if (cleaned.includes("/")) {
    return cleaned;
  }

  return fallback;
}

function repIdForMediaType(mediaType) {
  const normalized = String(mediaType || "").toLowerCase();
  if (normalized === "video") {
    return "0";
  }
  if (normalized === "audio") {
    return "1";
  }
  return null;
}

function deriveInitUrl(fragmentUrl, mediaType) {
  const url = new URL(fragmentUrl, window.location.href);
  const match = url.pathname.match(/^(.*\/)?chunk-([^/]+?)-\d+\.m4s$/);
  let repId = null;
  let basePath = "/";

  if (match) {
    basePath = match[1] || "/";
    repId = match[2];
  } else {
    const fallbackRepId = repIdForMediaType(mediaType);
    if (!fallbackRepId) {
      return null;
    }

    const slash = url.pathname.lastIndexOf("/");
    basePath = slash >= 0 ? `${url.pathname.slice(0, slash + 1)}` : "/";
    repId = fallbackRepId;
  }

  url.pathname = `${basePath}init-${repId}.mp4`;
  return url.toString();
}

async function loadC2pa() {
  return c2paPromise;
}

async function getInitBlob(initUrl, fallbackMimeType, { forceReload = false } = {}) {
  if (!forceReload && initBlobCache.has(initUrl)) {
    return initBlobCache.get(initUrl);
  }

  const res = await fetch(initUrl, { cache: "no-store" });
  if (!res.ok) {
    if (initBlobCache.has(initUrl)) {
      return initBlobCache.get(initUrl);
    }
    throw new Error(`init segment request failed: ${res.status}`);
  }

  const blob = await res.blob();
  const normalizedBlob = !blob.type && fallbackMimeType
    ? new Blob([blob], { type: fallbackMimeType })
    : blob;

  initBlobCache.set(initUrl, normalizedBlob);
  return normalizedBlob;
}

async function updateC2paButtonFromInitSegment(request, response) {
  const initUrl = request.url || "n/a";
  const initMime = request.mimeType || request.mediaType || "video/mp4";
  const initBlob = toBlob(response, initMime);
  initBlobCache.set(initUrl, initBlob);

  const initFormat = normalizeMediaFormat(initBlob.type || initMime);
  const c2pa = await loadC2pa();
  let reader = null;

  try {
    reader = await c2pa.reader.fromBlob(initFormat, initBlob);
    if (!reader) {
      setC2paButtonEnabled(false);
      setC2paState("bad", "init segment has no manifest store");
      c2paDetailsEl.textContent = JSON.stringify({
        ok: false,
        initUrl,
        initFormat,
        message: "init segment is not signed"
      }, null, 2);
      return false;
    }

    const manifestStore = await reader.manifestStore();
    const activeManifest = manifestStore?.active_manifest;
    const isSigned = hasManifestStore(manifestStore);
    const validationState = getManifestValidationState(manifestStore);
    const failures = getManifestFailures(manifestStore);
    const isInvalid = validationState.toLowerCase() === "invalid";
    const canValidate = isSigned && !isInvalid;

    setC2paButtonEnabled(canValidate);

    if (!isSigned) {
      setC2paState("bad", "init segment has no manifest store");
    } else if (isInvalid) {
      setC2paState("bad", `signed init found but validation_state=${validationState}`);
    } else {
      setC2paState("ok", `signed init detected (validation_state=${validationState})`);
    }

    c2paDetailsEl.textContent = JSON.stringify({
      ok: canValidate,
      initUrl,
      initFormat,
      activeManifest,
      validationState,
      failures,
      message: !isSigned
        ? "init segment is not signed"
        : isInvalid
          ? "init segment is signed but validation_state is Invalid"
          : "init segment contains a manifest store and is validation-ready"
    }, null, 2);

    return canValidate;
  } finally {
    if (reader) {
      await reader.free();
    }
  }
}

async function validateDownloadedFragment(request, response) {
  const fragmentUrl = request.url || manifestInput.value.trim();
  const initUrl = deriveInitUrl(fragmentUrl, request.mediaType || request.type);
  if (!initUrl) {
    throw new Error(`could not derive init URL from ${fragmentUrl} (mediaType=${request.mediaType || "unknown"})`);
  }

  const fragmentMimeType = request.mimeType || request.mediaType || "video/iso.segment";
  const fragmentBlob = toBlob(response, fragmentMimeType);
  // In live CMAF signing, init segments can be rewritten frequently; always reload to
  // keep fragment validation aligned with the latest signed state.
  const initBlob = await getInitBlob(initUrl, "video/mp4", { forceReload: true });
  const fragmentFormat = normalizeMediaFormat(initBlob.type || fragmentBlob.type || fragmentMimeType);
  const initFormat = normalizeMediaFormat(initBlob.type || fragmentFormat);
  const c2pa = await loadC2pa();

  const fragmentReader = await c2pa.reader.fromBlobFragment(
    fragmentFormat,
    initBlob,
    fragmentBlob
  );

  let reader = fragmentReader;
  let readerSource = "fragment";
  if (!reader) {
    reader = await c2pa.reader.fromBlob(initFormat, initBlob);
    readerSource = "init";
  }

  if (!reader) {
    throw new Error("c2pa reader could not be created from the init segment or fragment");
  }

  const manifestStore = await reader.manifestStore();
  const validationState = getManifestValidationState(manifestStore);
  const failures = getManifestFailures(manifestStore);
  await reader.free();

  return {
    fragmentUrl,
    initUrl,
    fragmentMime: fragmentBlob.type || fragmentMimeType,
    fragmentFormat,
    initMime: initBlob.type || "video/mp4",
    initFormat,
    readerSource,
    validationState,
    failures,
    manifestStore
  };
}

async function onFragmentLoadingCompleted(event) {
  const request = event?.request;
  if (!request) {
    return;
  }

  const requestUrl = request.url || "n/a";
  fragmentEl.textContent = requestUrl;

  if (isInitializationRequest(request)) {
    await updateC2paButtonFromInitSegment(request, event.response);
    return;
  }

  latestValidationContext = {
    request,
    response: event.response
  };

  setC2paState("loading", "verifying downloaded fragment");
  try {
    const validation = await validateDownloadedFragment(request, event.response);
    const isInvalid = validation.validationState.toLowerCase() === "invalid";
    if (isInvalid) {
      const failureText = validation.failures.length > 0
        ? JSON.stringify(validation.failures, null, 2)
        : "ManifestStore validation_state is Invalid";
      throw new Error(failureText);
    }

    setState("ok", `fragment verified (validation_state=${validation.validationState})`);
    setC2paState("ok", `validated (${validation.validationState})`);
    c2paDetailsEl.textContent = JSON.stringify(validation, null, 2);
    detailsEl.textContent = JSON.stringify({
      ok: true,
      fragmentUrl: validation.fragmentUrl,
      initUrl: validation.initUrl,
      validationState: validation.validationState,
      message: "fragment validated in browser"
    }, null, 2);
  } catch (err) {
    setState("bad", "fragment verification failed");
    setC2paState("bad", "failed");
    c2paDetailsEl.textContent = String(err);
    detailsEl.textContent = JSON.stringify({
      ok: false,
      fragmentUrl: requestUrl,
      error: String(err)
    }, null, 2);
  }
}

async function revalidateLatestFragment() {
  if (!latestValidationContext) {
    setState("bad", "no fragment downloaded yet");
    setC2paState("bad", "no fragment to verify");
    return;
  }

  await onFragmentLoadingCompleted({
    request: latestValidationContext.request,
    response: latestValidationContext.response
  });
}

function startValidationMode() {
  setState("", "waiting for fragments");
  setC2paState("", "checking init segment");
  setC2paButtonEnabled(false);
}

playBtn.addEventListener("click", () => {
  startPlayer();
  startValidationMode();
});

c2paBtn.addEventListener("click", revalidateLatestFragment);

setC2paButtonEnabled(false);
startPlayer();
startValidationMode();
