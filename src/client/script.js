import { createC2pa } from "https://esm.sh/@contentauth/c2pa-web@0.16.0/inline";
import { LiveVerifier } from "./live.js";

const video = document.getElementById("video");
const manifestInput = document.getElementById("manifest");
const playBtn = document.getElementById("playBtn");
const c2paBtn = document.getElementById("c2paBtn");
const stateEl = document.getElementById("state");
const fragmentEl = document.getElementById("fragment");
const detailsEl = document.getElementById("details");
const c2paStateEl = document.getElementById("c2paState");
const c2paDetailsEl = document.getElementById("c2paDetails");

let player;
let verifier;
let latest;
let generation = 0;
let verificationQueue = Promise.resolve();

function state(kind, message) {
  for (const element of [stateEl, c2paStateEl]) {
    element.textContent = message;
    element.classList.remove("ok", "bad");
    if (kind) element.classList.add(kind);
  }
}

async function initialize() {
  const response = await fetch("/api/c2pa/cert-chain.pem", { cache: "no-store" });
  if (!response.ok) throw new Error("Configure --trust-anchors to enable browser verification");
  const pem = await response.text();
  return createC2pa({
    settings: {
      trust: { trustAnchors: pem, userAnchors: pem },
      verify: { verifyTrust: true, verifyAfterReading: true }
    }
  });
}

const c2pa = initialize();
// Keep playback available when trust configuration is absent, but never claim verification.
c2pa.catch(error => state("bad", String(error)));

async function validate(request, response, run, replayCheck = true) {
  if (run !== generation) return;
  const activeVerifier = verifier;
  const bytes = response instanceof ArrayBuffer ? new Uint8Array(response)
    : ArrayBuffer.isView(response) ? new Uint8Array(response.buffer, response.byteOffset, response.byteLength)
      : new Uint8Array(await new Blob([response]).arrayBuffer());
  const url = new URL(request.url, window.location.href).href;
  const result = await activeVerifier.verify(bytes, url, replayCheck);
  if (run !== generation) return;
  state("ok", `VSI verified: segment ${result.sequence}`);
  detailsEl.textContent = JSON.stringify({ ok: true, fragmentUrl: url, ...result }, null, 2);
  c2paDetailsEl.textContent = detailsEl.textContent;
  c2paBtn.disabled = false;
}

function onFragment(event, run) {
  const request = event?.request;
  if (!request || run !== generation) return;
  const initialization = typeof request.isInitializationRequest === "function"
    ? request.isInitializationRequest()
    : ["InitializationSegment", "Initialization"].includes(request.type);
  if (initialization) {
    const response = event.response;
    verificationQueue = verificationQueue.then(async () => {
      if (run !== generation) return;
      const bytes = new Uint8Array(await new Blob([response]).arrayBuffer());
      await verifier.bindInitialization(bytes, request.url);
    }).catch(error => {
      if (run === generation) state("bad", String(error));
    });
    return;
  }
  fragmentEl.textContent = request.url;
  latest = { request, response: event.response };
  verificationQueue = verificationQueue.then(async () => {
    if (run !== generation) return;
    await validate(request, event.response, run);
  }).catch(error => {
    if (run !== generation) return;
    state("bad", "Fragment verification failed");
    detailsEl.textContent = String(error);
    c2paDetailsEl.textContent = String(error);
  });
}

async function startPlayer() {
  const run = ++generation;
  if (player) player.reset();
  latest = null;
  c2paBtn.disabled = true;
  state("", "Waiting for signed segments");
  const response = await fetch("/api/live-config", { cache: "no-store" });
  if (!response.ok) throw new Error(`Live configuration failed: ${response.status}`);
  const config = await response.json();
  const client = await c2pa.catch(error => {
    state("bad", String(error));
    return null;
  });
  if (run !== generation) return;
  verifier = client ? new LiveVerifier(client) : null;
  player = dashjs.MediaPlayer().create();
  player.updateSettings({ streaming: { delay: { liveDelay: config.playbackDelay } } });
  if (verifier) player.on(dashjs.MediaPlayer.events.FRAGMENT_LOADING_COMPLETED, event => onFragment(event, run));
  player.initialize(video, manifestInput.value.trim(), true);
}

function start() {
  startPlayer().catch(error => state("bad", String(error)));
}

playBtn.addEventListener("click", start);
c2paBtn.addEventListener("click", () => {
  if (!latest || !verifier) return;
  const snapshot = latest;
  const run = generation;
  verificationQueue = verificationQueue.then(() => validate(snapshot.request, snapshot.response, run, false))
    .catch(error => state("bad", String(error)));
});
start();
