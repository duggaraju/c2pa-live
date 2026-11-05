import { Decoder, Encoder } from "https://esm.sh/cbor-x@1.6.9";

const decoder = new Decoder({ mapsAsObjects: false });
const encoder = new Encoder({ useRecords: false, mapsAsObjects: false, tagUint8Array: false });
const utf8 = new TextDecoder();
const SCHEME = "urn:c2pa:verifiable-segment-info";
const UUID = "d8fec3d61b0e483c92975828877ec481";

function require(condition, message) {
  if (!condition) throw new Error(message);
}

function same(a, b) {
  return a instanceof Uint8Array && b instanceof Uint8Array
    && a.length === b.length && a.every((byte, i) => byte === b[i]);
}

function integer(value) {
  const number = Number(value);
  require(Number.isSafeInteger(number) && number >= 0, "Invalid unsigned integer");
  return number;
}

export function boxes(bytes) {
  const result = [];
  for (let offset = 0; offset < bytes.length;) {
    require(bytes.length - offset >= 8, "Truncated BMFF box");
    const view = new DataView(bytes.buffer, bytes.byteOffset + offset, bytes.length - offset);
    let size = view.getUint32(0);
    let header = 8;
    if (size === 1) {
      require(view.byteLength >= 16, "Truncated large box");
      size = integer(view.getBigUint64(8));
      header = 16;
    } else if (size === 0) {
      size = bytes.length - offset;
    }
    require(size >= header && size <= bytes.length - offset, "Invalid BMFF box size");
    result.push({
      type: utf8.decode(bytes.subarray(offset + 4, offset + 8)),
      offset,
      bytes: bytes.subarray(offset, offset + size),
      data: bytes.subarray(offset + header, offset + size)
    });
    offset += size;
  }
  return result;
}

function one(bytes, type) {
  const found = boxes(bytes).filter(b => b.type === type);
  require(found.length === 1, `Expected one ${type} box`);
  return found[0];
}

function cstring(bytes, offset) {
  const end = bytes.indexOf(0, offset);
  require(end >= offset, "Unterminated BMFF string");
  return [utf8.decode(bytes.subarray(offset, end)), end + 1];
}

function vsi(bytes) {
  const messages = [];
  for (const box of boxes(bytes).filter(b => b.type === "emsg")) {
    if (box.data[0] !== 0) continue;
    const [scheme, next] = cstring(box.data, 4);
    if (scheme !== SCHEME) continue;
    const [value, offset] = cstring(box.data, next);
    require(value === "fseg" && box.data.length >= offset + 16, "Invalid C2PA emsg");
    const view = new DataView(box.data.buffer, box.data.byteOffset + offset, 16);
    require(view.getUint32(0) > 0 && view.getUint32(4) === 0 && view.getUint32(8) > 0, "Invalid emsg timing");
    const tagged = decoder.decode(box.data.subarray(offset + 16));
    require(tagged.tag === 18, "VSI must be tagged COSE_Sign1");
    messages.push(tagged.value);
  }
  require(messages.length === 1, "Expected exactly one C2PA VSI emsg");
  return messages[0];
}

function manifestBytes(init) {
  const uuid = boxes(init).find(b => b.type === "uuid"
    && Array.from(b.data.subarray(0, 16), n => n.toString(16).padStart(2, "0")).join("") === UUID);
  require(uuid && uuid.data[16] === 0, "Missing C2PA manifest box");
  const [purpose, offset] = cstring(uuid.data, 20);
  require(purpose === "manifest", "Unexpected C2PA UUID purpose");
  // The manifest purpose is followed by an 8-byte auxiliary offset.
  return uuid.data.subarray(offset + 8);
}

function jumbfCbor(bytes, label) {
  for (const box of boxes(bytes)) {
    if (box.type !== "jumb") continue;
    const children = boxes(box.data);
    const description = children.find(b => b.type === "jumd");
    if (description && description.data.length > 17
      && cstring(description.data, 17)[0] === label) {
      const cbor = children.find(b => b.type === "cbor");
      require(cbor, `Missing ${label} CBOR`);
      return decoder.decode(cbor.data);
    }
    const nested = jumbfCbor(box.data, label);
    if (nested) return nested;
  }
  return null;
}

function untag(value) {
  return value?.tag === 18 ? value.value : value;
}

async function verifyCose(cose, key, detached) {
  require(Array.isArray(cose) && cose.length === 4, "Malformed COSE_Sign1");
  const [protectedBytes, unprotected, payload, signature] = cose;
  require(decoder.decode(protectedBytes).get(1) === -8, "Expected EdDSA signature");
  require(unprotected instanceof Map, "Invalid COSE header");
  require(detached ? payload === null : payload instanceof Uint8Array, "Invalid COSE payload");
  const structure = encoder.encode(["Signature1", protectedBytes, new Uint8Array(), detached || payload]);
  require(await crypto.subtle.verify("Ed25519", key, signature, structure), "COSE signature mismatch");
}

async function fetchBytes(url) {
  const response = await fetch(url, { cache: "no-store" });
  require(response.ok, `Request failed (${response.status}): ${url}`);
  return new Uint8Array(await response.arrayBuffer());
}

async function digest(bytes) {
  return new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
}

async function verifyHash(bytes, hash) {
  require(hash instanceof Map && hash.get("alg") === "sha256"
    && !hash.has("merkle"), "Unsupported VSI hash");
  const exclusions = hash.get("exclusions");
  require(Array.isArray(exclusions) && exclusions.length > 0, "Missing hash exclusions");
  const scheme = new TextEncoder().encode(SCHEME);
  const terminatedScheme = new TextEncoder().encode(`${SCHEME}\0`);
  const schemeExclusion = exclusion => exclusion instanceof Map
    && exclusion.get("xpath") === "/emsg"
    && !exclusion.has("subset")
    && exclusion.get("data")?.length === 1
    && same(exclusion.get("data")[0].get("value"),
      exclusion.get("data")[0].get("offset") === 0 ? scheme : terminatedScheme);
  require(exclusions.some(e => schemeExclusion(e) && e.get("data")[0].get("offset") === 0),
    "Missing mandatory VSI exclusion");
  require(exclusions.every(e => schemeExclusion(e) && [0, 12].includes(e.get("data")[0].get("offset"))),
    "Unsafe or unsupported VSI exclusions");
  const parts = [];
  for (const box of boxes(bytes)) {
    const excluded = exclusions.some(e => {
      const { offset, value } = Object.fromEntries(e.get("data")[0]);
      return box.type === "emsg" && same(box.bytes.subarray(offset, offset + value.length), value);
    });
    if (excluded) continue;
    const offset = new Uint8Array(8);
    new DataView(offset.buffer).setBigUint64(0, BigInt(box.offset));
    parts.push(offset, box.bytes);
  }
  const input = new Uint8Array(parts.reduce((sum, p) => sum + p.length, 0));
  let position = 0;
  for (const part of parts) { input.set(part, position); position += part.length; }
  require(same(await digest(input), hash.get("hash")), "Media hash mismatch");
}

export class LiveVerifier {
  constructor(c2pa) {
    this.c2pa = c2pa;
    this.sessions = new Map();
    this.sequences = new Map();
    this.initBindings = new Map();
  }

  async bindInitialization(bytes, url) {
    require(!boxes(bytes).some(b => b.type === "mdat"), "Invalid live initialization segment");
    const binding = await digest(one(bytes, "moov").bytes);
    this.initBindings.set(new URL(url, window.location.href).pathname, binding);
  }

  async session(info, fragmentUrl) {
    const ref = info.get("manifestUri");
    require(ref instanceof Map && ref.get("alg") === "sha256", "Missing manifest reference");
    const url = new URL(ref.get("url"), fragmentUrl);
    require(url.origin === window.location.origin && /^\/signed\/(?:[^/.]+\/)*session-[a-f0-9]{64}\.c2pa$/.test(url.pathname),
      "Unsupported external manifest URL");
    const cacheKey = `${url.href}:${info.get("manifestId")}`;
    if (!this.sessions.has(cacheKey)) {
      const pending = this.loadSession(url, info);
      this.sessions.set(cacheKey, pending);
      if (this.sessions.size > 16) this.sessions.delete(this.sessions.keys().next().value);
      try { await pending; } catch (error) { this.sessions.delete(cacheKey); throw error; }
    }
    const session = await this.sessions.get(cacheKey);
    require(same(session.hash, ref.get("hash")), "Manifest reference changed");
    return session;
  }

  async loadSession(url, info) {
    const manifest = await fetchBytes(url);
    const hash = await digest(manifest);
    require(same(hash, info.get("manifestUri").get("hash")), "External manifest hash mismatch");
    const init = await fetchBytes(new URL(url.href.replace(/\.c2pa$/, ".mp4")));
    require(same(manifestBytes(init), manifest), "Signed init does not contain referenced manifest");
    require(!boxes(init).some(b => b.type === "mdat"), "Invalid live initialization segment");
    const reader = await this.c2pa.reader.fromBlob("video/mp4", new Blob([init], { type: "video/mp4" }));
    require(reader, "Session has no C2PA manifest");
    let store;
    try { store = await reader.manifestStore(); } finally { await reader.free(); }
    require(String(store.validation_state || store.validationState).toLowerCase() === "trusted",
      "Session manifest is not trusted");
    require(store.active_manifest === info.get("manifestId"), "Manifest identifier mismatch");
    const assertion = jumbfCbor(manifest, "c2pa.session-keys");
    const signature = untag(jumbfCbor(manifest, "c2pa.signature"));
    require(assertion instanceof Map && Array.isArray(signature), "Missing session keys or claim signature");
    const chain = signature[1].get(33) || decoder.decode(signature[0]).get(33);
    const certificate = Array.isArray(chain) ? chain[0] : chain;
    require(certificate instanceof Uint8Array, "Missing end-entity certificate");
    const keys = new Map();
    for (const entry of assertion.get("keys") || []) {
      const key = entry.get("key");
      require(key.get(1) === 1 && key.get(-1) === 6 && key.get(-2)?.length === 32
        && key.get(2) instanceof Uint8Array && key.get(2).length > 0, "Unsupported session public key");
      const imported = await crypto.subtle.importKey("raw", key.get(-2), "Ed25519", false, ["verify"]);
      await verifyCose(untag(entry.get("signerBinding")), imported, certificate);
      const created = entry.get("createdAt");
      require(created instanceof Date && Number.isFinite(created.getTime()), "Invalid session creation time");
      const validity = integer(entry.get("validityPeriod"));
      require(validity > 0, "Invalid session validity period");
      keys.set(Array.from(key.get(2)).join(","), {
        key: imported, created: created.getTime() / 1000, validity, min: integer(entry.get("minSequenceNumber"))
      });
    }
    require(keys.size > 0, "Empty session keys assertion");
    return { keys, hash, moov: await digest(one(init, "moov").bytes) };
  }

  async verify(bytes, fragmentUrl, replayCheck = true) {
    const cose = vsi(bytes);
    const info = decoder.decode(cose[2]);
    require(info instanceof Map, "Invalid segment info");
    const session = await this.session(info, fragmentUrl);
    const key = session.keys.get(Array.from(cose[1].get(4) || []).join(","));
    require(key, "Unknown session key");
    await verifyCose(cose, key.key);
    const iat = decoder.decode(cose[0]).get("iat");
    require(Number.isSafeInteger(iat) && iat >= key.created && iat < key.created + key.validity,
      "Segment signed outside session key validity period");
    const sequence = integer(info.get("sequenceNumber"));
    const mfhd = one(one(bytes, "moof").data, "mfhd").data;
    require(mfhd.length >= 8 && sequence === new DataView(mfhd.buffer, mfhd.byteOffset).getUint32(4)
      && sequence >= key.min, "Invalid media sequence");
    const track = new URL(fragmentUrl).pathname.replace(/chunk-([^-]+)-\d+\.m4s$/, "init-$1.mp4");
    const binding = this.initBindings.get(track);
    require(binding && same(binding, session.moov), "Initialization binding does not match signed session");
    await verifyHash(bytes, info.get("bmffHash"));
    const previous = this.sequences.get(track);
    require(!replayCheck || previous === undefined || sequence > previous, "Repeated or out-of-order segment");
    this.initBindings.set(track, session.moov);
    if (replayCheck) this.sequences.set(track, sequence);
    return { sequence, manifestId: info.get("manifestId"), validationState: "Trusted", protocol: "C2PA 2.4 VSI" };
  }
}
