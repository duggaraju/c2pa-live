# c2pa-live

A Rust CLI that:

- Runs a Hyper HTTP server for ingest and playback.
- Launches FFmpeg via `essi-ffmpeg` command builder and the system `ffmpeg` binary.
- Produces DASH (`.mpd`) + HLS (`.m3u8`) in live mode.
- Signs live CMAF using the C2PA 2.4 Verifiable Segment Info (VSI) method.

## What It Does

1. Starts an HTTP server (default: `127.0.0.1:8080`).
2. Starts a live FFmpeg pipeline that continuously pushes DASH/HLS fragments to the same server via HTTP `PUT`.
3. Stores incoming files under `live_output/`.
4. Signs each track's initialization segment with the configured C2PA certificate,
   including a standard `c2pa.session-keys` assertion.
5. Signs each media segment with a short-lived Ed25519 session key and appends a
   version-0 `emsg` containing a tagged COSE_Sign1 VSI. Its BMFF v3 hash covers the
   segment (including box offsets), excluding only C2PA VSI events.
6. Publishes signed files atomically before acknowledging ingest. Signing errors
   fail the upload, rather than publishing unsigned data at a signed URL.

The implementation follows [C2PA 2.4 sections 18.25 and 19.4](https://spec.c2pa.org/specifications/specifications/2.4/specs/C2PA_Specification.html#live-video).
Session public keys have certificate-binding signatures, tagged creation times,
minimum sequence numbers, and validity periods. Rotation creates a new signed
manifest; every VSI references its immutable external manifest with an absolute
URL and SHA-256 hash. Historical media is never rescanned or re-signed.

## Runtime Prerequisites

Requires Rust 1.96+, the distribution-provided `ffmpeg` executable, and OpenSSL
development libraries for the default dependency features. Tests also use the
`openssl` executable to generate ephemeral test certificates.

On Ubuntu/Debian, install:

```bash
sudo apt-get update
sudo apt-get install -y ffmpeg pkg-config libssl-dev
```

## Usage

Download a sample source file (Big Buck Bunny):

Official source index:

- https://download.blender.org/demo/movies/BBB/

```bash
mkdir -p media
# Official 1080p 30fps file (normal):
curl -L "https://download.blender.org/demo/movies/BBB/bbb_sunflower_1080p_30fps_normal.mp4.zip" -o media/big_buck_bunny_1080p_30fps.zip
unzip -o media/big_buck_bunny_1080p_30fps.zip -d media
```

```bash
cargo run -- \
  --input ./media/bbb_sunflower_1080p_30fps_normal.mp4 \
  --cert /path/to/signcert.pem \
  --key /path/to/private_key.pem \
  --trust-anchors /path/to/trusted-roots.pem
```

Open `http://127.0.0.1:8080/client/` for the browser player. The browser validates
the C2PA session manifest against these explicit trust anchors, verifies the
certificate/session-key binding and every media COSE signature and BMFF hash,
and rejects replayed/out-of-order segments. It checks the signed claimed time
against the key's validity period; that claimed time is not an independent
trusted timestamp. It also checks the played init's `moov` against the signed
session init. An init-only validation is never treated as proof of media integrity.
Without trust anchors, playback remains available but verification is not claimed.
Browser verification requires a secure context (HTTPS or localhost) and Ed25519
WebCrypto support.

Optional flags:

- `--listen 127.0.0.1:8080`
- `--storage-dir live` (unsigned ingest)
- `--signed-dir signed` (must not overlap the unsigned directory)
- `--public-base-url https://stream.example.com` (public origin used in key-manifest
  URLs; defaults to `http://<listen>`, so set this for remote clients/reverse proxies)
- `--signing-alg es256|ps256|ed25519`
- `--segment-duration 1.0`
- `--playback-delay <seconds>` (defaults to three segment durations)
- `--session-key-validity-secs 300`
- `--session-key-overlap-secs 30` (positive and strictly less than validity)
- `--timestamp-url <TSA URL>` (timestamps certificate-signed manifests, not every segment)
- `--settings <path>` (defaults to `./settings.toml` when present)
- `--no-cache`
- `--video-codec libx264`
- `--audio-codec aac`
- `--hwaccel <name>` (optional hardware decode, for example `cuda`, `vaapi`, `qsv`, `d3d11va`)
- `--hwaccel-device <device>` (optional hardware device path/index)
- `--hwaccel-output-format <fmt>` (optional hardware pixel format)
- `--video-codec <codec>` (set encoder, for example `libx264`, `h264_nvenc`, `hevc_vaapi`, `h264_qsv`)
- `--no-loop` (disable input looping)

## Outputs

- Unsigned ingest: `live/...`, served only at `/live/...` and bare paths.
- Signed DASH manifest: `http://127.0.0.1:8080/signed/manifest.mpd`
- Signed fragments and initialization segments: `/signed/chunk-*.m4s`, `/signed/init-*.mp4`.
- Immutable session manifests and signed init copies: `/signed/session-*.c2pa` and `.mp4`.
- HLS playlists: generated alongside DASH outputs by the FFmpeg dash muxer and served under `/live/...`
  (unsigned) and `/signed/...` (signed). Ordinary HLS/DASH players can play the
  media but need a VSI-aware verifier to authenticate it.

Keep session manifests and their immutable init copies available as long as
their media is available. FFmpeg's rolling-window DELETE requests remove expired
media from both output trees; session manifests are retained. Use fresh output
directories for a new broadcast, rather than reusing
stale manifests from an earlier process.

## Latency versus signing work

**It matters, but there are two separate signing frequencies.** Every media
segment is signed with a session key; the certificate signs only the manifests
that authorize those keys. You can reduce certificate/TSA operations without
increasing segment duration or playback delay.

| Setting | Default | Effect |
|---|---|---|
| `--segment-duration` | 1 second | Lower values reduce segment buffering latency but increase session-key signatures and HTTP requests. |
| `--playback-delay` | 3 times segment duration, in seconds | Controls the bundled browser player's live-edge delay. Lower values increase stall risk; this does **not** change either signing frequency. Other players have their own buffering settings. |
| `--session-key-validity-secs` | 300 seconds | Longer lifetimes reduce certificate/TSA operations but extend session-key exposure. This is **not** a buffering delay: playback does not wait for the key to expire. |
| `--session-key-overlap-secs` | 30 seconds | Starts rotation this many seconds before expiry. At a fixed lifetime, a **larger** overlap rotates earlier and therefore **increases** certificate/TSA frequency. |

### Estimate the signing rate

For `R` tracks, segment duration `S`, key lifetime `V`, and overlap `O`:

- **Media session-key signatures:** approximately `R / S` per second.
- **Certificate-signed manifests:** one per track at initialization, then
  approximately `R / (V - O)` per second during continuous ingest.
- Each new key also makes one session-key signature binding it to the certificate.
  An optional TSA adds timestamping work when signing manifests, not per segment.

The usual video + audio output has **two tracks**, so the default one-second
segments require approximately **two media signatures per second**. With the
default `V = 300` and `O = 30`, each track's certificate-signed manifest is renewed
approximately every **270 seconds**, independent of the segment duration.
Additional renditions increase the track count and both rates.

Rotation is checked when a media segment arrives, not by a background timer, so
these are approximate rates. Session signing always uses Ed25519;
`--signing-alg` selects the certificate's manifest-signing algorithm only.
Each track must have one session signature per segment: there is no "sign every
Nth segment" option, and skipping signatures is not conformant to the VSI method.

### Configuration examples

Append these flags to the command in [Usage](#usage). Rates below assume one
video track and one audio track, and exclude initialization/rotation work.

| Goal | Flags | Approximate media signatures/second |
|---|---|---|
| Balanced (default) | `--segment-duration 1 --playback-delay 3` | 2 |
| Lower buffering latency | `--segment-duration 0.5 --playback-delay 1.5` | 4 |
| Aggressive small buffer | `--segment-duration 0.25 --playback-delay 0.75` | 8 |
| Fewer media signatures and requests | `--segment-duration 2 --playback-delay 6` | 1 |

To keep half-second segments but reduce certificate/TSA operations:

```bash
--segment-duration 0.5 --playback-delay 1.5 \
--session-key-validity-secs 3600 --session-key-overlap-secs 30
```

This still makes approximately **four media signatures per second**, but renews
each track's certificate-signed manifest about every **3570 seconds (59 minutes
30 seconds)** instead of every 270 seconds. Use a longer lifetime only if that
key-exposure window is acceptable for your application.

Start with the defaults. Reduce segment duration if segment buffering dominates
latency; increase it if per-segment signing/HTTP overhead cannot keep up. If only
certificate signing or TSA calls are expensive, increase key lifetime instead.
Adjust playback delay separately for network jitter and stalls. These are buffer
targets, **not guaranteed end-to-end latency values**.

### Practical latency limits

The video keyframe schedule follows the configured segment duration, rather than
a fixed two-second GOP. The software H.264 encoder uses `veryfast` and `zerolatency`;
hardware encoders retain their own tuning. Actual durations are quantized to
video frames/audio packets; DASH timelines describe their actual durations.
Playlist updates are advertised at one second (the FFmpeg option accepts integer
seconds), which can limit how close to the live edge very small buffers can play.

This is **whole-segment** signing, not partial-segment LL-HLS/LL-DASH: the complete
segment is needed before its hash can be signed. Ingest does not wait for a disk
`fsync`, so atomic publication is not a power-loss durability guarantee. Initial
certificate signing and rollover, especially when using a remote TSA, can still
add latency: rollover is performed inline before publishing the triggering
segment. Overlap does not make that work asynchronous or eliminate the stall.
Keep overlap positive and smaller than lifetime, leave enough lifetime for
manifest signing and delivery, and allow playback-buffer headroom for rollover
and network variability.

The supported profile is one track and one `moof` per media segment, as emitted
by the configured FFmpeg DASH muxer. Multiplexed tracks, MPEG-TS, and multi-`moof`
partial segments are rejected explicitly. The browser verifier supports this
application's Ed25519/SHA-256 VSI profile, not every possible C2PA live-video
profile. This is not a claim of independent C2PA conformance certification.

## Validation

```bash
cargo test --locked
cargo clippy --locked --all-targets -- -D warnings
```

Tests generate both audio and video with FFmpeg, validate signed initialization
segments with the SDK, check on-wire CBOR and certificate-binding signatures,
exercise rotation and certificate-signing frequency, and reject tampered media,
invalid signatures, expired keys, and malformed input.
