# c2pa-live

A Rust CLI that:

- Runs a Hyper HTTP server for ingest and playback.
- Launches FFmpeg via `essi-ffmpeg` command builder and the system `ffmpeg` binary.
- Produces DASH (`.mpd`) + HLS (`.m3u8`) in live mode.
- Signs fragmented media with C2PA provenance and writes signed outputs.

## What It Does

1. Starts an HTTP server (default: `127.0.0.1:8080`).
2. Starts a live FFmpeg pipeline that continuously pushes DASH/HLS fragments to the same server via HTTP `PUT`.
3. Stores incoming files under `live_output/`.
4. Detects init + media fragments and signs them with C2PA into `signed_output/`.
5. Serves files over HTTP (`signed_output` is preferred when available).

## Runtime Prerequisites

This app uses the distribution-provided `ffmpeg` executable.

On Ubuntu/Debian, install:

```bash
sudo apt-get update
sudo apt-get install -y ffmpeg
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
  --key /path/to/private_key.pem
```

Optional flags:

- `--listen 127.0.0.1:8080`
- `--storage-dir live_output`
- `--signed-dir signed_output`
- `--signing-alg es256|ps256|ed25519`
- `--segment-duration 2.0`
- `--video-codec libx264`
- `--audio-codec aac`
- `--hwaccel <name>` (optional hardware decode, for example `cuda`, `vaapi`, `qsv`, `d3d11va`)
- `--hwaccel-device <device>` (optional hardware device path/index)
- `--hwaccel-output-format <fmt>` (optional hardware pixel format)
- `--video-codec <codec>` (set encoder, for example `libx264`, `h264_nvenc`, `hevc_vaapi`, `h264_qsv`)
- `--no-loop` (disable input looping)

## Outputs

- Unsigned ingest: `live_output/...` (for example `live_output/manifest.mpd`)
- Signed fragments: `signed_output/...` (for example `signed_output/manifest.mpd`)
- DASH manifest: `http://127.0.0.1:8080/live/manifest.mpd`
- HLS playlists: generated alongside DASH outputs by the FFmpeg dash muxer and served under `/live/...`
