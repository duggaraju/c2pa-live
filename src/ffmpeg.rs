use std::io::{BufRead, BufReader};
use std::net::SocketAddr;
use std::path::PathBuf;

use anyhow::{Context, Result};
use clap::Args;
use essi_ffmpeg::{FFmpeg, FFmpegCommand};

const DASH_ADAPTATION_SETS: &str = "id=0,streams=v id=1,streams=a";
const DASH_MAP_VIDEO: &str = "0:v:0";
const DASH_MAP_AUDIO: &str = "0:a:0";
const DASH_INIT_SEGMENT_NAME: &str = "init-$RepresentationID$.mp4";
const DASH_MEDIA_SEGMENT_NAME: &str = "chunk-$RepresentationID$-$Number%05d$.m4s";
const DASH_STREAMING_MODE: &str = "0";
const DASH_LDASH_MODE: &str = "0";
const DASH_FRAG_TYPE: &str = "none";
const DASH_REMOVE_AT_EXIT: &str = "0";
const LIVE_PUBLISH_PREFIX: &str = "live";

#[derive(Debug, Args, Clone)]
#[command(next_help_heading = "FFmpeg")]
pub(crate) struct FfmpegArgs {
    #[arg(short = 'i', long)]
    pub input: PathBuf,

    #[arg(long, default_value_t = 1.0, value_parser = parse_positive_duration,
        help = "Segment duration in seconds; shorter segments lower latency but require more session signatures")]
    pub segment_duration: f64,

    #[arg(long, default_value = "libx264")]
    video_codec: String,

    #[arg(long, default_value = "aac")]
    audio_codec: String,

    #[arg(long)]
    hwaccel: Option<String>,

    #[arg(long)]
    hwaccel_device: Option<String>,

    #[arg(long)]
    hwaccel_output_format: Option<String>,

    #[arg(long, default_value_t = false)]
    no_loop: bool,
}

impl FfmpegArgs {
    fn command_args(&self, listen: SocketAddr) -> Result<Vec<String>> {
        let output_url = format!("http://{}/{}/manifest.mpd", listen, LIVE_PUBLISH_PREFIX);

        println!("starting ffmpeg live publish to {output_url}");

        let input_path = self
            .input
            .to_str()
            .context("Input path contains invalid UTF-8")?;

        let mut args = vec!["-hide_banner".to_string(), "-re".to_string()];

        if let Some(hwaccel) = &self.hwaccel {
            args.push("-hwaccel".to_string());
            args.push(hwaccel.clone());
        }
        if let Some(hwaccel_device) = &self.hwaccel_device {
            args.push("-hwaccel_device".to_string());
            args.push(hwaccel_device.clone());
        }
        if let Some(hwaccel_output_format) = &self.hwaccel_output_format {
            args.push("-hwaccel_output_format".to_string());
            args.push(hwaccel_output_format.clone());
        }

        if !self.no_loop {
            args.push("-stream_loop".to_string());
            args.push("-1".to_string());
        }

        args.extend([
            "-i".to_string(),
            input_path.to_string(),
            "-map".to_string(),
            DASH_MAP_VIDEO.to_string(),
            "-c:v".to_string(),
            self.video_codec.clone(),
            "-map".to_string(),
            DASH_MAP_AUDIO.to_string(),
            "-c:a".to_string(),
            self.audio_codec.clone(),
            "-sc_threshold".to_string(),
            "0".to_string(),
            "-bf".to_string(),
            "0".to_string(),
            "-force_key_frames".to_string(),
            // An absolute time grid can create short GOPs that DASH merges into longer segments.
            format!(
                "expr:if(isnan(prev_forced_t),1,gte(t,prev_forced_t+{}-0.000001))",
                self.segment_duration
            ),
            "-f".to_string(),
            "dash".to_string(),
            "-streaming".to_string(),
            DASH_STREAMING_MODE.to_string(),
            "-ldash".to_string(),
            DASH_LDASH_MODE.to_string(),
            "-frag_type".to_string(),
            DASH_FRAG_TYPE.to_string(),
            "-hls_playlist".to_string(),
            "1".to_string(),
            "-use_template".to_string(),
            "1".to_string(),
            "-use_timeline".to_string(),
            "1".to_string(),
            "-update_period".to_string(),
            "1".to_string(),
            "-window_size".to_string(),
            "5".to_string(),
            "-extra_window_size".to_string(),
            "10".to_string(),
            "-seg_duration".to_string(),
            self.segment_duration.to_string(),
            "-frag_duration".to_string(),
            self.segment_duration.to_string(),
            "-adaptation_sets".to_string(),
            DASH_ADAPTATION_SETS.to_string(),
            "-init_seg_name".to_string(),
            DASH_INIT_SEGMENT_NAME.to_string(),
            "-media_seg_name".to_string(),
            DASH_MEDIA_SEGMENT_NAME.to_string(),
            "-remove_at_exit".to_string(),
            DASH_REMOVE_AT_EXIT.to_string(),
            "-hls_segment_type".to_string(),
            "fmp4".to_string(),
            "-method".to_string(),
            "PUT".to_string(),
            "-http_persistent".to_string(),
            "0".to_string(),
            output_url,
        ]);

        if self.video_codec == "libx264" {
            let output_position = args.len() - 1;
            args.splice(
                output_position..output_position,
                [
                    "-preset".into(),
                    "veryfast".into(),
                    "-tune".into(),
                    "zerolatency".into(),
                ],
            );
        }
        Ok(args)
    }

    pub fn start_ffmpeg_live(&self, listen: SocketAddr) -> Result<FFmpegCommand> {
        let args = self.command_args(listen)?;
        println!("ffmpeg command: ffmpeg {}", args.join(" "));

        let mut ffmpeg = FFmpeg::new_with_program("ffmpeg")
            .args(args)
            .start()
            .with_context(|| "Failed to start ffmpeg process")?;

        attach_ffmpeg_loggers(&mut ffmpeg);
        Ok(ffmpeg)
    }
}

pub(crate) fn parse_positive_duration(value: &str) -> std::result::Result<f64, String> {
    let duration: f64 = value
        .parse()
        .map_err(|_| "Expected a positive finite duration".to_string())?;
    if !duration.is_finite() || duration <= 0.0 {
        return Err("Duration must be positive and finite".into());
    }
    Ok(duration)
}

fn attach_ffmpeg_loggers(ffmpeg: &mut FFmpegCommand) {
    if let Some(stdout) = ffmpeg.take_stdout() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stdout);
            for line in reader.lines() {
                match line {
                    Ok(line) => println!("[ffmpeg][stdout] {line}"),
                    Err(err) => {
                        eprintln!("[ffmpeg][stdout] read error: {err}");
                        break;
                    }
                }
            }
        });
    }

    if let Some(stderr) = ffmpeg.take_stderr() {
        std::thread::spawn(move || {
            let reader = BufReader::new(stderr);
            for line in reader.lines() {
                match line {
                    Ok(line) => eprintln!("[ffmpeg][stderr] {line}"),
                    Err(err) => {
                        eprintln!("[ffmpeg][stderr] read error: {err}");
                        break;
                    }
                }
            }
        });
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use clap::Parser;

    #[test]
    fn short_segments_control_keyframes_without_fixed_two_second_gop() -> Result<()> {
        let cli = crate::Cli::try_parse_from([
            "c2pa-live",
            "--input",
            "input.mp4",
            "--cert",
            "cert.pem",
            "--key",
            "key.pem",
            "--segment-duration",
            "0.25",
        ])?;
        let args = cli.ffmpeg.command_args("127.0.0.1:8080".parse()?)?;
        assert!(args.windows(2).any(|p| p
            == [
                "-force_key_frames",
                "expr:if(isnan(prev_forced_t),1,gte(t,prev_forced_t+0.25-0.000001))"
            ]));
        assert!(args.windows(2).any(|p| p == ["-seg_duration", "0.25"]));
        assert!(args.windows(2).any(|p| p == ["-use_timeline", "1"]));
        assert!(args.windows(2).any(|p| p == ["-update_period", "1"]));
        assert!(
            !args
                .iter()
                .any(|a| a == "-g" || a == "-keyint_min" || a == "-ignore_io_errors")
        );
        let input = args.iter().position(|a| a == "-i").unwrap();
        let tune = args.iter().position(|a| a == "-tune").unwrap();
        assert!(tune > input && tune < args.len() - 1);
        Ok(())
    }
}
