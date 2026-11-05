use anyhow::{Context, Result, ensure};

pub(crate) const SCHEME: &str = "urn:c2pa:verifiable-segment-info";

pub(crate) struct BoxRef<'a> {
    pub kind: &'a [u8],
    pub data: &'a [u8],
    pub offset: usize,
}

pub(crate) fn boxes(data: &[u8]) -> Result<Vec<BoxRef<'_>>> {
    let mut result = Vec::new();
    let mut offset = 0;
    while offset < data.len() {
        let rest = &data[offset..];
        ensure!(rest.len() >= 8, "Truncated BMFF box header");
        let size = u32_at(rest, 0)?;
        let (size, header) = match size {
            0 => (rest.len(), 8),
            1 => (usize::try_from(u64_at(rest, 8)?)?, 16),
            size => (usize::try_from(size)?, 8),
        };
        ensure!(
            size >= header && size <= rest.len(),
            "Invalid BMFF box size"
        );
        result.push(BoxRef {
            kind: &rest[4..8],
            data: &rest[header..size],
            offset,
        });
        offset += size;
    }
    Ok(result)
}

fn child<'a>(data: &'a [u8], kind: &[u8]) -> Result<&'a [u8]> {
    let matches: Vec<_> = boxes(data)?
        .into_iter()
        .filter(|b| b.kind == kind)
        .collect();
    ensure!(
        matches.len() == 1,
        "Expected exactly one {} box",
        String::from_utf8_lossy(kind)
    );
    Ok(matches[0].data)
}

pub(crate) fn u32_at(data: &[u8], offset: usize) -> Result<u32> {
    let bytes = data
        .get(offset..offset + 4)
        .context("Truncated BMFF integer")?;
    Ok(u32::from_be_bytes(bytes.try_into()?))
}

fn u64_at(data: &[u8], offset: usize) -> Result<u64> {
    let bytes = data
        .get(offset..offset + 8)
        .context("Truncated BMFF integer")?;
    Ok(u64::from_be_bytes(bytes.try_into()?))
}

#[derive(Clone, Copy)]
pub(crate) struct TrackTiming {
    pub timescale: u32,
    default_duration: u32,
    track_id: u32,
}

impl TrackTiming {
    pub fn from_init(init: &[u8]) -> Result<Self> {
        ensure!(
            !boxes(init)?.iter().any(|b| b.kind == b"mdat"),
            "Live initialization segment must not contain mdat"
        );
        let moov = child(init, b"moov")?;
        let trak = child(moov, b"trak")?;
        let tkhd = child(trak, b"tkhd")?;
        let track_id = u32_at(tkhd, if tkhd.first() == Some(&1) { 20 } else { 12 })?;
        let mdhd = child(child(trak, b"mdia")?, b"mdhd")?;
        let timescale = u32_at(mdhd, if mdhd.first() == Some(&1) { 20 } else { 12 })?;
        ensure!(timescale > 0, "Track timescale must be positive");
        let trex = child(child(moov, b"mvex")?, b"trex")?;
        ensure!(
            u32_at(trex, 4)? == track_id,
            "trex track does not match initialization track"
        );
        Ok(Self {
            timescale,
            default_duration: u32_at(trex, 12)?,
            track_id,
        })
    }

    pub fn segment(&self, data: &[u8]) -> Result<(u32, u32)> {
        let root = boxes(data)?;
        ensure!(
            root.iter().any(|b| b.kind == b"mdat"),
            "Media segment has no mdat"
        );
        // Appending an excluded emsg must not change the interpretation of a size-to-EOF box.
        ensure!(
            root.iter()
                .all(|b| u32_at(data, b.offset).is_ok_and(|size| size != 0)),
            "Size-to-EOF boxes cannot precede a live emsg"
        );
        let moof = child(data, b"moof")?;
        let sequence = u32_at(child(moof, b"mfhd")?, 4)?;
        let traf = child(moof, b"traf")?;
        let tfhd = child(traf, b"tfhd")?;
        ensure!(
            u32_at(tfhd, 4)? == self.track_id,
            "Media track does not match initialization track"
        );
        let flags = u32_at(tfhd, 0)? & 0x00ff_ffff;
        let mut offset = 8;
        if flags & 1 != 0 {
            offset += 8;
        }
        if flags & 2 != 0 {
            offset += 4;
        }
        let default_duration = if flags & 8 != 0 {
            u32_at(tfhd, offset)?
        } else {
            self.default_duration
        };
        let mut duration = 0u64;
        let mut runs = 0;
        for trun in boxes(traf)?.into_iter().filter(|b| b.kind == b"trun") {
            runs += 1;
            let flags = u32_at(trun.data, 0)? & 0x00ff_ffff;
            let count = u32_at(trun.data, 4)?;
            let mut offset = 8;
            if flags & 1 != 0 {
                offset += 4;
            }
            if flags & 4 != 0 {
                offset += 4;
            }
            let stride = ((flags & 0xf00).count_ones() as usize) * 4;
            let bytes = usize::try_from(count)?
                .checked_mul(stride)
                .context("trun size overflow")?;
            ensure!(
                offset <= trun.data.len() && bytes <= trun.data.len() - offset,
                "Truncated trun samples"
            );
            if flags & 0x100 == 0 {
                ensure!(default_duration > 0, "Sample duration is not specified");
                duration = duration
                    .checked_add(u64::from(count) * u64::from(default_duration))
                    .context("Segment duration overflow")?;
            } else {
                for _ in 0..count {
                    duration = duration
                        .checked_add(u64::from(u32_at(trun.data, offset)?))
                        .context("Segment duration overflow")?;
                    offset += stride;
                }
            }
        }
        ensure!(runs > 0 && duration > 0, "Empty media segment");
        Ok((
            sequence,
            u32::try_from(duration).context("Segment duration exceeds emsg limit")?,
        ))
    }
}

pub(crate) fn encode(message: &[u8], timescale: u32, duration: u32, id: u32) -> Result<Vec<u8>> {
    ensure!(timescale > 0 && duration > 0, "Invalid emsg timing");
    let mut data = vec![0; 4]; // FullBox version 0 and flags.
    data.extend_from_slice(SCHEME.as_bytes());
    data.push(0);
    data.extend_from_slice(b"fseg\0");
    data.extend_from_slice(&timescale.to_be_bytes());
    data.extend_from_slice(&0u32.to_be_bytes());
    data.extend_from_slice(&duration.to_be_bytes());
    data.extend_from_slice(&id.to_be_bytes());
    data.extend_from_slice(message);
    make_box(b"emsg", &data)
}

pub(crate) fn make_box(kind: &[u8; 4], payload: &[u8]) -> Result<Vec<u8>> {
    let size = u32::try_from(payload.len().checked_add(8).context("Box size overflow")?)?;
    let mut out = size.to_be_bytes().to_vec();
    out.extend_from_slice(kind);
    out.extend_from_slice(payload);
    Ok(out)
}

pub(crate) fn message(data: &[u8]) -> Result<Option<&[u8]>> {
    let mut found = None;
    for b in boxes(data)? {
        if b.kind != b"emsg" {
            continue;
        }
        ensure!(b.data.len() >= 4, "Truncated emsg");
        if b.data[0] != 0 {
            continue;
        }
        let rest = &b.data[4..];
        let end = rest
            .iter()
            .position(|b| *b == 0)
            .context("Unterminated emsg scheme")?;
        if &rest[..end] != SCHEME.as_bytes() {
            continue;
        }
        ensure!(found.is_none(), "Duplicate C2PA emsg");
        let rest = &rest[end + 1..];
        ensure!(
            rest.starts_with(b"fseg\0") && rest.len() >= 21,
            "Invalid C2PA emsg fields"
        );
        ensure!(
            u32_at(rest, 5)? > 0 && u32_at(rest, 9)? == 0 && u32_at(rest, 13)? > 0,
            "Invalid C2PA emsg timing"
        );
        found = Some(&rest[21..]);
    }
    Ok(found)
}
