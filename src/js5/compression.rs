use super::{CacheError, Result};
use crate::Packet;
use crate::bz2::{bz2_compress, bz2_decompress};
use crate::crc::getcrc;
use crate::gz::{gz_compress_with, gz_decompress};
use rs_crypto::xtea::Xtea;
use std::borrow::Cow;
use std::io::Cursor;

/// Compression type used in cache
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
#[repr(u8)]
pub enum CompressionType {
    None = 0,
    Bzip2 = 1,
    Gzip = 2,
    Lzma = 3,
}

impl TryFrom<u8> for CompressionType {
    type Error = CacheError;

    fn try_from(value: u8) -> std::result::Result<Self, Self::Error> {
        match value {
            0 => Ok(CompressionType::None),
            1 => Ok(CompressionType::Bzip2),
            2 => Ok(CompressionType::Gzip),
            3 => Ok(CompressionType::Lzma),
            _ => Err(CacheError::Decompression(format!(
                "Unknown compression type: {}",
                value
            ))),
        }
    }
}

pub struct Container<'a> {
    pub compression: CompressionType,
    pub compressed_len: u32,
    pub uncompressed_len: u32,
    pub version: Option<u16>,
    pub data: &'a [u8],
}

impl<'a> Container<'a> {
    pub fn parse(raw: &'a [u8]) -> Result<Self> {
        if raw.len() < 5 {
            return Err(CacheError::InvalidFormat);
        }
        let mut buf = Packet::from(raw);
        let compression = CompressionType::try_from(buf.g1())?;
        let compressed_len = buf.g4s() as u32;
        let header_len = if compression == CompressionType::None {
            5
        } else {
            9
        };
        let end = header_len + compressed_len as usize;
        let data = raw.get(..end).ok_or(CacheError::InvalidFormat)?;
        let uncompressed_len = if compression == CompressionType::None {
            compressed_len
        } else {
            buf.g4s() as u32
        };
        let version = raw.get(end..end + 2).map(|bytes| Packet::from(bytes).g2());
        Ok(Self {
            compression,
            compressed_len,
            uncompressed_len,
            version,
            data,
        })
    }

    pub fn crc(&self) -> u32 {
        getcrc(self.data, 0, self.data.len()) as u32
    }
}

pub fn decompress(data: &[u8]) -> Result<Cow<'_, [u8]>> {
    let container = Container::parse(data)?;
    if container.compression == CompressionType::None {
        return Ok(Cow::Borrowed(&container.data[5..]));
    }
    let expected_len = container.uncompressed_len as usize;
    if expected_len > 64 * 1024 * 1024 {
        return Err(CacheError::Decompression(format!(
            "Decompressed length {expected_len} bytes is unreasonably large (corrupt XTEA?)"
        )));
    }
    let payload = &container.data[9..];
    let output = match container.compression {
        CompressionType::None => unreachable!(),
        CompressionType::Bzip2 => bz2_decompress(payload, expected_len, true, 0),
        CompressionType::Gzip => gz_decompress(payload, expected_len),
        CompressionType::Lzma => {
            let mut output = Vec::with_capacity(expected_len);
            lzma_rs::lzma_decompress(&mut Cursor::new(payload), &mut output)
                .map_err(|e| CacheError::Decompression(format!("LZMA error: {e}")))?;
            output
        }
    };
    if output.len() != expected_len {
        return Err(CacheError::Decompression(format!(
            "Length mismatch: expected {expected_len}, got {}",
            output.len()
        )));
    }
    Ok(Cow::Owned(output))
}

pub(super) fn decompress_owned(mut data: Vec<u8>) -> Result<Vec<u8>> {
    if data.first() == Some(&(CompressionType::None as u8)) {
        let len = Container::parse(&data)?.data.len();
        data.truncate(len);
        data.drain(..5);
        return Ok(data);
    }
    decompress(&data).map(Cow::into_owned)
}

pub fn compress(data: &[u8], compression: CompressionType) -> Result<Vec<u8>> {
    let compressed: Cow<'_, [u8]> = match compression {
        CompressionType::None => data.into(),
        CompressionType::Bzip2 => bz2_compress(data, true).into(),
        CompressionType::Gzip => gz_compress_with(data, 6, 0).into(),
        CompressionType::Lzma => {
            let mut output = Vec::new();
            lzma_rs::lzma_compress(&mut Cursor::new(data), &mut output)
                .map_err(|e| CacheError::Decompression(format!("LZMA compress error: {e}")))?;
            output.into()
        }
    };
    let mut out = Packet::new(9 + compressed.len());
    out.p1(compression as u8);
    out.p4(compressed.len() as i32);
    if compression != CompressionType::None {
        out.p4(data.len() as i32);
    }
    out.pdata(&compressed, 0, compressed.len());
    out.data.truncate(out.pos);
    Ok(out.data)
}

pub fn decompress_xtea(raw: &[u8], keys: &[i32; 4]) -> Result<Vec<u8>> {
    if *keys == [0; 4] {
        return decompress(raw).map(Cow::into_owned);
    }
    let mut data = Container::parse(raw)?.data.to_vec();
    let end = 5 + ((data.len() - 5) & !7);
    Xtea::decrypt(&mut data[5..end], &keys.map(|k| k as u32))
        .map_err(|_| CacheError::XteaDecryption)?;
    decompress_owned(data)
}

pub fn compress_xtea(
    data: &[u8],
    compression: CompressionType,
    version: u16,
    keys: &[i32; 4],
) -> Result<Vec<u8>> {
    let mut out = compress(data, compression)?;
    if *keys != [0; 4] {
        let end = 5 + ((out.len() - 5) & !7);
        Xtea::encrypt(&mut out[5..end], &keys.map(|k| k as u32))
            .map_err(|_| CacheError::XteaDecryption)?;
    }
    let pos = out.len();
    out.resize(pos + 2, 0);
    Packet::from(&mut out[pos..]).p2(version);
    Ok(out)
}

/// Compress data using the codec that produces the smallest output.
///
/// Algorithm (reverse-engineered from Jagex's rev 647 cache):
/// 1. Compress with both Gzip and Bzip2
/// 2. Pick whichever compressed payload is smaller (tiebreak: Bzip2 wins)
/// 3. If `allow_uncompressed` AND the compressed payload ≥ raw data size,
///    fall back to None (uncompressed)
///
/// `allow_uncompressed` is a per-archive property — some archives (maps,
/// jingles, configs) always compress even when it increases size, while
/// others (animations, vorbis, synth) fall back to None for small or
/// incompressible data.
pub fn compress_best(
    data: &[u8],
    allow_uncompressed: bool,
    allow_bzip2: bool,
    forced_codec: Option<CompressionType>,
) -> Result<Vec<u8>> {
    if let Some(codec) = forced_codec {
        let compressed = compress(data, codec)?;
        let payload = if codec == CompressionType::None {
            compressed.len() - 5
        } else {
            compressed.len() - 9
        };
        if allow_uncompressed && payload >= data.len() {
            return compress(data, CompressionType::None);
        }
        return Ok(compressed);
    }

    let gzip = compress(data, CompressionType::Gzip)?;

    let (best_compressed, best_payload) = if allow_bzip2 {
        let bzip2 = compress(data, CompressionType::Bzip2)?;
        let gzip_payload = gzip.len() - 9;
        let bzip2_payload = bzip2.len() - 9;
        if bzip2_payload <= gzip_payload {
            (bzip2, bzip2_payload)
        } else {
            (gzip, gzip_payload)
        }
    } else {
        let gzip_payload = gzip.len() - 9;
        (gzip, gzip_payload)
    };

    if allow_uncompressed && best_payload >= data.len() {
        return compress(data, CompressionType::None);
    }

    Ok(best_compressed)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_compression_type_from_u8() {
        assert_eq!(
            CompressionType::try_from(0u8).unwrap(),
            CompressionType::None
        );
        assert_eq!(
            CompressionType::try_from(1u8).unwrap(),
            CompressionType::Bzip2
        );
        assert_eq!(
            CompressionType::try_from(2u8).unwrap(),
            CompressionType::Gzip
        );
        assert_eq!(
            CompressionType::try_from(3u8).unwrap(),
            CompressionType::Lzma
        );
        assert!(CompressionType::try_from(99u8).is_err());
    }

    #[test]
    fn container_bounds_and_version() {
        let raw = [0, 0, 0, 0, 3, 1, 2, 3, 0x12, 0x34];
        let c = Container::parse(&raw).unwrap();
        assert_eq!(c.data, &raw[..8]);
        assert_eq!(c.version, Some(0x1234));
        assert_eq!(&decompress(&raw).unwrap()[..], &[1, 2, 3]);
        assert_eq!(c.crc(), Container::parse(&raw[..8]).unwrap().crc());
        let decoded = decompress(&raw).unwrap();
        assert_eq!(&*decoded, &[1, 2, 3]);
        assert_eq!(decoded.as_ptr(), raw[5..].as_ptr());
        let owned = raw.to_vec();
        let ptr = owned.as_ptr();
        let decoded = decompress_owned(owned).unwrap();
        assert_eq!(decoded, [1, 2, 3]);
        assert_eq!(decoded.as_ptr(), ptr);
        assert_eq!(Container::parse(&raw[..8]).unwrap().version, None);
        for len in 0..8 {
            assert!(Container::parse(&raw[..len]).is_err());
        }
        for len in 5..9 {
            assert!(Container::parse(&[2, 0, 0, 0, 0, 0, 0, 0, 0][..len]).is_err());
        }
    }

    #[test]
    fn encrypted_containers_accept_disk_and_network_bytes() {
        let keys = [-1, 2, -3, 4];
        for codec in [
            CompressionType::None,
            CompressionType::Bzip2,
            CompressionType::Gzip,
        ] {
            for len in [0, 1, 6, 7, 8, 9, 15, 16, 17, 511] {
                let data: Vec<u8> = (0..len).map(|i| i as u8).collect();
                let raw = compress_xtea(&data, codec, 0x1234, &keys).unwrap();
                let c = Container::parse(&raw).unwrap();
                assert_eq!(c.version, Some(0x1234));
                for bytes in [&raw[..], c.data] {
                    assert_eq!(&decompress_xtea(bytes, &keys).unwrap()[..], data);
                }
            }
        }
    }

    #[test]
    fn test_compress_decompress_none() {
        let original = b"Hello, RuneScape cache!";
        let compressed = compress(original, CompressionType::None).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..], original);
    }

    #[test]
    fn test_compress_decompress_gzip() {
        let original = b"Hello, RuneScape cache! This is gzip compressed data.";
        let compressed = compress(original, CompressionType::Gzip).unwrap();
        assert_eq!(compressed[0], CompressionType::Gzip as u8);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..], original);
    }

    #[test]
    fn test_compress_decompress_bzip2() {
        let original = b"Hello, RuneScape cache! This is bzip2 compressed data.";
        let compressed = compress(original, CompressionType::Bzip2).unwrap();
        assert_eq!(compressed[0], CompressionType::Bzip2 as u8);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..], original);
    }

    #[test]
    fn test_compress_decompress_lzma() {
        let original = b"Hello, RuneScape cache! This is LZMA compressed data.";
        let compressed = compress(original, CompressionType::Lzma).unwrap();
        assert_eq!(compressed[0], CompressionType::Lzma as u8);
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..], original);
    }

    #[test]
    fn test_compress_decompress_large() {
        // 64KB of repeated data (compresses well)
        let original: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        for compression in [
            CompressionType::None,
            CompressionType::Gzip,
            CompressionType::Bzip2,
            CompressionType::Lzma,
        ] {
            let compressed = compress(&original, compression).unwrap();
            let decompressed = decompress(&compressed).unwrap();
            assert_eq!(
                &decompressed[..],
                &original[..],
                "Round-trip failed for {:?}",
                compression
            );
        }
    }

    /// Test that compressing real cache data from archive 2 reference table
    /// produces a valid container that decompresses back.
    #[test]
    fn test_compress_real_reference_table() {
        let cache_dir = std::path::Path::new("../cache");
        if !cache_dir.exists() {
            eprintln!("Skipping (no cache)");
            return;
        }
        let mut store = crate::js5::Js5Store::open(cache_dir).unwrap();
        let raw = store.read_group_raw_decompressed(255, 2).unwrap().unwrap();

        // Re-compress with gzip
        let compressed = compress(&raw, CompressionType::Gzip).unwrap();
        let decompressed = decompress(&compressed).unwrap();
        assert_eq!(&decompressed[..], &raw[..]);
    }
}
