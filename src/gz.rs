use crate::crc::getcrc;

pub fn gz_compress(data: &[u8]) -> Vec<u8> {
    gz_compress_with(data, 6, 0)
}

pub fn gz_compress_with(data: &[u8], level: u8, os: u8) -> Vec<u8> {
    let deflated = miniz_oxide::deflate::compress_to_vec(data, level);
    let crc = getcrc(data, 0, data.len()) as u32;
    let size = data.len() as u32;

    let mut out = Vec::with_capacity(10 + deflated.len() + 8);

    // gzip header
    out.extend_from_slice(&[
        0x1f, 0x8b, // magic
        0x08, // method = deflate
        0x00, // flags
        0, 0, 0, 0, // mtime = 0
        0x00, // extra flags
        os,
    ]);

    out.extend_from_slice(&deflated);

    // gzip footer
    out.extend_from_slice(&crc.to_le_bytes());
    out.extend_from_slice(&size.to_le_bytes());

    out
}

pub fn gz_decompress(data: &[u8], expected_len: usize) -> Vec<u8> {
    if data.len() < 18 {
        return Vec::new();
    }

    let flags = data[3];
    let mut pos: usize = 10;

    // FEXTRA
    if flags & 0x04 != 0 {
        if pos + 2 > data.len() {
            return Vec::new();
        }
        let xlen = u16::from_le_bytes([data[pos], data[pos + 1]]) as usize;
        pos += 2 + xlen;
    }

    // FNAME
    if flags & 0x08 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }

    // FCOMMENT
    if flags & 0x10 != 0 {
        while pos < data.len() && data[pos] != 0 {
            pos += 1;
        }
        pos += 1;
    }

    // FHCRC
    if flags & 0x02 != 0 {
        pos += 2;
    }

    let deflated = &data[pos..data.len().saturating_sub(8)];
    miniz_oxide::inflate::decompress_to_vec_with_limit(deflated, expected_len)
        .unwrap_or_default()
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let original = b"Hello, gzip world! This is a test of compression and decompression.";
        let compressed = gz_compress(original);
        assert_eq!(compressed[0], 0x1f);
        assert_eq!(compressed[1], 0x8b);
        let decompressed = gz_decompress(&compressed, original.len());
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn roundtrip_large() {
        let original: Vec<u8> = (0..65536).map(|i| (i % 256) as u8).collect();
        let compressed = gz_compress(&original);
        let decompressed = gz_decompress(&compressed, original.len());
        assert_eq!(decompressed, original);
    }

    #[test]
    fn custom_os_byte() {
        let original = b"test data";
        let compressed = gz_compress_with(original, 6, 0xff);
        assert_eq!(compressed[9], 0xff);
        let decompressed = gz_decompress(&compressed, original.len());
        assert_eq!(&decompressed, original);
    }
}
