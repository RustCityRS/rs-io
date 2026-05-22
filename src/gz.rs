use crate::crc::getcrc;
use std::os::raw::{c_int, c_uint, c_ulong};

const Z_OK: c_int = 0;
const Z_STREAM_END: c_int = 1;
const Z_FINISH: c_int = 4;
const Z_DEFLATED: c_int = 8;
const Z_DEFAULT_STRATEGY: c_int = 0;
const MAX_WBITS: c_int = 15;
const DEF_MEM_LEVEL: c_int = 8;

#[repr(C)]
struct ZStream {
    next_in: *const u8,
    avail_in: c_uint,
    total_in: c_ulong,
    next_out: *mut u8,
    avail_out: c_uint,
    total_out: c_ulong,
    msg: *const u8,
    state: *mut u8,
    zalloc: usize,
    zfree: usize,
    opaque: usize,
    data_type: c_int,
    adler: c_ulong,
    reserved: c_ulong,
}

unsafe extern "C" {
    fn deflateInit2_(
        strm: *mut ZStream,
        level: c_int,
        method: c_int,
        window_bits: c_int,
        mem_level: c_int,
        strategy: c_int,
        version: *const u8,
        stream_size: c_int,
    ) -> c_int;
    fn deflate(strm: *mut ZStream, flush: c_int) -> c_int;
    fn deflateEnd(strm: *mut ZStream) -> c_int;
    fn deflateBound(strm: *mut ZStream, source_len: c_ulong) -> c_ulong;

    fn inflateInit2_(
        strm: *mut ZStream,
        window_bits: c_int,
        version: *const u8,
        stream_size: c_int,
    ) -> c_int;
    fn inflate(strm: *mut ZStream, flush: c_int) -> c_int;
    fn inflateEnd(strm: *mut ZStream) -> c_int;
}

const ZLIB_VERSION: &[u8] = b"1.2.3\0";

fn new_zstream() -> ZStream {
    ZStream {
        next_in: std::ptr::null(),
        avail_in: 0,
        total_in: 0,
        next_out: std::ptr::null_mut(),
        avail_out: 0,
        total_out: 0,
        msg: std::ptr::null(),
        state: std::ptr::null_mut(),
        zalloc: 0,
        zfree: 0,
        opaque: 0,
        data_type: 0,
        adler: 0,
        reserved: 0,
    }
}

fn raw_deflate(data: &[u8], level: c_int) -> Vec<u8> {
    unsafe {
        let mut strm = new_zstream();
        let ret = deflateInit2_(
            &mut strm,
            level,
            Z_DEFLATED,
            -MAX_WBITS,
            DEF_MEM_LEVEL,
            Z_DEFAULT_STRATEGY,
            ZLIB_VERSION.as_ptr(),
            size_of::<ZStream>() as c_int,
        );
        assert_eq!(ret, Z_OK);

        let bound = deflateBound(&mut strm, data.len() as c_ulong) as usize;
        let mut out = Vec::with_capacity(bound);

        strm.next_in = data.as_ptr();
        strm.avail_in = data.len() as c_uint;
        strm.next_out = out.as_mut_ptr();
        strm.avail_out = bound as c_uint;

        let ret = deflate(&mut strm, Z_FINISH);
        assert_eq!(ret, Z_STREAM_END);

        out.set_len(strm.total_out as usize);
        deflateEnd(&mut strm);
        out
    }
}

fn raw_inflate(data: &[u8], expected_len: usize) -> Vec<u8> {
    unsafe {
        let mut strm = new_zstream();
        let ret = inflateInit2_(
            &mut strm,
            -MAX_WBITS,
            ZLIB_VERSION.as_ptr(),
            size_of::<ZStream>() as c_int,
        );
        assert_eq!(ret, Z_OK);

        let mut out = Vec::with_capacity(expected_len);

        strm.next_in = data.as_ptr();
        strm.avail_in = data.len() as c_uint;
        strm.next_out = out.as_mut_ptr();
        strm.avail_out = expected_len as c_uint;

        let ret = inflate(&mut strm, Z_FINISH);
        if ret != Z_STREAM_END && ret != Z_OK {
            inflateEnd(&mut strm);
            return Vec::new();
        }

        out.set_len(strm.total_out as usize);
        inflateEnd(&mut strm);
        out
    }
}

pub fn gz_compress(data: &[u8]) -> Vec<u8> {
    gz_compress_with(data, 6, 0)
}

pub fn gz_compress_with(data: &[u8], level: u8, os: u8) -> Vec<u8> {
    let deflated = raw_deflate(data, level as c_int);
    let crc = getcrc(data, 0, data.len()) as u32;
    let size = data.len() as u32;

    let mut out = Vec::with_capacity(10 + deflated.len() + 8);

    // gzip header
    out.extend_from_slice(&[
        0x1f, 0x8b, // magic
        0x08, // method = deflate
        0x00, // flags
        0, 0, 0, 0,    // mtime = 0
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
    if data.len() < 18 || data[0] != 0x1f || data[1] != 0x8b {
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

    let end = data.len().saturating_sub(8);
    if pos >= end {
        return Vec::new();
    }

    let deflated = &data[pos..end];
    raw_inflate(deflated, expected_len)
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
