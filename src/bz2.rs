use std::os::raw::{c_char, c_int, c_uint};

unsafe extern "C" {
    fn BZ2_bzBuffToBuffCompress(
        dest: *mut c_char,
        dest_len: *mut c_uint,
        source: *mut c_char,
        source_len: c_uint,
        block_size_100k: c_int,
        verbosity: c_int,
        work_factor: c_int,
    ) -> c_int;

    fn BZ2_bzBuffToBuffDecompress(
        dest: *mut c_char,
        dest_len: *mut c_uint,
        source: *mut c_char,
        source_len: c_uint,
        small: c_int,
        verbosity: c_int,
    ) -> c_int;
}

const BZ2_HEADER: [u8; 4] = *b"BZh1";

#[allow(dead_code)]
unsafe extern "C" {
    fn bz_internal_error(errcode: c_int);
}

#[inline]
pub fn bz2_decompress(
    bytes: &[u8],
    decompress_length: usize,
    prepend_header: bool,
    offset: usize,
) -> Vec<u8> {
    unsafe {
        let mut dest = Vec::with_capacity(decompress_length);
        let mut dest_len = decompress_length as c_uint;

        if prepend_header {
            let src_len = 4 + bytes.len() - offset;
            let mut src: Vec<u8> = Vec::with_capacity(src_len);
            src.as_mut_ptr()
                .copy_from_nonoverlapping(BZ2_HEADER.as_ptr(), 4);
            src.as_mut_ptr()
                .add(4)
                .copy_from_nonoverlapping(bytes.as_ptr().add(offset), bytes.len() - offset);
            src.set_len(src_len);

            BZ2_bzBuffToBuffDecompress(
                dest.as_mut_ptr() as *mut c_char,
                &mut dest_len,
                src.as_ptr() as *mut c_char,
                src_len as c_uint,
                0,
                0,
            );
        } else {
            BZ2_bzBuffToBuffDecompress(
                dest.as_mut_ptr() as *mut c_char,
                &mut dest_len,
                bytes.as_ptr() as *mut c_char,
                bytes.len() as c_uint,
                0,
                0,
            );
        }

        dest.set_len(dest_len as usize);
        dest
    }
}

#[inline]
pub fn bz2_compress(bytes: &[u8], remove_header: bool) -> Vec<u8> {
    unsafe {
        let max_len = bytes.len() + (bytes.len() / 100) + 608;
        let mut dest = Vec::with_capacity(max_len);
        let mut dest_len = max_len as c_uint;

        BZ2_bzBuffToBuffCompress(
            dest.as_mut_ptr() as *mut c_char,
            &mut dest_len,
            bytes.as_ptr() as *mut c_char,
            bytes.len() as c_uint,
            1,
            0,
            0,
        );

        let len = dest_len as usize;
        if remove_header {
            let trimmed_len = len - 4;
            let ptr: *mut u8 = dest.as_mut_ptr();
            std::ptr::copy(ptr.add(4), ptr, trimmed_len);
            dest.set_len(trimmed_len);
        } else {
            dest.set_len(len);
        }
        dest
    }
}

#[inline]
pub fn bz2_compress_with_size(raw: &[u8]) -> Vec<u8> {
    let compressed = bz2_compress(raw, true);
    let size = raw.len() as u32;
    let mut result = Vec::with_capacity(4 + compressed.len());
    unsafe {
        let ptr = result.as_mut_ptr();
        *ptr = (size >> 24) as u8;
        *ptr.add(1) = (size >> 16) as u8;
        *ptr.add(2) = (size >> 8) as u8;
        *ptr.add(3) = size as u8;
        std::ptr::copy_nonoverlapping(compressed.as_ptr(), ptr.add(4), compressed.len());
        result.set_len(4 + compressed.len());
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip() {
        let original = b"Hello, bzip2 world! This is a test of compression and decompression.";
        let compressed = bz2_compress(original, false);
        let decompressed = bz2_decompress(&compressed, original.len(), false, 0);
        assert_eq!(&decompressed, original);
    }

    #[test]
    fn roundtrip_with_header_strip() {
        let original = b"Hello world!";
        let compressed = bz2_compress(original, true);
        let decompressed = bz2_decompress(&compressed, original.len(), true, 0);
        assert_eq!(&decompressed, original);
    }
}
