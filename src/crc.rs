unsafe extern "C" {
    fn crc32(src: *const u8, offset: usize, length: usize) -> i32;
}

pub fn getcrc(src: &[u8], offset: usize, length: usize) -> i32 {
    unsafe { crc32(src.as_ptr(), offset, length) }
}
