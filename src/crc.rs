use crc32fast::hash;

pub fn getcrc(src: &[u8], offset: usize, length: usize) -> i32 {
    hash(&src[offset..length]) as i32
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ieee_crc_uses_an_exclusive_end_offset() {
        assert_eq!(getcrc(b"", 0, 0), 0);
        assert_eq!(getcrc(b"123456789", 0, 9) as u32, 0xcbf43926);
        assert_eq!(getcrc(b"__123456789__", 2, 11) as u32, 0xcbf43926);
        assert_eq!(getcrc(b"__123456789__", 2, 2), 0);
    }
}
