const TABLE: [char; 32] = [
    '€', '\0', '‚', 'ƒ', '„', '…', '†', '‡', 'ˆ', '‰', 'Š', '‹', 'Œ', '\0', 'Ž', '\0', '\0', '‘',
    '’', '“', '”', '•', '–', '—', '˜', '™', 'š', '›', 'œ', '\0', 'ž', 'Ÿ',
];

#[inline(always)]
pub const fn encode(cp: u32) -> u8 {
    match cp {
        0x01..=0x7F | 0xA0..=0xFF => cp as u8,
        0x20AC => 128, // €
        0x201A => 130, // ‚
        0x0192 => 131, // ƒ
        0x201E => 132, // „
        0x2026 => 133, // …
        0x2020 => 134, // †
        0x2021 => 135, // ‡
        0x02C6 => 136, // ˆ
        0x2030 => 137, // ‰
        0x0160 => 138, // Š
        0x2039 => 139, // ‹
        0x0152 => 140, // Œ
        0x017D => 142, // Ž
        0x2018 => 145, // '
        0x2019 => 146, // '
        0x201C => 147, // "
        0x201D => 148, // "
        0x2022 => 149, // •
        0x2013 => 150, // –
        0x2014 => 151, // —
        0x02DC => 152, // ˜
        0x2122 => 153, // ™
        0x0161 => 154, // š
        0x203A => 155, // ›
        0x0153 => 156, // œ
        0x017E => 158, // ž
        0x0178 => 159, // Ÿ
        _ => 0,
    }
}

#[inline(always)]
pub fn decode(src: &[u8], offset: usize, len: usize) -> String {
    let slice = unsafe { core::slice::from_raw_parts(src.as_ptr().add(offset), len) };
    if slice.iter().all(|&b| b > 0 && b < 128) {
        return unsafe { String::from_utf8_unchecked(slice.to_vec()) };
    }
    let mut s = String::with_capacity(len);
    let ptr = slice.as_ptr();
    let mut i = 0;
    while i < len {
        let b = unsafe { *ptr.add(i) } as u32;
        if b != 0 {
            let c = if (128..160).contains(&b) {
                let mapped = TABLE[(b - 128) as usize];
                if mapped == '\0' { '?' } else { mapped }
            } else {
                unsafe { char::from_u32_unchecked(b) }
            };
            s.push(c);
        }
        i += 1;
    }
    s
}
