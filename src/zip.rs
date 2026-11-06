use crate::Packet;
use crate::crc::getcrc;

// https://github.com/101arrowz/fflate/blob/master/src/index.ts
pub fn fflate<'a>(entries: impl IntoIterator<Item = (String, &'a [u8])>) -> Vec<u8> {
    let mut out = Vec::new();
    let mut central = Vec::new();
    let mut count = 0u16;
    for (name, data) in entries {
        count += 1;
        let offset = out.len() as u32;
        let crc = getcrc(data, 0, data.len());
        let name = name.as_bytes();
        let size = data.len() as u32;
        // local file header
        let mut header = Packet::from([0; 30]);
        header.p4_alt1(0x0403_4b50); // signature
        header.p2_alt1(20); // version needed
        header.p2_alt1(0); // flags
        header.p2_alt1(0); // method: stored
        header.p4_alt1(0); // mod time + date
        header.p4_alt1(crc);
        header.p4_alt1(size as i32); // compressed size
        header.p4_alt1(size as i32); // uncompressed size
        header.p2_alt1(name.len() as u16);
        header.p2_alt1(0); // extra len
        out.extend_from_slice(&header.data);
        out.extend_from_slice(name);
        out.extend_from_slice(data);
        // central directory header
        let mut header = Packet::from([0; 46]);
        header.p4_alt1(0x02014b50); // signature
        header.p2_alt1(20); // version made by
        header.p2_alt1(20); // version needed
        header.p2_alt1(0); // flags
        header.p2_alt1(0); // method
        header.p4_alt1(0); // mod time + date
        header.p4_alt1(crc);
        header.p4_alt1(size as i32);
        header.p4_alt1(size as i32);
        header.p2_alt1(name.len() as u16);
        header.p2_alt1(0); // extra len
        header.p2_alt1(0); // comment len
        header.p2_alt1(0); // disk number
        header.p2_alt1(0); // internal attrs
        header.p4_alt1(0); // external attrs
        header.p4_alt1(offset as i32); // local header offset
        central.extend_from_slice(&header.data);
        central.extend_from_slice(name);
    }
    let cd_offset = out.len() as u32;
    let cd_size = central.len() as u32;
    out.extend_from_slice(&central);
    // end of central directory record
    let mut header = Packet::from([0; 22]);
    header.p4_alt1(0x06054b50); // signature
    header.p2_alt1(0); // disk number
    header.p2_alt1(0); // cd start disk
    header.p2_alt1(count); // entries this disk
    header.p2_alt1(count); // total entries
    header.p4_alt1(cd_size as i32);
    header.p4_alt1(cd_offset as i32);
    header.p2_alt1(0); // comment len
    out.extend_from_slice(&header.data);
    out
}
