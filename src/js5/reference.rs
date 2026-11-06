//! Reference table parsing
//!
//! Reference tables (stored in archive 255) contain metadata about groups in other archives.

use super::Result;
use crate::Packet;
use crate::crc::getcrc;
use rs_crypto::rsa::RsaKey;
use rs_crypto::whirlpool;
use tracing::trace;

/// A reference table containing metadata about an archive
#[derive(Debug, Clone)]
pub struct ReferenceTable {
    pub archive_id: u8,
    pub format: u8,
    pub version: u32,
    pub named: bool,
    pub whirlpooled: bool,
    pub groups: Vec<GroupInfo>,
}

/// Metadata about a group
#[derive(Debug, Clone)]
pub struct GroupInfo {
    pub id: u32,
    pub name_hash: i32,
    pub crc: u32,
    pub whirlpool: Option<[u8; 64]>,
    pub version: u32,
    pub size: usize,
    pub file_count: u32,
    pub files: Vec<FileInfo>,
}

/// Metadata about a file within a group
#[derive(Debug, Clone)]
pub struct FileInfo {
    pub id: u32,
    pub name_hash: Option<i32>,
}

/// Encodes a Whirlpool-signed master-index container from reference tables and versions in archive order.
pub fn encode_master_index<'a>(
    archives: impl ExactSizeIterator<Item = (&'a [u8], u32)>,
    private_key: &RsaKey,
) -> Vec<u8> {
    let archives: Vec<_> = archives.collect();
    let count = u8::try_from(archives.len()).expect("too many JS5 archives");
    let payload_len = 1 + count as usize * 72;
    let mut out = Packet::new(5 + payload_len + private_key.n.bits().div_ceil(8) as usize + 1);
    out.p1(0);
    out.p4(0);
    out.p1(count);
    for (data, version) in archives {
        out.p4(getcrc(data, 0, data.len()));
        out.p4(version as i32);
        out.pdata(&whirlpool(data), 0, 64);
    }
    let mut signed = [10; 65];
    signed[1..].copy_from_slice(&whirlpool(&out.data[5..out.pos]));
    let signature = private_key.decrypt(&signed);
    if signature.first().is_some_and(|b| b & 0x80 != 0) {
        out.p1(0);
    }
    out.pdata(&signature, 0, signature.len());
    let len = out.pos;
    out.pos = 1;
    out.p4((len - 5) as i32);
    out.data.truncate(len);
    out.data
}

/// Parse a reference table from raw data.
///
/// Reference table format (all versions):
///   u8:  format version (5, 6, or 7)
///   u8:  flags  (0x01=named, 0x02=whirlpooled, 0x04=sizes)
///   u16: group count (format < 7)  OR  big_smart (format >= 7)
///   [group IDs — delta-encoded u16s (format < 7) or big_smarts (format >= 7)]
///   [name hashes — i32 per group, present when named flag set]
///   [CRC values — u32 per group]
///   [whirlpool hashes — 64 bytes per group, present when whirlpooled flag set]
///   [versions — u32 per group]
///   [file counts — u16 per group (format < 7) or big_smart (format >= 7)]
///   [file IDs per group — delta-encoded u16s or big_smarts]
///   [file name hashes per group — i32, present when named flag set]
pub fn parse_reference_table(data: &[u8]) -> Result<ReferenceTable> {
    let mut pkt = Packet::from(data);

    let format = pkt.g1();

    // For format >= 6, a 4-byte version field precedes the flags byte
    let version = if format >= 6 { pkt.g4s() as u32 } else { 0 };

    // flags byte: 0x01=named, 0x02=whirlpooled, 0x04=sizes
    let flags = pkt.g1();
    let named = (flags & 0x01) != 0;
    let whirlpooled = (flags & 0x02) != 0;

    let group_count = if format >= 7 {
        pkt.gsmart2or4s() as u32
    } else {
        pkt.g2() as u32
    };

    trace!(
        "Parsing reference table: format={}, flags={:#04x}, groups={}",
        format, flags, group_count
    );

    // Group IDs (delta-encoded)
    let mut group_ids = Vec::with_capacity(group_count as usize);
    let mut last_id = 0u32;
    for _ in 0..group_count {
        let delta = if format >= 7 {
            pkt.gsmart2or4s() as u32
        } else {
            pkt.g2() as u32
        };
        last_id += delta;
        group_ids.push(last_id);
    }

    // Name hashes (if named flag)
    let group_names: Vec<i32> = if named {
        (0..group_count).map(|_| pkt.g4s()).collect()
    } else {
        vec![-1; group_count as usize]
    };

    // CRC values
    let group_crcs: Vec<u32> = (0..group_count).map(|_| pkt.g4s() as u32).collect();

    // Whirlpool hashes (if whirlpooled flag)
    let mut group_whirlpools: Vec<Option<[u8; 64]>> = vec![None; group_count as usize];
    if whirlpooled {
        for wp in group_whirlpools.iter_mut() {
            let mut hash = [0u8; 64];
            pkt.gdata(&mut hash, 0, 64);
            *wp = Some(hash);
        }
    }

    // Versions
    let group_versions: Vec<u32> = (0..group_count).map(|_| pkt.g4s() as u32).collect();

    // File counts per group
    let group_file_counts: Vec<u32> = (0..group_count)
        .map(|_| {
            if format >= 7 {
                pkt.gsmart2or4s() as u32
            } else {
                pkt.g2() as u32
            }
        })
        .collect();

    // Build group structs
    let mut groups: Vec<GroupInfo> = (0..group_count as usize)
        .map(|i| GroupInfo {
            id: group_ids[i],
            name_hash: group_names[i],
            crc: group_crcs[i],
            whirlpool: group_whirlpools[i],
            version: group_versions[i],
            size: 0,
            file_count: group_file_counts[i],
            files: Vec::with_capacity(group_file_counts[i] as usize),
        })
        .collect();

    // File IDs per group (delta-encoded)
    for group in &mut groups {
        let fc = group.file_count as usize;
        let mut file_ids = Vec::with_capacity(fc);
        let mut last_file_id = 0u32;
        for _ in 0..fc {
            let delta = if format >= 7 {
                pkt.gsmart2or4s() as u32
            } else {
                pkt.g2() as u32
            };
            last_file_id += delta;
            file_ids.push(last_file_id);
        }

        // File name hashes (if named flag)
        if named {
            for fid in file_ids {
                let name_hash = pkt.g4s();
                group.files.push(FileInfo {
                    id: fid,
                    name_hash: Some(name_hash),
                });
            }
        } else {
            for fid in file_ids {
                group.files.push(FileInfo {
                    id: fid,
                    name_hash: None,
                });
            }
        }
    }

    Ok(ReferenceTable {
        archive_id: 0, // Set by caller
        format,
        version,
        named,
        whirlpooled,
        groups,
    })
}

/// Encode a reference table back to binary format.
pub fn encode_reference_table(table: &ReferenceTable) -> Vec<u8> {
    let capacity = 10
        + table
            .groups
            .iter()
            .map(|group| 84 + 8 * group.files.len())
            .sum::<usize>();
    let mut out = Packet::new(capacity);

    // Format version
    out.p1(table.format);

    // Version field (format >= 6)
    if table.format >= 6 {
        out.p4(table.version as i32);
    }

    // Flags
    let mut flags: u8 = 0;
    if table.named {
        flags |= 0x01;
    }
    if table.whirlpooled {
        flags |= 0x02;
    }
    out.p1(flags);

    // Group count
    let gc = table.groups.len() as u32;
    if table.format >= 7 {
        out.psmart2or4null(gc as i32);
    } else {
        out.p2(gc as u16);
    }

    // Group IDs (delta-encoded)
    let mut last_id = 0u32;
    for group in &table.groups {
        let delta = group.id - last_id;
        if table.format >= 7 {
            out.psmart2or4null(delta as i32);
        } else {
            out.p2(delta as u16);
        }
        last_id = group.id;
    }

    // Name hashes
    if table.named {
        for group in &table.groups {
            out.p4(group.name_hash);
        }
    }

    // CRC values
    for group in &table.groups {
        out.p4(group.crc as i32);
    }

    // Whirlpool hashes
    if table.whirlpooled {
        for group in &table.groups {
            if let Some(wp) = &group.whirlpool {
                out.pdata(wp, 0, 64);
            } else {
                out.pdata(&[0; 64], 0, 64);
            }
        }
    }

    // Versions
    for group in &table.groups {
        out.p4(group.version as i32);
    }

    // File counts
    for group in &table.groups {
        if table.format >= 7 {
            out.psmart2or4null(group.file_count as i32);
        } else {
            out.p2(group.file_count as u16);
        }
    }

    // File IDs per group (delta-encoded)
    for group in &table.groups {
        let mut last_file_id = 0u32;
        for file in &group.files {
            let delta = file.id - last_file_id;
            if table.format >= 7 {
                out.psmart2or4null(delta as i32);
            } else {
                out.p2(delta as u16);
            }
            last_file_id = file.id;
        }

        // File name hashes (0 = no name, matches Jagex default)
        if table.named {
            for file in &group.files {
                let hash = file.name_hash.unwrap_or(0);
                out.p4(hash);
            }
        }
    }

    out.data.truncate(out.pos);
    out.data
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn format_seven_uses_two_or_four_byte_smarts() {
        let table = ReferenceTable {
            archive_id: 2,
            format: 7,
            version: 1,
            named: false,
            whirlpooled: false,
            groups: vec![GroupInfo {
                id: 32767,
                name_hash: -1,
                crc: 0x12345678,
                whirlpool: None,
                version: 2,
                size: 0,
                file_count: 2,
                files: vec![
                    FileInfo {
                        id: 0,
                        name_hash: None,
                    },
                    FileInfo {
                        id: 65536,
                        name_hash: None,
                    },
                ],
            }],
        };
        let bytes = encode_reference_table(&table);
        assert_eq!(
            bytes,
            [
                7, 0, 0, 0, 1, 0, 0, 1, 0x80, 0, 0x7f, 0xff, 0x12, 0x34, 0x56, 0x78, 0, 0, 0, 2, 0,
                2, 0, 0, 0x80, 1, 0, 0
            ]
        );
        let decoded = parse_reference_table(&bytes).unwrap();
        assert_eq!(decoded.groups[0].id, 32767);
        assert_eq!(decoded.groups[0].files[1].id, 65536);
        assert_eq!(
            encode_reference_table(&decoded),
            encode_reference_table(&table)
        );
    }
    use crate::js5::Js5Store;
    use rs_crypto::rsa::parse_rsa_key_from_pem;
    use std::fs;
    use std::path::Path;

    #[test]
    fn test_packet_reads() {
        let mut pkt = Packet::from(vec![0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07]);
        assert_eq!(pkt.g1(), 0x01);
        assert_eq!(pkt.g2(), 0x0203);
        assert_eq!(pkt.g4s() as u32, 0x04050607);
    }

    /// Round-trip test: decode reference table from real cache → encode → compare bytes.
    /// Verifies that our encoder produces byte-identical output to the original cache data.
    #[test]
    fn test_reference_table_roundtrip_archive2() {
        let cache_dir = Path::new("../cache");
        if !cache_dir.exists() {
            eprintln!("Skipping reference table round-trip test (no cache directory)");
            return;
        }

        let mut store = Js5Store::open(cache_dir).expect("Failed to open cache");

        // Archive 2 = CONFIG — the one we'll be writing to
        let raw_decompressed = store
            .read_group_raw_decompressed(255, 2)
            .expect("Failed to read archive 2 reference table")
            .expect("Archive 2 reference table not found");

        // Parse
        let table = parse_reference_table(&raw_decompressed)
            .expect("Failed to parse archive 2 reference table");

        eprintln!(
            "Archive 2: format={} named={} whirlpooled={} groups={}",
            table.format,
            table.named,
            table.whirlpooled,
            table.groups.len()
        );

        // Encode back
        let re_encoded = encode_reference_table(&table);

        // Diagnostic: find first mismatch
        if raw_decompressed.len() != re_encoded.len() {
            eprintln!(
                "Length mismatch: original={} re-encoded={}",
                raw_decompressed.len(),
                re_encoded.len()
            );
        } else {
            for i in 0..raw_decompressed.len() {
                if raw_decompressed[i] != re_encoded[i] {
                    eprintln!(
                        "First byte mismatch at offset {}: original=0x{:02x} re-encoded=0x{:02x}",
                        i, raw_decompressed[i], re_encoded[i]
                    );
                    eprintln!(
                        "  original context: {:02x?}",
                        &raw_decompressed
                            [i.saturating_sub(4)..i.min(raw_decompressed.len()).saturating_add(8)]
                    );
                    eprintln!(
                        "  encoded context:  {:02x?}",
                        &re_encoded[i.saturating_sub(4)..i.min(re_encoded.len()).saturating_add(8)]
                    );
                    break;
                }
            }
        }

        // Compare byte-for-byte
        assert_eq!(
            &raw_decompressed[..],
            &re_encoded[..],
            "Reference table bytes don't match after round-trip"
        );
    }

    /// Round-trip ALL reference tables (archives 0-40) to verify the encoder
    /// handles every format variant in our cache.
    #[test]
    fn test_reference_table_roundtrip_all() {
        let cache_dir = Path::new("../cache");
        if !cache_dir.exists() {
            eprintln!("Skipping reference table round-trip test (no cache directory)");
            return;
        }

        let mut store = Js5Store::open(cache_dir).expect("Failed to open cache");

        let mut tested = 0;
        let mut failed = Vec::new();
        for archive_id in 0..=40u8 {
            let Ok(Some(raw)) = store.read_group_raw_decompressed(255, archive_id as u32) else {
                continue;
            };
            let Ok(table) = parse_reference_table(&raw) else {
                continue;
            };
            let re_encoded = encode_reference_table(&table);
            if raw.len() != re_encoded.len() || raw[..] != re_encoded[..] {
                failed.push(archive_id);
            }
            tested += 1;
        }

        assert!(
            failed.is_empty(),
            "Reference table round-trip failed for archives: {:?} ({} of {} tested)",
            failed,
            failed.len(),
            tested
        );
        assert!(
            tested > 0,
            "No reference tables tested (cache may be empty)"
        );
        eprintln!("Successfully round-tripped {} reference tables", tested);
    }

    /// Full write pipeline test: copy cache → write reference table → read back → verify.
    #[test]
    fn test_write_reference_table_roundtrip() {
        let cache_dir = Path::new("../cache");
        if !cache_dir.exists() {
            eprintln!("Skipping write test (no cache directory)");
            return;
        }

        // Copy cache files to project-local temp dir so we don't corrupt the original
        let tmp =
            Path::new(env!("CARGO_MANIFEST_DIR")).join("../target/test_tmp/rs_cache_write_test");
        let _ = fs::remove_dir_all(&tmp);
        fs::create_dir_all(&tmp).unwrap();
        for entry in fs::read_dir(cache_dir).unwrap() {
            let entry = entry.unwrap();
            if !entry.file_type().unwrap().is_file() {
                continue;
            }
            let dest = tmp.join(entry.file_name());
            fs::copy(entry.path(), &dest).unwrap();
        }

        // Read original reference table for archive 2
        let mut store = Js5Store::open(&tmp).expect("Failed to open temp cache");
        let original_raw = store.read_group_raw_decompressed(255, 2).unwrap().unwrap();
        let table = parse_reference_table(&original_raw).unwrap();

        // Write it back (compress + write to archive 255)
        store.write_reference_table(2, &table).unwrap();

        // Read it back and verify
        drop(store);
        let mut store2 = Js5Store::open(&tmp).expect("Failed to reopen temp cache");
        let readback = store2.read_group_raw_decompressed(255, 2).unwrap().unwrap();

        assert_eq!(
            &original_raw[..],
            &readback[..],
            "Reference table changed after write-read round-trip"
        );

        let _ = fs::remove_dir_all(&tmp);
        eprintln!("Write reference table round-trip: PASSED");
    }

    #[test]
    fn master_index_signature_matches_the_served_reference_tables() {
        const TEST_KEY_PEM: &str = "-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQCdQzsEvIb5dBQ3
XzRy+69J5EnVsgZehslAlxWbhUgbO6eF4BHXT5Y+9r8/wY7AefZzGWgzNyHwxm1w
Ws5Jn60r/ff4Njca9Eft9NWx3j124xOxFxtGqjBDTa1mXzTHbqyHNEjuK43tWWyW
vXjpcfusuv48qmGFRjbhPmqGgtQaqTrtgyoWanbgGcKAygZ4zIWR/NQv4WvD17vg
v1sVlyhUZbtshTed/OlXCrVn7kT/9ZfWAgY3y6dHHqtO4c+M4LJe/DyfLBxyHDKf
owI4CMXSfM+fEGEvkVRKhP8MjvlISS3AupagGc6oS+RPTa+IFJX0hJXG7ir4OreR
DqCsGv9xAgMBAAECggEAHADaw48mocjvyKRlXIxAvHGwTCM1SyPJNn0w1c639lF7
FTW/N43ufSvHBn1bBB8zqW8+xM/udUeAOV+SGD4cwhapT0OoMF6LaG4Ol2uxmjf5
S7GHo9+uVG3CkNYnOdQVWMYQroiG71rbIUSAAWHQpQNvPjJAx1CneRh6M5WcW1q7
qV3ipEq58U2GPKlHhlOxGOtZmsArNHOuO5r90gitLOpnoa26Bb+ojFn1tDjIVRPo
s3LSmPLv/KT9Od0SFFAwW/tYywrE5VfUIbKaTtbYA/VtoZkPnjr3SK57tsyTDhYq
CTNhaQ+bt9RUfx7h5T2CyUnfEdk2vLMSJMn52d07+QKBgQDPqlDJegXmjEGnr4CO
vUEcVV5GfERVd63Sr510qnm0V6lWekT8HV9hgRbTA/DqsHbicWVpZmgh7ss+51r3
hsTEGsw1INPScNLKpvGDT1sMGmf73W9zeeJ/osWB5pizpk5LawoBK1xKr46xtUTf
rmOjAW6kdGLSAntfm8iZ/pLxqwKBgQDB3a8nC6AM+HfQL2fS6OH8SUn0XNZi7ir+
IpVjCiT5BQmC6OuFFtgYRBtpsQUxpKXCs1/kHentglXAZyAYF5vOaSKhhhN/Tvhi
R0EMdL2LgMT8quMbQ/6liw9fjLTnd2VzCtrdOQzorERdIHm4HL4RB22uYMwA88cA
vcV2sIjvUwKBgAsSQ3haXxIpjB6KhsoVYPFHw9zyJxp/ZO8EmdpsdEyfF9Iadq8S
SdGC9lqNrTx16ACulv+FjCuy9XcHEpx7vOXPn+99Lo3bogFX4SxlAK+mgMC2z4hS
iTbQ0MLaLm31gdsXe9MQIr2AmpTy2xcpzvoTy3hNFC+qHjW8snczUVY9AoGASeWL
fzGiN296lCONyso0Yes5wmik2573Slm6Yb8bKsStxHWuWNPFWTKU1GvClBKzkIy5
L4XrhjoZH7bvd99/52UR60nlIrDiYuvQMsRI/+T8sWceHGWFqmpgWMaUqmpLhFeN
56d4cTRA9tKLMw/ZrzoKp96DxJUntPOhUkWmXLsCgYA6pJ3eC5sGDBrxxtthe/I+
15vlSF1LIVaTK1j/rUDCrfcISBUDwiX3iAY4kcntLrAFhLze2fJ7D5XY1Lahfd54
YECBv/SeBfxkckIJOj9bPbi7zXVtWXRrcj8+e6tF16WeemxvOGRY++OQ1+ktQMwn
4eEwZa3l2FKL9vv9/l6eVA==
-----END PRIVATE KEY-----";

        let keys = parse_rsa_key_from_pem(TEST_KEY_PEM).unwrap();
        let reference = [0, 0, 0, 0, 4, 5, 1, 0, 0];
        let container = encode_master_index([(reference.as_ref(), 0); 2].into_iter(), &keys);
        assert_eq!(container[0], 0);
        assert_eq!(
            u32::from_be_bytes(container[1..5].try_into().unwrap()) as usize,
            container.len() - 5
        );
        assert_eq!(container[5], 2);
        for entry in container[6..150].as_chunks::<72>().0 {
            assert_eq!(
                i32::from_be_bytes(entry[..4].try_into().unwrap()),
                getcrc(&reference, 0, reference.len())
            );
            assert_eq!(&entry[4..8], &[0; 4]);
            assert_eq!(&entry[8..], &whirlpool(&reference));
        }
        assert_eq!(container[150] & 0x80, 0);
        let signed = keys.encrypt(&container[150..]);
        assert_eq!(signed.len(), 65);
        assert_eq!(signed[0], 10);
        assert_eq!(&signed[1..], &whirlpool(&container[5..150]));
    }
}
