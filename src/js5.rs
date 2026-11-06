//! RuneScape cache stores, JS5 containers and reference tables.

use crate::Packet;
use crate::crc::getcrc;
use crate::gz::gz_decompress;
use compression::{decompress_owned, decompress_xtea};
use std::collections::HashMap;
use std::fs::{self, File, OpenOptions};
use std::io::{Read, Seek, SeekFrom, Write};
use std::ops::Range;
use std::path::Path;
use std::sync::Arc;
use thiserror::Error;
use tracing::{debug, trace, warn};

pub mod compression;
pub mod reference;

/// Cache error types
#[derive(Error, Debug)]
pub enum CacheError {
    #[error("IO error: {0}")]
    Io(#[from] std::io::Error),

    #[error("Invalid cache file format")]
    InvalidFormat,

    #[error("Archive {0} not found")]
    ArchiveNotFound(u8),

    #[error("Group {0} not found in archive {1}")]
    GroupNotFound(u32, u8),

    #[error("Decompression error: {0}")]
    Decompression(String),

    #[error("XTEA decryption failed")]
    XteaDecryption,

    #[error("CRC32 mismatch: expected {expected}, got {actual}")]
    CrcMismatch { expected: u32, actual: u32 },
}

pub type Result<T> = std::result::Result<T, CacheError>;

pub struct Js5Store {
    data_file: File,
    index_files: HashMap<u8, IndexFile>,
    reference_tables: HashMap<u8, reference::ReferenceTable>,
    legacy: bool,
}

struct IndexFile {
    file: File,
    data: Vec<u8>,
}

/// A group entry in the cache
#[derive(Debug, Clone)]
pub struct Group {
    pub id: u32,
    pub name_hash: i32,
    pub crc: u32,
    pub whirlpool: Option<[u8; 64]>,
    pub version: u32,
    pub size: usize,
    pub entries: Vec<Entry>,
}

/// An individual entry within a group
#[derive(Debug, Clone)]
pub struct Entry {
    pub id: u32,
    pub name_hash: i32,
    data: Arc<Vec<u8>>,
    range: Range<usize>,
}

impl Entry {
    #[inline]
    pub fn data(&self) -> &[u8] {
        &self.data[self.range.clone()]
    }
}

impl Js5Store {
    pub fn open<P: AsRef<Path>>(path: P) -> Result<Self> {
        let path = path.as_ref().to_path_buf();
        let legacy = !path.join("main_file_cache.dat2").exists();
        let data_path = path.join(if legacy {
            "main_file_cache.dat"
        } else {
            "main_file_cache.dat2"
        });
        let data_file = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&data_path)
            .or_else(|_| File::open(&data_path))?;
        let mut index_files = HashMap::new();
        for id in 0..=255u8 {
            let idx_path = path.join(format!("main_file_cache.idx{id}"));
            if idx_path.exists() {
                let mut file = OpenOptions::new()
                    .read(true)
                    .write(true)
                    .open(&idx_path)
                    .or_else(|_| File::open(&idx_path))?;
                let mut data = Vec::new();
                file.read_to_end(&mut data)?;
                index_files.insert(id, IndexFile { file, data });
            }
        }
        let mut store = Self {
            data_file,
            index_files,
            reference_tables: HashMap::new(),
            legacy,
        };
        if !legacy {
            store.load_reference_tables()?;
        }
        Ok(store)
    }

    pub fn create<P: AsRef<Path>>(path: P, archive_ids: &[u8]) -> Result<Self> {
        let path = path.as_ref();
        fs::create_dir_all(path)?;
        let mut data = OpenOptions::new()
            .write(true)
            .create(true)
            .truncate(false)
            .open(path.join("main_file_cache.dat2"))?;
        if data.metadata()?.len() == 0 {
            data.write_all(&[0; 520])?;
        }
        for id in archive_ids.iter().copied().chain([255]) {
            OpenOptions::new()
                .write(true)
                .create(true)
                .truncate(false)
                .open(path.join(format!("main_file_cache.idx{id}")))?;
        }
        Self::open(path)
    }

    /// Load all reference tables from index 255
    fn load_reference_tables(&mut self) -> Result<()> {
        // Index 255 contains reference tables for other archives
        for archive_id in 0..=255u8 {
            match self.read_group(255, archive_id as u32) {
                Ok(Some(group)) => {
                    if let Some(entry) = group.entries.first() {
                        match reference::parse_reference_table(entry.data()) {
                            Ok(table) => {
                                self.reference_tables.insert(archive_id, table);
                                debug!("Loaded reference table for archive {}", archive_id);
                            }
                            Err(e) => {
                                trace!(
                                    "Could not parse reference table for archive {}: {}",
                                    archive_id, e
                                );
                            }
                        }
                    }
                }
                Ok(None) => {} // Group doesn't exist
                Err(e) => {
                    trace!(
                        "Could not read reference table for archive {}: {}",
                        archive_id, e
                    );
                }
            }
        }

        Ok(())
    }

    pub fn read_raw_group_bytes(
        &mut self,
        archive_id: u8,
        group_id: u32,
    ) -> Result<Option<Vec<u8>>> {
        let index = self
            .index_files
            .get(&archive_id)
            .ok_or(CacheError::ArchiveNotFound(archive_id))?;
        if group_id as usize >= index.data.len() / 6 {
            return Ok(None);
        }
        let pos = group_id as usize * 6;
        let mut entry = Packet::from(&index.data[pos..pos + 6]);
        let size = entry.g3() as usize;
        let mut sector = entry.g3() as u32;
        if size == 0 || sector == 0 {
            return Ok(None);
        }
        let width = if group_id > u16::MAX as u32 { 4 } else { 2 };
        let header_len = width + 6;
        let mut data = vec![0; size];
        let mut block = [0; 520];
        for (chunk, payload) in data.chunks_mut(520 - header_len).enumerate() {
            if sector == 0 {
                return Err(CacheError::InvalidFormat);
            }
            self.data_file.seek(SeekFrom::Start(sector as u64 * 520))?;
            self.data_file
                .read_exact(&mut block[..header_len + payload.len()])?;
            let mut header = Packet::from(&block[..header_len]);
            let group = if width == 4 {
                header.g4s() as u32
            } else {
                header.g2() as u32
            };
            let part = header.g2();
            sector = header.g3() as u32;
            let archive = header.g1();
            if group != group_id
                || part as usize != chunk
                || archive as u16 != archive_id as u16 + u16::from(self.legacy)
            {
                return Err(CacheError::InvalidFormat);
            }
            payload.copy_from_slice(&block[header_len..header_len + payload.len()]);
        }
        Ok(Some(data))
    }

    /// Read and decompress a group from the cache, splitting into entries using the reference table
    pub fn read_group(&mut self, archive_id: u8, group_id: u32) -> Result<Option<Group>> {
        let Some(decompressed) = self.read_group_raw_decompressed(archive_id, group_id)? else {
            return Ok(None);
        };
        let size = decompressed.len();

        // Look up group info from reference table
        let group_info = self.reference_tables.get(&archive_id).and_then(|rt| {
            rt.groups
                .binary_search_by_key(&group_id, |group| group.id)
                .ok()
                .map(|index| &rt.groups[index])
        });

        let (name_hash, crc, whirlpool, version, entries) = if let Some(info) = group_info {
            let file_count = info.files.len();
            let entries = if file_count <= 1 {
                // Single file - return data directly
                let file_id = info.files.first().map(|f| f.id).unwrap_or(0);
                let file_name = info.files.first().and_then(|f| f.name_hash).unwrap_or(-1);
                vec![Entry {
                    id: file_id,
                    name_hash: file_name,
                    data: Arc::new(decompressed),
                    range: 0..size,
                }]
            } else {
                // Multi-file: split using stripe format
                split_group_entries(decompressed, &info.files)
            };
            (
                info.name_hash,
                info.crc,
                info.whirlpool,
                info.version,
                entries,
            )
        } else {
            // No reference table - return as single entry
            let entries = vec![Entry {
                id: 0,
                name_hash: -1,
                data: Arc::new(decompressed),
                range: 0..size,
            }];
            (-1, 0, None, 0, entries)
        };

        Ok(Some(Group {
            id: group_id,
            name_hash,
            crc,
            whirlpool,
            version,
            size,
            entries,
        }))
    }

    /// Get the number of groups in an archive
    pub fn group_count(&self, archive_id: u8) -> Option<u32> {
        self.index_files
            .get(&archive_id)
            .map(|idx| (idx.data.len() / 6) as u32)
    }

    /// Check if an archive exists
    pub fn has_archive(&self, archive_id: u8) -> bool {
        self.index_files.contains_key(&archive_id)
    }

    /// Get the reference table for an archive
    pub fn reference_table(&self, archive_id: u8) -> Option<&reference::ReferenceTable> {
        self.reference_tables.get(&archive_id)
    }

    /// Read and decompress a group, returning the raw decompressed bytes (before entry splitting).
    /// Useful for debugging cache format issues.
    pub fn read_group_raw_decompressed(
        &mut self,
        archive_id: u8,
        group_id: u32,
    ) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self.read_raw_group_bytes(archive_id, group_id)? else {
            return Ok(None);
        };
        let data = if self.legacy {
            if archive_id == 0 {
                raw
            } else {
                gz_decompress(&raw, 4 * 1024 * 1024)
            }
        } else {
            decompress_owned(raw)?
        };
        Ok(Some(data))
    }

    pub fn write_raw_group(&mut self, archive_id: u8, group_id: u32, data: &[u8]) -> Result<()> {
        if data.len() > 0xffffff {
            return Err(CacheError::InvalidFormat);
        }
        let index = self
            .index_files
            .get_mut(&archive_id)
            .ok_or(CacheError::ArchiveNotFound(archive_id))?;
        let dat_end = self.data_file.seek(SeekFrom::End(0))?;
        let first_sector = dat_end.div_ceil(520).max(1) as u32;
        let archive = archive_id
            .checked_add(u8::from(self.legacy))
            .ok_or(CacheError::InvalidFormat)?;
        let width = if group_id > u16::MAX as u32 { 4 } else { 2 };
        let header_len = width + 6;
        let capacity = 520 - header_len;
        let sectors = data.len().div_ceil(capacity);
        if first_sector as usize + sectors > 0x1000000 {
            return Err(CacheError::InvalidFormat);
        }
        for (chunk, payload) in data.chunks(capacity).enumerate() {
            let current = first_sector + chunk as u32;
            let next = if chunk + 1 == sectors { 0 } else { current + 1 };
            let mut sector = Packet::from([0; 520]);
            if width == 4 {
                sector.p4(group_id as i32);
            } else {
                sector.p2(group_id as u16);
            }
            sector.p2(chunk as u16);
            sector.p3(next as i32);
            sector.p1(archive);
            sector.pdata(payload, 0, payload.len());
            self.data_file.seek(SeekFrom::Start(current as u64 * 520))?;
            self.data_file.write_all(&sector.data)?;
        }
        let mut entry = Packet::from([0; 6]);
        entry.p3(data.len() as i32);
        entry.p3(first_sector as i32);
        index.file.seek(SeekFrom::Start(group_id as u64 * 6))?;
        index.file.write_all(&entry.data)?;
        let pos = group_id as usize * 6;
        if index.data.len() < pos + 6 {
            index.data.resize(pos + 6, 0);
        }
        index.data[pos..pos + 6].copy_from_slice(&entry.data);

        Ok(())
    }

    /// Write a group to the cache with compression.
    /// Compresses the decompressed data, appends the 2-byte version suffix,
    /// writes to dat2, and updates idx.
    ///
    /// Returns the CRC32 of the compressed data (excluding the version suffix),
    /// which is what the reference table expects.
    pub fn write_group(
        &mut self,
        archive_id: u8,
        group_id: u32,
        data: &[u8],
        compression: compression::CompressionType,
        version: u16,
    ) -> Result<u32> {
        let compressed = compression::compress(data, compression)?;
        let crc = compute_group_crc(&compressed);
        // Append 2-byte version suffix (big-endian) — the idx size includes this
        let mut with_version = compressed;
        with_version.push((version >> 8) as u8);
        with_version.push(version as u8);
        self.write_raw_group(archive_id, group_id, &with_version)?;
        Ok(crc)
    }

    /// Reference tables carry their version in the body, with no group version suffix.
    pub fn write_reference_table(
        &mut self,
        archive_id: u8,
        table: &reference::ReferenceTable,
    ) -> Result<()> {
        let encoded = reference::encode_reference_table(table);
        let compressed = compression::compress_best(&encoded, true, true, None)?;
        // No version suffix for archive 255 entries.
        self.write_raw_group(255, archive_id as u32, &compressed)?;
        // Update our in-memory copy
        self.reference_tables.insert(archive_id, table.clone());
        Ok(())
    }

    /// Write a raw (already-compressed) reference table to archive 255
    /// and update the in-memory cache. Use this for passthrough where
    /// you already have the exact bytes from the source cache.
    pub fn write_reference_table_raw(
        &mut self,
        archive_id: u8,
        raw_compressed: &[u8],
        table: reference::ReferenceTable,
    ) -> Result<()> {
        self.write_raw_group(255, archive_id as u32, raw_compressed)?;
        self.reference_tables.insert(archive_id, table);
        Ok(())
    }

    pub fn read_group_xtea(
        &mut self,
        archive_id: u8,
        group_id: u32,
        keys: &[i32; 4],
    ) -> Result<Option<Vec<u8>>> {
        let Some(raw) = self.read_raw_group_bytes(archive_id, group_id)? else {
            return Ok(None);
        };

        if *keys == [0; 4] {
            return Ok(Some(decompress_owned(raw)?));
        }
        Ok(Some(decompress_xtea(&raw, keys)?))
    }
}

/// Split a multi-file group's decompressed data into individual entries using the JS5 stripe format.
///
/// The trailer at the end of the data contains:
/// - `num_stripes * file_count` big-endian i32 delta-encoded chunk sizes
///   (row-major: stripe 0 all files, stripe 1 all files, ...)
///   Each value is delta-encoded: actual_size = running_sum_per_stripe += read_i32()
/// - 1 byte: num_stripes
///
/// Data body is laid out as sequential stripes, each stripe containing one chunk per file in order.
///
/// Public so a group obtained from somewhere other than a local `Js5Store`
/// -- an archive server, say -- can be split with the same code the cache
/// reader uses. The stripe layout is fiddly enough that a second
/// implementation would be a second set of bugs.
pub fn split_group_entries(data: Vec<u8>, files: &[reference::FileInfo]) -> Vec<Entry> {
    let file_count = files.len();
    if data.is_empty() || file_count == 0 {
        return vec![];
    }

    let num_stripes = data[data.len() - 1] as usize;
    let trailer_size = 1 + num_stripes * file_count * 4;

    if num_stripes == 0 || data.len() < trailer_size {
        // Fallback: return all data as the single (first) file
        return vec![Entry {
            id: files[0].id,
            name_hash: files[0].name_hash.unwrap_or(-1),
            range: 0..data.len(),
            data: Arc::new(data),
        }];
    }

    let body_len = data.len() - trailer_size;
    let mut trailer = Packet::from(&data[body_len..]);
    let mut sizes = vec![0usize; file_count];
    for _ in 0..num_stripes {
        let mut len: i32 = 0;
        for size in &mut sizes {
            len += trailer.g4s();
            *size += len.max(0) as usize;
        }
    }

    let mut pos = 0;
    if num_stripes == 1 {
        let data = Arc::new(data);
        return files
            .iter()
            .zip(sizes)
            .enumerate()
            .map(|(index, (file, size))| {
                let start = pos;
                pos += size;
                let range = if pos <= body_len {
                    start..pos
                } else {
                    warn!("Chunk out of bounds: file={}, stripe=0", index);
                    0..0
                };
                Entry {
                    id: file.id,
                    name_hash: file.name_hash.unwrap_or(-1),
                    data: Arc::clone(&data),
                    range,
                }
            })
            .collect();
    }

    let mut total = 0;
    let mut ranges: Vec<_> = sizes
        .into_iter()
        .map(|size| {
            let start = total;
            total += size;
            start..start
        })
        .collect();
    let mut output = vec![0; total];
    trailer.pos = 0;
    for stripe in 0..num_stripes {
        let mut len: i32 = 0;
        for (index, range) in ranges.iter_mut().enumerate() {
            len += trailer.g4s();
            let size = len.max(0) as usize;
            let end = pos + size;
            if end <= body_len {
                output[range.end..range.end + size].copy_from_slice(&data[pos..end]);
                range.end += size;
            } else {
                warn!("Chunk out of bounds: file={}, stripe={}", index, stripe);
            }
            pos = end;
        }
    }
    let data = Arc::new(output);
    files
        .iter()
        .zip(ranges)
        .map(|(file, range)| Entry {
            id: file.id,
            name_hash: file.name_hash.unwrap_or(-1),
            data: Arc::clone(&data),
            range,
        })
        .collect()
}

/// Encode multiple file entries into a single group blob using the JS5 stripe format.
///
/// Each entry is `(file_id, data)`. For single-entry groups, returns the
/// data directly (no trailer). For multi-entry groups, produces a 1-stripe layout.
pub fn encode_group_entries(entries: &[(u32, &[u8])]) -> Vec<u8> {
    if entries.is_empty() {
        return vec![];
    }
    if entries.len() == 1 {
        return entries[0].1.to_vec();
    }

    let size: usize = entries.iter().map(|(_, data)| data.len()).sum();
    let mut out = Packet::new(size + entries.len() * 4 + 1);
    for (_, data) in entries {
        out.pdata(data, 0, data.len());
    }
    let mut prev = 0;
    for (_, data) in entries {
        let size = data.len() as i32;
        out.p4(size - prev);
        prev = size;
    }
    out.p1(1);
    out.data
}

/// Encode with a custom stripe splitter.
///
/// `split_fn(entry_data, stripe_count) -> Vec<Vec<u8>>` splits each entry
/// into `stripe_count` chunks. The body interleaves all entries' chunk 0,
/// then all entries' chunk 1, etc.
pub fn encode_group_entries_striped(
    entries: &[(u32, &[u8])],
    num_stripes: u8,
    split_fn: impl Fn(&[u8], u8) -> Vec<Vec<u8>>,
) -> Vec<u8> {
    if entries.is_empty() {
        return vec![];
    }
    if entries.len() == 1 {
        return entries[0].1.to_vec();
    }

    let ns = num_stripes as usize;

    // Split each entry into stripes
    let split: Vec<Vec<Vec<u8>>> = entries
        .iter()
        .map(|(_, data)| split_fn(data, num_stripes))
        .collect();

    // Interleave: body = [all stripe 0 chunks][all stripe 1 chunks]...
    let size: usize = split
        .iter()
        .flat_map(|chunks| &chunks[..ns])
        .map(Vec::len)
        .sum();
    let mut body = Vec::with_capacity(size + ns * entries.len() * 4 + 1);
    for s in 0..ns {
        for entry_chunks in &split {
            body.extend_from_slice(&entry_chunks[s]);
        }
    }

    // Trailer: delta-encoded sizes per stripe, then num_stripes byte
    let pos = body.len();
    body.resize(pos + ns * entries.len() * 4 + 1, 0);
    let mut trailer = Packet::from(&mut body[pos..]);
    for s in 0..ns {
        let mut prev: i32 = 0;
        for entry_chunks in &split {
            let size = entry_chunks[s].len() as i32;
            trailer.p4(size - prev);
            prev = size;
        }
    }
    trailer.p1(num_stripes);
    body
}

/// Detect the number of files in a group blob by parsing its entry footer.
///
/// Multi-entry groups end with `[delta_sizes: file_count * num_stripes * 4 bytes] [num_stripes: u8]`.
/// Single-entry groups have no footer (the blob IS the data).
///
/// Returns 1 for single-entry blobs, or the detected file_count for multi-entry blobs.
pub fn detect_file_count(blob: &[u8]) -> u32 {
    if blob.is_empty() {
        return 1;
    }
    let num_stripes = blob[blob.len() - 1] as usize;
    if num_stripes == 0 {
        return 1;
    }
    // Try candidate file_counts from 2 upward.
    // trailer = file_count * num_stripes * 4 + 1
    // body = blob.len() - trailer
    // The accumulated deltas (per stripe) must sum to body length.
    for fc in 2u32..=4096 {
        let trailer_len = fc as usize * num_stripes * 4 + 1;
        if trailer_len >= blob.len() {
            break;
        }
        let body_len = blob.len() - trailer_len;
        let trailer_start = body_len;

        let mut total_size: i64 = 0;
        let mut valid = true;
        for stripe in 0..num_stripes {
            let mut prev: i32 = 0;
            for file in 0..fc as usize {
                let off = trailer_start + (stripe * fc as usize + file) * 4;
                let delta = Packet::from(&blob[off..off + 4]).g4s();
                prev = prev.wrapping_add(delta);
                if prev < 0 {
                    valid = false;
                    break;
                }
                total_size += prev as i64;
            }
            if !valid {
                break;
            }
        }
        if valid && total_size == body_len as i64 {
            return fc;
        }
    }
    1
}

/// Compute CRC32 of a group's raw compressed bytes (for reference table updates).
pub fn compute_group_crc(raw_compressed: &[u8]) -> u32 {
    getcrc(raw_compressed, 0, raw_compressed.len()) as u32
}

/// Compute Java's String.hashCode() (same as RS2 name hash algorithm).
pub fn java_string_hash(s: &str) -> i32 {
    let mut h: i32 = 0;
    for b in s.bytes() {
        h = h.wrapping_mul(31).wrapping_add(b as i32);
    }
    h
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::time::{SystemTime, UNIX_EPOCH};

    #[test]
    fn stripe_layout_preserves_order_empty_chunks_and_negative_deltas() {
        let files = [
            reference::FileInfo {
                id: 2,
                name_hash: Some(10),
            },
            reference::FileInfo {
                id: 5,
                name_hash: None,
            },
            reference::FileInfo {
                id: 9,
                name_hash: Some(20),
            },
        ];
        let one = b"abcdxyz\x00\x00\x00\x04\xff\xff\xff\xfc\x00\x00\x00\x03\x01".to_vec();
        assert_eq!(
            encode_group_entries(&[(2, b"abcd"), (5, b""), (9, b"xyz")]),
            one,
        );
        let ptr = one.as_ptr();
        let entries = split_group_entries(one, &files);
        for (entry, (id, name, data)) in
            entries
                .iter()
                .zip([(2, 10, b"abcd".as_slice()), (5, -1, b""), (9, 20, b"xyz")])
        {
            assert_eq!((entry.id, entry.name_hash), (id, name));
            assert_eq!(entry.data(), data);
        }
        assert_eq!(entries[0].data().as_ptr(), ptr);
        assert_eq!(entries[2].data().as_ptr(), ptr.wrapping_add(4));
        assert!(Arc::ptr_eq(&entries[0].data, &entries[2].data));
        let retained = entries[2].clone();
        drop(entries);
        assert_eq!(retained.data(), b"xyz");

        let two = b"abCdefGHi\x00\x00\x00\x02\xff\xff\xff\xfe\x00\x00\x00\x01\x00\x00\x00\x03\xff\xff\xff\xff\xff\xff\xff\xff\x02".to_vec();
        let entries = split_group_entries(two, &files);
        for (entry, expected) in entries.iter().zip([b"abdef".as_slice(), b"GH", b"Ci"]) {
            assert_eq!(entry.data(), expected);
        }
        assert!(Arc::ptr_eq(&entries[0].data, &entries[2].data));
        assert!(encode_group_entries(&[]).is_empty());
        assert_eq!(encode_group_entries(&[(2, b"one")]), b"one");
    }

    #[test]
    fn disk_stores_share_sector_io() {
        let path = std::env::temp_dir().join(format!(
            "rs-cache-{}-{}",
            std::process::id(),
            SystemTime::now()
                .duration_since(UNIX_EPOCH)
                .unwrap()
                .as_nanos()
        ));
        let data: Vec<u8> = (0..1030).map(|i| i as u8).collect();
        fs::create_dir_all(&path).unwrap();
        let mut dat = vec![0; 4 * 520];
        for (part, payload) in data.chunks(512).enumerate() {
            let offset = (part + 1) * 520;
            let next = if part == 2 { 0 } else { part as u8 + 2 };
            dat[offset..offset + 8].copy_from_slice(&[0, 1, 0, part as u8, 0, 0, next, 1]);
            dat[offset + 8..offset + 8 + payload.len()].copy_from_slice(payload);
        }
        fs::write(path.join("main_file_cache.dat"), dat).unwrap();
        fs::write(
            path.join("main_file_cache.idx0"),
            [0, 0, 0, 0, 0, 0, 0, 4, 6, 0, 0, 1],
        )
        .unwrap();
        fs::write(path.join("main_file_cache.idx1"), []).unwrap();
        {
            let mut store = Js5Store::open(&path).unwrap();
            assert_eq!(store.read_raw_group_bytes(0, 1).unwrap().unwrap(), data);
            let mut compressed = crate::gz::gz_compress(&data);
            compressed.extend_from_slice(&7u16.to_be_bytes());
            store.write_raw_group(1, 3, &compressed).unwrap();
            assert_eq!(
                store.read_group_raw_decompressed(1, 3).unwrap().unwrap(),
                data
            );
            store.write_raw_group(0, 4, &data).unwrap();
            assert_eq!(store.group_count(0), Some(5));
            assert_eq!(store.read_raw_group_bytes(0, 4).unwrap().unwrap(), data);
        }
        let modern = path.join("modern");
        {
            let mut store = Js5Store::create(&modern, &[1]).unwrap();
            for group in [0, 7, 65536] {
                store.write_raw_group(1, group, &data).unwrap();
                assert_eq!(store.group_count(1), Some(group + 1));
                assert_eq!(store.read_raw_group_bytes(1, group).unwrap().unwrap(), data);
            }
            assert!(store.read_raw_group_bytes(1, 1).unwrap().is_none());
        }
        {
            let mut store = Js5Store::open(&modern).unwrap();
            assert_eq!(store.read_raw_group_bytes(1, 65536).unwrap().unwrap(), data);
            let end = store.data_file.metadata().unwrap().len();
            store.data_file.set_len(end - 520 + 10 + 10).unwrap();
            assert_eq!(store.read_raw_group_bytes(1, 65536).unwrap().unwrap(), data);
            store.write_raw_group(1, 7, b"replacement").unwrap();
            assert_eq!(
                store.read_raw_group_bytes(1, 7).unwrap().unwrap(),
                b"replacement"[..]
            );
            assert_eq!(store.group_count(1), Some(65537));
            // The first group spans sectors 1-3; corrupt one header field at a time.
            for (offset, original) in [(520 + 1, 0), (520 + 3, 0), (520 + 7, 1), (1040 + 3, 1)] {
                store.data_file.seek(SeekFrom::Start(offset)).unwrap();
                store.data_file.write_all(&[original + 1]).unwrap();
                assert!(matches!(
                    store.read_raw_group_bytes(1, 0),
                    Err(CacheError::InvalidFormat)
                ));
                store.data_file.seek(SeekFrom::Start(offset)).unwrap();
                store.data_file.write_all(&[original]).unwrap();
            }
            store.data_file.seek(SeekFrom::Start(520 + 4)).unwrap();
            store.data_file.write_all(&[0; 3]).unwrap();
            assert!(matches!(
                store.read_raw_group_bytes(1, 0),
                Err(CacheError::InvalidFormat)
            ));
        }
        fs::remove_dir_all(path).unwrap();
    }
}
