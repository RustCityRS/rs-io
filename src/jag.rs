use crate::Packet;
use crate::bz2::{bz2_compress, bz2_decompress};
use std::path::Path;

struct JagQueueFile {
    hash: i32,
    write: bool,
    data: Option<Box<[u8]>>,
    packed_size: Option<usize>,
    unpacked_size: Option<usize>,
    delete: bool,
    rename: bool,
    new_hash: Option<i32>,
}

pub struct JagFile {
    pub file_count: usize,
    pub file_hashes: Option<Box<[i32]>>,
    pub file_unpacks: Option<Box<[i32]>>,
    pub file_packs: Option<Box<[i32]>>,
    pub file_offsets: Option<Box<[usize]>>,
    pub data: Option<Box<[u8]>>,
    pub unpacked: bool,
    file_write: Vec<Option<Box<[u8]>>>,
    file_queue: Vec<JagQueueFile>,
}

impl JagFile {
    pub fn hash(name: &str) -> i32 {
        let mut hash: i32 = 0;
        for ch in name.as_bytes() {
            hash = hash
                .wrapping_mul(61)
                .wrapping_add(ch.to_ascii_uppercase() as i32 - 32);
        }
        hash
    }

    #[allow(clippy::new_without_default)]
    pub fn new() -> JagFile {
        JagFile {
            file_count: 0,
            file_hashes: None,
            file_unpacks: None,
            file_packs: None,
            file_offsets: None,
            data: None,
            unpacked: false,
            file_write: Vec::new(),
            file_queue: Vec::new(),
        }
    }

    pub fn from(bytes: Vec<u8>) -> JagFile {
        let mut buf = Packet::from(bytes);
        let unpacked = buf.g3();
        let packed = buf.g3();

        let mut decompressed: bool = false;

        if packed != unpacked {
            buf = Packet::from(bz2_decompress(&buf.data, unpacked as usize, true, 6));
            decompressed = true;
        }

        let file_count: usize = buf.g2() as usize;

        let mut file_hashes: Vec<i32> = vec![0; file_count];
        let mut file_unpacks: Vec<i32> = vec![0; file_count];
        let mut file_packs: Vec<i32> = vec![0; file_count];
        let mut file_offsets: Vec<usize> = vec![0; file_count];

        let mut pos: usize = buf.pos + file_count * 10;

        for index in 0..file_count {
            file_hashes[index] = buf.g4s();
            file_unpacks[index] = buf.g3();
            file_packs[index] = buf.g3();
            file_offsets[index] = pos;
            pos += file_packs[index] as usize;
        }

        JagFile {
            file_count,
            file_hashes: Some(file_hashes.into_boxed_slice()),
            file_unpacks: Some(file_unpacks.into_boxed_slice()),
            file_packs: Some(file_packs.into_boxed_slice()),
            file_offsets: Some(file_offsets.into_boxed_slice()),
            data: Some(buf.data.into_boxed_slice()),
            unpacked: decompressed,
            file_write: Vec::new(),
            file_queue: Vec::new(),
        }
    }

    pub fn read(&self, name: &str) -> Option<Packet> {
        let hash = JagFile::hash(name);
        self.file_hashes
            .iter()
            .flatten()
            .position(|&file_hash| file_hash == hash)
            .and_then(|index| self.get(index))
    }

    pub fn get(&self, index: usize) -> Option<Packet> {
        if index >= self.file_count {
            return None;
        }

        let Some(data) = &self.data else {
            return None;
        };

        let Some(file_offsets) = &self.file_offsets else {
            return None;
        };

        if file_offsets[index] >= data.len() {
            return None;
        }

        let Some(file_packs) = &self.file_packs else {
            return None;
        };

        let start = file_offsets[index];
        let end = start + file_packs[index] as usize;
        if self.unpacked {
            Some(Packet::from(data[start..end].to_vec()))
        } else {
            let Some(file_unpacks) = &self.file_unpacks else {
                return None;
            };
            Some(Packet::from(bz2_decompress(
                &data[start..end],
                file_unpacks[index] as usize,
                true,
                0,
            )))
        }
    }

    pub fn file_hash(&self, index: usize) -> i32 {
        self.file_hashes.as_ref().unwrap()[index]
    }

    pub fn write(&mut self, name: &str, data: Vec<u8>) {
        let hash = JagFile::hash(name);
        let len = data.len();
        self.file_queue.push(JagQueueFile {
            hash,
            write: true,
            data: Some(data.into_boxed_slice()),
            packed_size: Some(len),
            unpacked_size: Some(len),
            delete: false,
            rename: false,
            new_hash: None,
        });
    }

    pub fn delete(&mut self, name: &str) {
        let hash = JagFile::hash(name);
        self.file_queue.push(JagQueueFile {
            hash,
            write: false,
            data: None,
            packed_size: None,
            unpacked_size: None,
            delete: true,
            rename: false,
            new_hash: None,
        });
    }

    pub fn rename(&mut self, old_name: &str, new_name: &str) {
        let old_hash = JagFile::hash(old_name);
        let new_hash = JagFile::hash(new_name);
        self.file_queue.push(JagQueueFile {
            hash: old_hash,
            write: false,
            data: None,
            packed_size: None,
            unpacked_size: None,
            delete: false,
            rename: true,
            new_hash: Some(new_hash),
        });
    }

    pub fn build(&mut self) -> Vec<u8> {
        self.process_queue();
        let per_entry = self.assemble(false);
        let whole_archive = self.assemble(true);
        if whole_archive.len() < per_entry.len() {
            whole_archive
        } else {
            per_entry
        }
    }

    fn assemble(&self, compress_whole: bool) -> Vec<u8> {
        let hashes = self.file_hashes.as_ref().unwrap();
        let unpacks = self.file_unpacks.as_ref().unwrap();

        if compress_whole {
            let raw_size: usize = self
                .file_write
                .iter()
                .map(|d| d.as_ref().map_or(0, |v| v.len()))
                .sum();
            let buf_size = 2 + self.file_count * 10 + raw_size;
            let mut buf = Packet::new(buf_size);
            buf.p2(self.file_count as u16);
            for i in 0..self.file_count {
                buf.p4(hashes[i]);
                buf.p3(unpacks[i]);
                buf.p3(unpacks[i]);
            }
            for i in 0..self.file_count {
                let data = self.file_write[i].as_ref().expect("Missing file data");
                buf.pdata(data, 0, data.len());
            }
            let compressed = bz2_compress(&buf.data[..buf.pos], true);
            let mut jag = Packet::new(6 + compressed.len());
            jag.p3(buf.pos as i32);
            jag.p3(compressed.len() as i32);
            jag.pdata(&compressed, 0, compressed.len());
            jag.data[..jag.pos].to_vec()
        } else {
            let mut compressed_entries: Vec<Vec<u8>> = Vec::with_capacity(self.file_count);
            for i in 0..self.file_count {
                let data = self.file_write[i].as_ref().expect("Missing file data");
                compressed_entries.push(bz2_compress(data, true));
            }
            let compressed_size: usize = compressed_entries.iter().map(|c| c.len()).sum();
            let buf_size = 2 + self.file_count * 10 + compressed_size;
            let mut buf = Packet::new(buf_size);
            buf.p2(self.file_count as u16);
            for i in 0..self.file_count {
                buf.p4(hashes[i]);
                buf.p3(unpacks[i]);
                buf.p3(compressed_entries[i].len() as i32);
            }
            for entry in &compressed_entries {
                buf.pdata(entry, 0, entry.len());
            }
            let mut jag = Packet::new(6 + buf.pos);
            jag.p3(buf.pos as i32);
            jag.p3(buf.pos as i32);
            jag.pdata(&buf.data, 0, buf.pos);
            jag.data[..jag.pos].to_vec()
        }
    }

    fn process_queue(&mut self) {
        let queue: Vec<JagQueueFile> = self.file_queue.drain(..).collect();

        let mut hashes: Vec<i32> = self.file_hashes.take().map_or_else(Vec::new, Vec::from);
        let mut unpacks: Vec<i32> = self.file_unpacks.take().map_or_else(Vec::new, Vec::from);
        let mut packs: Vec<i32> = self.file_packs.take().map_or_else(Vec::new, Vec::from);
        let mut offsets: Vec<usize> = self.file_offsets.take().map_or_else(Vec::new, Vec::from);

        for queued in queue {
            let index = hashes.iter().position(|&h| h == queued.hash);

            if queued.write {
                let index = match index {
                    Some(i) => i,
                    None => {
                        let i = self.file_count;
                        self.file_count += 1;
                        hashes.push(queued.hash);
                        unpacks.push(0);
                        packs.push(0);
                        offsets.push(0);
                        self.file_write.push(None);
                        i
                    }
                };
                let data = queued.data.expect("Cannot write without data");
                unpacks[index] = queued.unpacked_size.unwrap() as i32;
                packs[index] = queued.packed_size.unwrap() as i32;
                offsets[index] = usize::MAX;
                self.file_write.resize(self.file_count, None);
                self.file_write[index] = Some(data);
            }

            if queued.delete
                && let Some(i) = index
            {
                hashes.remove(i);
                unpacks.remove(i);
                packs.remove(i);
                offsets.remove(i);
                if i < self.file_write.len() {
                    self.file_write.remove(i);
                }
                self.file_count -= 1;
            }

            if queued.rename
                && let Some(i) = index
            {
                hashes[i] = queued.new_hash.expect("Cannot rename without new_hash");
            }
        }

        self.file_hashes = Some(hashes.into_boxed_slice());
        self.file_unpacks = Some(unpacks.into_boxed_slice());
        self.file_packs = Some(packs.into_boxed_slice());
        self.file_offsets = Some(offsets.into_boxed_slice());
    }

    pub fn save(&mut self, path: &Path) {
        let bytes = self.build();
        std::fs::write(path, bytes).expect("Failed to save JagFile");
    }
}

#[cfg(test)]
mod tests {
    use crate::jag::JagFile;

    #[test]
    fn test_hash_gnomeball_buttons() {
        assert_eq!(22834782, JagFile::hash("gnomeball_buttons.dat"));
    }

    #[test]
    fn test_hash_headicons() {
        assert_eq!(-288954319, JagFile::hash("headicons.dat"));
    }

    #[test]
    fn test_hash_hitmarks() {
        assert_eq!(-1502153170, JagFile::hash("hitmarks.dat"));
    }
}
