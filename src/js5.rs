use std::path::Path;

use crate::gz::{gz_compress, gz_decompress};
use crate::zip::fflate;

const SECTOR_SIZE: usize = 512 + SECTOR_HEADER_SIZE;
const SECTOR_HEADER_SIZE: usize = 8;
const SECTOR_PAYLOAD: usize = SECTOR_SIZE - SECTOR_HEADER_SIZE;
const INDEX_ENTRY_SIZE: usize = 6;
const MAX_BLOB_SIZE: usize = 2_000_000;

pub struct Js5Store {
    dat: Vec<u8>,
    idx: Vec<Option<Vec<u8>>>,
}

impl Js5Store {
    pub fn open(dir: &Path, count: usize) -> std::io::Result<Self> {
        let dat_path = dir.join("main_file_cache.dat");
        let dat = std::fs::read(&dat_path).map_err(|e| {
            std::io::Error::new(e.kind(), format!("reading {}: {e}", dat_path.display()))
        })?;

        let mut idx = Vec::with_capacity(count);
        for i in 0..count {
            idx.push(std::fs::read(dir.join(format!("main_file_cache.idx{i}"))).ok());
        }

        Ok(Self { dat, idx })
    }

    pub fn count(&self, index: usize) -> usize {
        match self.idx.get(index).and_then(|o| o.as_ref()) {
            Some(bytes) => bytes.len() / INDEX_ENTRY_SIZE,
            None => 0,
        }
    }

    pub fn has(&self, index: usize, file: usize) -> bool {
        self.locate(index, file).is_some()
    }

    pub fn read(&self, index: usize, file: usize, decompress: bool) -> Option<Vec<u8>> {
        let (size, first_sector) = self.locate(index, file)?;

        let mut out = Vec::with_capacity(size);
        let mut sector = first_sector;
        let mut part = 0;

        while out.len() < size {
            if sector == 0 {
                break;
            }

            let off = sector * SECTOR_SIZE;
            let data_start = off + SECTOR_HEADER_SIZE;
            if data_start > self.dat.len() {
                return None;
            }
            let header = &self.dat[off..data_start];

            let sector_file = u16::from_be_bytes([header[0], header[1]]) as usize;
            let sector_part = u16::from_be_bytes([header[2], header[3]]) as usize;
            let next_sector = g3(&header[4..7]);
            let sector_index = header[7] as usize;

            if sector_file != file || sector_part != part || sector_index != index + 1 {
                return None;
            }
            if next_sector > self.dat.len() / SECTOR_SIZE {
                return None;
            }

            let take = (size - out.len()).min(SECTOR_PAYLOAD);
            let data_end = data_start + take;
            if data_end > self.dat.len() {
                return None;
            }
            out.extend_from_slice(&self.dat[data_start..data_end]);

            sector = next_sector;
            part += 1;
        }

        if decompress && index != 0 {
            return Some(gunzip(&out));
        }
        Some(out)
    }

    fn locate(&self, index: usize, file: usize) -> Option<(usize, usize)> {
        let idx = self.idx.get(index)?.as_ref()?;
        if file >= idx.len() / INDEX_ENTRY_SIZE {
            return None;
        }

        let start = file * INDEX_ENTRY_SIZE;
        let entry = &idx[start..start + INDEX_ENTRY_SIZE];
        let size = g3(&entry[0..3]);
        let sector = g3(&entry[3..6]);

        if size > MAX_BLOB_SIZE {
            return None;
        }
        if sector == 0 || sector > self.dat.len() / SECTOR_SIZE {
            return None;
        }

        Some((size, sector))
    }

    pub fn create(count: usize) -> Self {
        Self {
            dat: Vec::new(),
            idx: (0..count).map(|_| Some(Vec::new())).collect(),
        }
    }

    pub fn write(&mut self, index: usize, file: usize, data: &[u8]) {
        if index >= self.idx.len() {
            return;
        }

        let mut sector = self.dat.len().div_ceil(SECTOR_SIZE).max(1);

        let idx = self.idx[index].get_or_insert_with(Vec::new);
        let pos = file * INDEX_ENTRY_SIZE;
        if idx.len() < pos + INDEX_ENTRY_SIZE {
            idx.resize(pos + INDEX_ENTRY_SIZE, 0);
        }
        p3(&mut idx[pos..pos + 3], data.len());
        p3(&mut idx[pos + 3..pos + 6], sector);

        let mut written = 0;
        let mut part = 0;
        while written < data.len() {
            let mut next_sector = self.dat.len().div_ceil(SECTOR_SIZE).max(1);
            if next_sector == sector {
                next_sector += 1;
            }
            if data.len() - written <= SECTOR_PAYLOAD {
                next_sector = 0;
            }

            let off = sector * SECTOR_SIZE;
            if self.dat.len() < off {
                self.dat.resize(off, 0);
            }

            self.dat.extend_from_slice(&(file as u16).to_be_bytes());
            self.dat.extend_from_slice(&(part as u16).to_be_bytes());
            let mut next = [0; 3];
            p3(&mut next, next_sector);
            self.dat.extend_from_slice(&next);
            self.dat.push((index + 1) as u8);

            let take = (data.len() - written).min(SECTOR_PAYLOAD);
            self.dat.extend_from_slice(&data[written..written + take]);
            written += take;

            sector = next_sector;
            part += 1;
        }
    }

    pub fn write_compressed(&mut self, index: usize, file: usize, content: &[u8], version: u16) {
        let mut blob = gz_compress(content);
        if version != 0 {
            blob.extend_from_slice(&version.to_be_bytes());
        }
        self.write(index, file, &blob);
    }

    pub fn ensure_file_count(&mut self, index: usize, count: usize) {
        if let Some(slot) = self.idx.get_mut(index) {
            let idx = slot.get_or_insert_with(Vec::new);
            let need = count * INDEX_ENTRY_SIZE;
            if idx.len() < need {
                idx.resize(need, 0);
            }
        }
    }

    pub fn save(&self, dir: &Path) -> std::io::Result<()> {
        std::fs::create_dir_all(dir)?;
        std::fs::write(dir.join("main_file_cache.dat"), &self.dat)?;
        for (i, idx) in self.idx.iter().enumerate() {
            if let Some(bytes) = idx {
                std::fs::write(dir.join(format!("main_file_cache.idx{i}")), bytes)?;
            }
        }
        Ok(())
    }
}

#[inline(always)]
fn g3(b: &[u8]) -> usize {
    ((b[0] as usize) << 16) | ((b[1] as usize) << 8) | (b[2] as usize)
}

#[inline(always)]
fn p3(dst: &mut [u8], val: usize) {
    dst[0] = (val >> 16) as u8;
    dst[1] = (val >> 8) as u8;
    dst[2] = val as u8;
}

fn gunzip(data: &[u8]) -> Vec<u8> {
    if data.len() < 18 {
        return Vec::new();
    }
    gz_decompress(data, 4 * 1024 * 1024)
}

pub fn js5zip(store: &Js5Store, count: usize) -> Vec<u8> {
    let mut entries: Vec<(String, Vec<u8>)> = Vec::new();
    for index in 1..count {
        for id in 0..store.count(index) {
            if let Some(blob) = store.read(index, id, false).filter(|d| !d.is_empty()) {
                entries.push((format!("{index}.{id}"), blob));
            }
        }
    }
    fflate(&entries)
}
