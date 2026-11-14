<div align="center">
<pre>
██████╗ ██╗   ██╗███████╗████████╗ ██████╗██╗████████╗██╗   ██╗
██╔══██╗██║   ██║██╔════╝╚══██╔══╝██╔════╝██║╚══██╔══╝╚██╗ ██╔╝
██████╔╝██║   ██║███████╗   ██║   ██║     ██║   ██║    ╚████╔╝ 
██╔══██╗██║   ██║╚════██║   ██║   ██║     ██║   ██║     ╚██╔╝  
██║  ██║╚██████╔╝███████║   ██║   ╚██████╗██║   ██║      ██║   
╚═╝  ╚═╝ ╚═════╝ ╚══════╝   ╚═╝    ╚═════╝╚═╝   ╚═╝      ╚═╝   
</pre>
</div>

----

# rs-io

Low-level binary I/O library for the RuneScape protocol. Provides fixed-size packet buffers with bit-level operations,
RSA encryption, bzip2 compression, CRC-32 checksums, and Jag archive file handling.

---

## Table of Contents

- [Architecture Overview](#architecture-overview)
- [Packet](#packet)
    - [Construction](#construction)
    - [Write Operations](#write-operations)
    - [Read Operations](#read-operations)
    - [Bit Operations](#bit-operations)
    - [RSA Operations](#rsa-operations)
    - [Smart Encoding](#smart-encoding)
    - [Size Headers](#size-headers)
- [Jag Archive Format](#jag-archive-format)
    - [Binary Layout](#binary-layout)
    - [JagFile API](#jagfile-api)
    - [Archive Assembly](#archive-assembly)
- [JS5 Cache Stores](#js5-cache-stores)
- [Bzip2 Compression](#bzip2-compression)
- [CRC-32](#crc-32)
- [Build System](#build-system)
- [File Reference](#file-reference)

---

## Architecture Overview

```
┌─────────────────────────────────────────────────────────┐
│                        rs-io                            │
│                                                         │
│  ┌──────────────────────────────────────────────────┐   │
│  │                    Packet                        │   │
│  │                                                  │   │
│  │  data: T (owned or borrowed, fixed length)       │   │
│  │  pos: usize (byte cursor)                        │   │
│  │                                                  │   │
│  │  Write: p1 p2 p3 p4 p8 pjstr pdata               │   │
│  │  Read: g1 g1s g2 g2s g3 g4s g8s gjstr            │   │
│  │  Smarts: psmart1or2 gsmart1or2 psmart2or4null    │   │
│  │  Varints: pvarint gmidivarlen                    │   │
│  │  ALT: p1_alt1/2/3 p2_alt2/3 p4_alt2/3            │   │
│  │  RSA: rsaencrypt rsadecrypt                      │   │
│  │  Bit output: BitWriter                           │   │
│  └──────────────────────────────────────────────────┘   │
│                                                         │
│  ┌──────────────┐  ┌──────────────┐  ┌──────────────┐   │
│  │   JagFile    │  │     bz2      │  │    crc32     │   │
│  │              │  │              │  │              │   │
│  │  Archive     │  │  compress()  │  │  getcrc()    │   │
│  │  read/write  │  │  decompress()│  │  (zlib poly) │   │
│  │  build/save  │  │  (FFI to C)  │  │  (FFI to C)  │   │
│  └──────────────┘  └──────────────┘  └──────────────┘   │
│                           │                    │        │
│                    ┌──────┴────────────────────┘        │
│                    │  Bundled C: bzip2 1.0.8 + zlib     │
│                    │  Compiled at -O3 via cc crate      │
│                    └────────────────────────────────────│
└─────────────────────────────────────────────────────────┘
```

---

## Packet

The core type for all binary protocol I/O. Fixed-capacity buffer with a position cursor. Uses unchecked indexing for
performance — callers must ensure bounds.

### Construction

```rust
// Allocate with exact capacity
let mut buf = Packet::new(256);

// Wrap existing bytes
let mut buf = Packet::from(vec![0x01, 0x02, 0x03]);

// Access
buf.len()    // data.len()
buf.pos      // current read/write position
```

### PacketFrame

```rust
pub enum PacketFrame {
    Fixed = 0,     // no size header
    VarByte = 1,   // 1-byte size prefix
    VarShort = 2,  // 2-byte BE size prefix
}
```

---

### Write Operations

All write methods advance `pos` by the number of bytes written.

| Method                   | Bytes | Encoding           | Description               |
|--------------------------|-------|--------------------|---------------------------|
| `p1(u8)`                 | 1     | Direct             | Write unsigned byte       |
| `p1_alt2(u8)`            | 1     | Negate             | Write `(-value) & 0xFF`   |
| `p1_alt3(u8)`            | 1     | 128 minus          | Write `(128 - value)`     |
| `p1_alt1(u8)`            | 1     | Plus 128           | Write `(value + 128)`     |
| `p2(u16)`                | 2     | Big-endian         | Unsigned 16-bit           |
| `p2_alt2(u16)`           | 2     | BE, lo+128         | `[hi, lo+128]`            |
| `p2_alt1(u16)`           | 2     | Little-endian      | Unsigned 16-bit           |
| `p2_alt3(u16)`           | 2     | LE, lo+128         | `[lo+128, hi]`            |
| `p3(i32)`                | 3     | Big-endian         | Lower 24 bits             |
| `p4(i32)`                | 4     | Big-endian         | Signed 32-bit             |
| `p4_alt1(i32)`           | 4     | Little-endian      | Signed 32-bit             |
| `p8(i64)`                | 8     | Big-endian         | Signed 64-bit             |
| `pjstr(&str, u8)`        | var   | UTF-8 + terminator | Null/10-terminated string |
| `pdata(&[u8], off, len)` | var   | Raw copy           | Bulk data write           |

### Read Operations

All read methods advance `pos` by the number of bytes read.

| Method                       | Bytes | Returns  | Description            |
|------------------------------|-------|----------|------------------------|
| `g1()`                       | 1     | `u8`     | Unsigned byte          |
| `g1s()`                      | 1     | `i8`     | Signed byte            |
| `g1_alt2()`                  | 1     | `u8`     | Negate: `(-val)`       |
| `g1_alt3()`                  | 1     | `u8`     | 128 minus: `(128-val)` |
| `g1_alt1()`                  | 1     | `u8`     | Minus 128: `(val-128)` |
| `g2()`                       | 2     | `u16`    | BE unsigned 16-bit     |
| `g2s()`                      | 2     | `i16`    | BE signed 16-bit       |
| `g2_alt2()`                  | 2     | `u16`    | BE, lo-128             |
| `g2_alt1()`                  | 2     | `u16`    | LE unsigned 16-bit     |
| `g2s_alt1()`                 | 2     | `i16`    | LE signed 16-bit       |
| `g2_alt3()`                  | 2     | `u16`    | LE, lo-128             |
| `g3()`                       | 3     | `i32`    | BE 24-bit as i32       |
| `g4s()`                      | 4     | `i32`    | BE signed 32-bit       |
| `g4s_alt1()`                 | 4     | `i32`    | LE signed 32-bit       |
| `g8s()`                      | 8     | `i64`    | BE signed 64-bit       |
| `gjstr(u8)`                  | var   | `String` | Read until terminator  |
| `gdata(&mut [u8], off, len)` | var   | —        | Bulk data read         |

---

### Bit Operations

Switch between byte mode and bit mode for sub-byte granularity:

```
Byte mode:  pos tracks byte position
Bit mode:   bit_pos tracks bit position (pos * 8)

┌─────────┬─────────┬─────────┬─────────┐
│ byte 0  │ byte 1  │ byte 2  │ byte 3  │
│76543210 │76543210 │76543210 │76543210 │
└─────────┴─────────┴─────────┴─────────┘
     ▲              ▲
     bit_pos=5      bit_pos=13
```

| Method           | Description                               |
|------------------|-------------------------------------------|
| `bits()`         | Enter bit mode: `bit_pos = pos << 3`      |
| `bytes()`        | Exit bit mode: `pos = (bit_pos + 7) >> 3` |
| `gbit(n) -> i32` | Read `n` bits, handles byte boundaries    |
| `pbit(n, value)` | Write `n` bits, handles byte boundaries   |

Bit operations handle spanning across byte boundaries automatically.

---

### RSA Operations

```
Encryption (rsaencrypt):
  plaintext → BigInt → plaintext^e mod n → [len_byte][ciphertext_bytes]

Decryption (rsadecrypt, CRT optimized):
  [len_byte][ciphertext_bytes] → BigInt →
    m1 = cipher^dp mod p
    m2 = cipher^dq mod q
    h  = qinv * (m1 - m2) mod p
    plaintext = m2 + h * q
  → writes decrypted bytes from pos=0
```

RSA arithmetic is provided by `rs-crypto::rsa::RsaKey`. `Packet` handles the `RsaFrame::Byte` or
`RsaFrame::Short` length prefix and the buffer cursor.

---

### Smart Encoding

Variable-length integer encoding for space efficiency:

```
psmart1or2 / gsmart1or2 (unsigned):
┌──────────────────────┬────────────────────────────────┐
│ value 0..127         │ 1 byte: value as u8            │
│ value 128..32767     │ 2 bytes: (value + 32768) as u16│
└──────────────────────┴────────────────────────────────┘
  Discriminator: first byte < 128 → 1 byte, >= 128 → 2 bytes

psmart1or2s / gsmart1or2s (signed):
┌──────────────────────┬────────────────────────────────┐
│ value -64..63        │ 1 byte: (value + 64) as u8     │
│ value -16384..16383  │ 2 bytes: (value + 49152) as u16│
└──────────────────────┴────────────────────────────────┘
```

---

### Size Headers

For variable-length packets, the size is written retroactively:

```rust
let start = buf.pos;
buf.pos += 2;          // reserve space for size
// ... write payload ...
let len = buf.pos - start - 2;
buf.psize2(len as u16); // writes the payload length at start
```

The argument is the payload length; these methods leave `pos` unchanged.

| Method              | Header Size | Header Position       |
|---------------------|-------------|-----------------------|
| `psize1(size: u8)`  | 1 byte      | `self.pos - size - 1` |
| `psize2(size: u16)` | 2 bytes, BE | `self.pos - size - 2` |
| `psize4(size: i32)` | 4 bytes, BE | `self.pos - size - 4` |

---

## Jag Archive Format

The Jag (Jagex Archive) format stores multiple named files in a single compressed archive.

### Binary Layout

```
┌────────────────────────────────────────────────────────────┐
│ Header                                                     │
│   unpacked_size: u24 (3 bytes, BE)                         │
│   packed_size:   u24 (3 bytes, BE)                         │
│                                                            │
│ If packed_size != unpacked_size:                           │
│   entire data section is bzip2 compressed                  │
├────────────────────────────────────────────────────────────┤
│ File Table                                                 │
│   file_count: u16 (2 bytes, BE)                            │
│                                                            │
│   For each file:                                           │
│     name_hash:      i32 (4 bytes, BE)                      │
│     unpacked_size:  u24 (3 bytes, BE)                      │
│     packed_size:    u24 (3 bytes, BE)                      │
├────────────────────────────────────────────────────────────┤
│ File Data                                                  │
│   For each file:                                           │
│     [packed_size bytes of data]                            │
│     (individually bzip2'd if not whole-archive compressed) │
└────────────────────────────────────────────────────────────┘
```

### Name Hashing

```rust
fn hash(name: &str) -> i32 {
    let mut hash: i32 = 0;
    for c in name.to_uppercase().chars() {
        hash = hash.wrapping_mul(61).wrapping_add(c as i32 - 32);
    }
    hash
}
```

Files are looked up by hash, not by name string.

### JagFile API

```rust
// Parse from bytes
let jag = JagFile::from(archive_bytes);

// Read a file by name
let packet: Option<Packet> = jag.read("config");

// Read by index
let packet: Option<Packet> = jag.get(0);

// Mutation
jag.write("newfile", & data);
jag.delete("oldfile");
jag.rename("old", "new");

// Build and save
let bytes: Vec<u8> = jag.build();
jag.save("output.jag");
```

### Archive Assembly

When building, the archive tries two compression strategies and picks the smaller result:

```
Strategy 1: Whole-archive compression
  ┌─header─┬─file table─┬─file1 raw─┬─file2 raw─┬─...─┐
  │        └──────────── bzip2 compressed ────────────┘  │

Strategy 2: Per-file compression
  ┌─header─┬─file table─┬─file1 bz2─┬─file2 bz2─┬─...─┐
  │        │             │ (each file individually)      │

Final output = min(strategy1.len(), strategy2.len())
```

---

## JS5 Cache Stores

`js5::Js5Store` reads and writes the sector stores used by `main_file_cache.dat` and
`main_file_cache.dat2`. `open(path)` detects the format; `create(path, archive_ids)`
creates or opens a dat2 store. Legacy archive 0 contains JAGs and its ondemand
archives contain gzip streams. Dat2 groups use JS5 compression containers.
Index files are held in memory and updated on writes; reopen the store after an external
writer changes its indexes. Data sectors remain on disk. Each sector header and payload
are read together, including caches whose final sector has no padding.

Raw reads return `Vec<u8>`. Group entries hold ranges into a shared `Arc<Vec<u8>>`;
`Entry::data()` borrows the file bytes. Single-stripe splitting takes ownership of the
original vector without copying its payload. Multi-stripe splitting assembles one shared
output buffer in linear passes over the chunk table. `compression::decompress` returns
`Cow<[u8]>`, borrowing uncompressed payloads and owning decompressed ones.

```rust,no_run
use rs_io::js5::Js5Store;

let mut cache = Js5Store::open("cache")?;
let raw = cache.read_raw_group_bytes(5, 0)?;
let group = cache.read_group(2, 0)?;
# Ok::<(), rs_io::js5::CacheError>(())
```

`js5::compression` handles containers, optional version trailers and XTEA.
`Container::data` excludes the version trailer and is the input for group CRCs,
Whirlpool hashes and network transfers. `js5::reference` reads and writes archive
reference tables. `encode_master_index` builds the Whirlpool-signed master-index container from
reference-table bytes and versions in archive order. Archive IDs and packing policies are supplied by the caller.

`Packet::gmidivarlen` and `Packet::pvarint` read and write unsigned integers with the most-significant
seven-bit group first, as used by MIDI and Jagex MIDI streams. Callers validate input boundaries.
`Packet<T = Vec<u8>>` also accepts borrowed byte slices and fixed arrays, so asset parsers and
packers reuse the same byte operations without copying buffers. Method names follow
[osrs-cache Packet.java](https://github.com/zwyz/osrs-cache/blob/master/src/main/java/osrs/util/Packet.java)
with lowercase Rust spelling, including `sizejstr`, `pvarint`, `gmidivarlen` and signed
reads such as `g1s`, `g2s`, `g4s` and `g8s`.

`zip::fflate` writes deterministic stored ZIPs from an iterator of names and
borrowed byte slices, without constructing an intermediate disk cache.

## Bzip2 Compression

Bundled bzip2 1.0.8 compiled from C source via FFI. Used for Jag archive compression and decompression.

```rust
// Decompress
let data = bz2_decompress(
& compressed,       // input bytes
unpacked_len,      // expected output size
true,              // prepend "BZh1" header before decompression
0,                 // byte offset into input
);

// Compress
let data = bz2_compress(
& raw,              // input bytes
true,              // strip "BZh1" header from output
);

// Compress with size prefix
let data = bz2_compress_with_size( & raw);
// output: [4-byte BE size][compressed data]
```

The `prepend_header` / `remove_header` options handle RuneScape's convention of stripping the bzip2 magic header ("
BZh1") from stored data to save 4 bytes per file.

### Bzip2 Pipeline

```
Compression:   raw → RLE → BWT → MTF → Huffman → output
Decompression: input → Huffman → MTF → BWT → RLE → raw

RLE  = Run-Length Encoding
BWT  = Burrows-Wheeler Transform (block sorting)
MTF  = Move-to-Front Transform
```

---

## CRC-32

```rust
let checksum: i32 = getcrc( & data, offset, length);
```

Uses IEEE CRC-32 via [`crc32fast`](https://github.com/srijs/rust-crc32fast), with runtime
CPU detection and a portable fallback. `length` is the exclusive end offset, so the
checked range is `data[offset..length]`. The returned `i32` preserves the checksum bits.

---

## Build System

Bundled zlib 1.2.3 preserves the original compressed bytes. Its gzip wrapper is disabled
with `NO_GZIP`; `gz.rs` supplies the header, footer and CRC around raw DEFLATE.

`build.rs` compiles the native sources with the `cc` crate at optimization level 3.
`BZ_NO_STDIO` disables bzip2 file I/O; the `bz-error-handler` feature supplies its error handler.

---

## File Reference

```
rs-io/
  Cargo.toml              # runtime dependencies; build-dependency: cc
  build.rs                # compiles bzip2 + zlib 1.2.3 from C source
  src/
    lib.rs                # public modules and Packet exports
    packet.rs             # Packet struct, all encode/decode methods
    jag.rs                # JagFile archive handling
    js5.rs                # dat/dat2 sector stores and group entries
    js5/compression.rs    # JS5 compression containers and XTEA
    js5/reference.rs      # archive reference tables and signed master indexes
    gz.rs                 # gzip compression
    zip.rs                # deterministic stored ZIP writer
    bz2.rs                # bzip2 compress/decompress FFI wrappers
    crc.rs                # IEEE CRC-32 via crc32fast
  csrc/
    bzlib.h               # bzip2 public API header
    bzlib_private.h       # bzip2 internal types and macros
    bzlib.c               # bzip2 high-level interface
    blocksort.c           # BWT block sorting algorithm
    huffman.c             # Huffman tree construction
    compress.c            # bzip2 compression core
    decompress.c          # bzip2 decompression core
    crctable.c            # bzip2 CRC lookup table
    randtable.c           # Random table for bzip2 internals
    zlib/                 # zlib 1.2.3 raw DEFLATE sources
```

### Dependencies

| Crate       | Version | Purpose                             |
|-------------|---------|-------------------------------------|
| `rs-crypto` | 0.3     | RSA operations, XTEA and Whirlpool  |
| `crc32fast` | 1       | Accelerated IEEE CRC-32             |
| `memchr`    | 2       | Packet string terminator scanning   |
| `lzma-rs`   | 0.3     | LZMA container compression          |
| `thiserror` | 2       | Cache errors                        |
| `tracing`   | 0.1     | Cache diagnostics                   |
| `cc`        | 1.2     | C compiler integration (build-time) |
