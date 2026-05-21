# rs-io — Protocol I/O, Jag, CRC & Compression

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
│  │  data: Vec<u8>     (fixed-capacity, no realloc)  │   │
│  │  pos: usize        (byte cursor)                 │   │
│  │  pos2: usize       (bit cursor)                  │   │
│  │                                                  │   │
│  │  Write: p1 p2 p3 p4 p8 pjstr pdata psmart pbit   │   │
│  │  Read:  g1 g2 g3 g4 g8 gjstr gdata gsmart gbit   │   │
│  │  ALT:   p1_alt1/2/3  p2_alt1  ip2_alt1           │   │
│  │         g1_alt1/2/3  g2_alt1  ig2  ig2_alt1       │   │
│  │  RSA:   rsaenc  rsadec (CRT optimized)           │   │
│  │  Bits:  bits()  bytes()  gbit(n)  pbit(n,v)      │   │
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
│                    │  Bundled C: bzip2 1.0.8 + zcrc32   │
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
| `p1_alt1(u8)`            | 1     | Negate             | Write `(-value) & 0xFF`   |
| `p1_alt2(u8)`            | 1     | 128 minus          | Write `(128 - value)`     |
| `p1_alt3(u8)`            | 1     | Plus 128           | Write `(value + 128)`     |
| `p2(u16)`                | 2     | Big-endian         | Unsigned 16-bit           |
| `p2_alt1(u16)`           | 2     | BE, lo+128         | `[hi, lo+128]`            |
| `ip2(u16)`               | 2     | Little-endian      | Unsigned 16-bit           |
| `ip2_alt1(u16)`          | 2     | LE, lo+128         | `[lo+128, hi]`            |
| `p3(i32)`                | 3     | Big-endian         | Lower 24 bits             |
| `p4(i32)`                | 4     | Big-endian         | Signed 32-bit             |
| `ip4(i32)`               | 4     | Little-endian      | Signed 32-bit             |
| `p8(i64)`                | 8     | Big-endian         | Signed 64-bit             |
| `pjstr(&str, u8)`        | var   | UTF-8 + terminator | Null/10-terminated string |
| `pdata(&[u8], off, len)` | var   | Raw copy           | Bulk data write           |

### Read Operations

All read methods advance `pos` by the number of bytes read.

| Method                       | Bytes | Returns  | Description           |
|------------------------------|-------|----------|-----------------------|
| `g1()`                       | 1     | `u8`     | Unsigned byte         |
| `g1s()`                      | 1     | `i8`     | Signed byte           |
| `g1_alt1()`                  | 1     | `u8`     | Negate: `(-val)`      |
| `g1_alt2()`                  | 1     | `u8`     | 128 minus: `(128-val)`|
| `g1_alt3()`                  | 1     | `u8`     | Minus 128: `(val-128)`|
| `g2()`                       | 2     | `u16`    | BE unsigned 16-bit    |
| `g2s()`                      | 2     | `i16`    | BE signed 16-bit      |
| `g2_alt1()`                  | 2     | `u16`    | BE, lo-128            |
| `ig2()`                      | 2     | `u16`    | LE unsigned 16-bit    |
| `ig2s()`                     | 2     | `i16`    | LE signed 16-bit      |
| `ig2_alt1()`                 | 2     | `u16`    | LE, lo-128            |
| `g3()`                       | 3     | `i32`    | BE 24-bit as i32      |
| `g4s()`                      | 4     | `i32`    | BE signed 32-bit      |
| `ig4s()`                     | 4     | `i32`    | LE signed 32-bit      |
| `g8s()`                      | 8     | `i64`    | BE signed 64-bit      |
| `gjstr(u8)`                  | var   | `String` | Read until terminator |
| `gdata(&mut [u8], off, len)` | var   | —        | Bulk data read        |

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
Encryption (rsaenc):
  plaintext → BigInt → plaintext^e mod n → [len_byte][ciphertext_bytes]

Decryption (rsadec, CRT optimized):
  [len_byte][ciphertext_bytes] → BigInt →
    m1 = cipher^dp mod p
    m2 = cipher^dq mod q
    h  = qinv * (m1 - m2) mod p
    plaintext = m2 + h * q
  → writes decrypted bytes from pos=0
```

CRT (Chinese Remainder Theorem) decryption is ~4x faster than naive `cipher^d mod n`.

---

### Smart Encoding

Variable-length integer encoding for space efficiency:

```
psmart / gsmart (unsigned):
┌──────────────────────┬────────────────────────────────┐
│ value 0..127         │ 1 byte: value as u8            │
│ value 128..32767     │ 2 bytes: (value + 32768) as u16│
└──────────────────────┴────────────────────────────────┘
  Discriminator: first byte < 128 → 1 byte, >= 128 → 2 bytes

psmarts / gsmarts (signed):
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
buf.psize2(start);     // writes (pos - start - 2) at start
```

| Method        | Header Size | Description                            |
|---------------|-------------|----------------------------------------|
| `psize1(pos)` | 1 byte      | Write `(self.pos - pos - 1) as u8`     |
| `psize2(pos)` | 2 bytes     | Write `(self.pos - pos - 2) as u16` BE |
| `psize4(pos)` | 4 bytes     | Write `(self.pos - pos - 4) as i32` BE |

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

Uses the standard zlib CRC-32 polynomial with a pre-computed 256-entry lookup table. Compiled from bundled C source (
`zcrc32.c` + `crctable.c`).

---

## Build System

```rust
// build.rs
fn main() {
    cc::Build::new()
        .files([
            "csrc/blocksort.c",    // BWT block sorting
            "csrc/huffman.c",      // Huffman coding
            "csrc/crctable.c",     // CRC-32 lookup table
            "csrc/randtable.c",    // Random table for bzip2
            "csrc/compress.c",     // bzip2 compression
            "csrc/decompress.c",   // bzip2 decompression
            "csrc/bzlib.c",        // bzip2 high-level API
            "csrc/zcrc32.c",       // CRC-32 computation
        ])
        .include("csrc")
        .opt_level(3)
        .define("BZ_NO_STDIO", None)
        .warnings(false)
        .compile("rsio_native");
}
```

---

## File Reference

```
rs-io/
  Cargo.toml              # deps: rs-crypto, num-bigint; build-dep: cc
  build.rs                # compiles bzip2 + crc32 from C source
  src/
    lib.rs                # pub mod bz2, crc, jag, packet
    packet.rs             # Packet struct, all encode/decode methods
    jag.rs                # JagFile archive handling
    bz2.rs                # bzip2 compress/decompress FFI wrappers
    crc.rs                # CRC-32 FFI wrapper
  csrc/
    bzlib.h               # bzip2 public API header
    bzlib_private.h       # bzip2 internal types and macros
    bzlib.c               # bzip2 high-level interface
    blocksort.c           # BWT block sorting algorithm
    huffman.c             # Huffman tree construction
    compress.c            # bzip2 compression core
    decompress.c          # bzip2 decompression core
    crctable.c            # CRC-32 pre-computed lookup table
    randtable.c           # Random table for bzip2 internals
    zcrc32.c              # CRC-32 computation
```

### Dependencies

| Crate        | Version   | Purpose                              |
|--------------|-----------|--------------------------------------|
| `rs-crypto`  | workspace | RSA key types for `rsaenc`/`rsadec`  |
| `num-bigint` | workspace | BigInt arithmetic for RSA operations |
| `cc`         | 1.2       | C compiler integration (build-time)  |
