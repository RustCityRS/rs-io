use crate::cp1252::{decode, encode_utf8_to_cp1252};
use num_bigint::{BigInt, Sign};
use rs_crypto::rsa::RsaKey;
use std::io::Error;

#[repr(u8)]
pub enum PacketFrame {
    Fixed = 0,
    VarByte = 1,
    VarShort = 2,
}

#[repr(u8)]
pub enum RsaFrame {
    Byte,
    Short,
}

#[repr(C)]
pub struct Packet {
    pub data: Vec<u8>,
    pub pos: usize,
}

impl Packet {
    pub fn new(len: usize) -> Packet {
        Packet {
            data: vec![0; len],
            pos: 0,
        }
    }

    pub const fn from(data: Vec<u8>) -> Packet {
        Packet { data, pos: 0 }
    }

    pub fn io(path: &str) -> Result<Packet, Error> {
        match std::fs::read(path) {
            Ok(bytes) => Ok(Packet::from(bytes)),
            Err(err) => Err(err),
        }
    }

    #[inline(always)]
    pub const fn remaining(&self) -> i32 {
        (self.len() - self.pos) as i32
    }

    #[inline(always)]
    pub const fn len(&self) -> usize {
        self.data.len()
    }

    #[inline(always)]
    pub const fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    #[inline(always)]
    pub const fn p1(&mut self, value: u8) {
        unsafe { *self.data.as_mut_ptr().add(self.pos) = value }
        self.pos += 1;
    }

    #[inline(always)]
    pub const fn p2(&mut self, value: u16) {
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(self.pos) as *mut u16,
                value.to_be(),
            )
        };
        self.pos += 2;
    }

    #[inline(always)]
    pub const fn ip2(&mut self, value: u16) {
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(self.pos) as *mut u16,
                value.to_le(),
            )
        };
        self.pos += 2;
    }

    #[inline(always)]
    pub const fn p3(&mut self, value: i32) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value >> 16) as u8 };
        unsafe { core::ptr::write_unaligned(ptr.add(1) as *mut u16, (value as u16).to_be()) };
        self.pos += 3;
    }

    #[inline(always)]
    pub const fn p4(&mut self, value: i32) {
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(self.pos) as *mut i32,
                value.to_be(),
            )
        };
        self.pos += 4;
    }

    #[inline(always)]
    pub const fn ip4(&mut self, value: i32) {
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(self.pos) as *mut i32,
                value.to_le(),
            )
        };
        self.pos += 4;
    }

    #[inline(always)]
    pub const fn p8(&mut self, value: i64) {
        unsafe {
            core::ptr::write_unaligned(
                self.data.as_mut_ptr().add(self.pos) as *mut i64,
                value.to_be(),
            )
        };
        self.pos += 8;
    }

    #[inline(always)]
    pub const fn p1_alt1(&mut self, value: u8) {
        unsafe { *self.data.as_mut_ptr().add(self.pos) = (-(value as i8)) as u8 }
        self.pos += 1;
    }

    #[inline(always)]
    pub const fn p1_alt2(&mut self, value: u8) {
        unsafe { *self.data.as_mut_ptr().add(self.pos) = 128u8.wrapping_sub(value) }
        self.pos += 1;
    }

    #[inline(always)]
    pub const fn p1_alt3(&mut self, value: u8) {
        unsafe { *self.data.as_mut_ptr().add(self.pos) = value.wrapping_add(128) }
        self.pos += 1;
    }

    #[inline(always)]
    pub const fn p2_alt1(&mut self, value: u16) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value >> 8) as u8 };
        unsafe { *ptr.add(1) = (value as u8).wrapping_add(128) };
        self.pos += 2;
    }

    #[inline(always)]
    pub const fn ip2_alt1(&mut self, value: u16) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value as u8).wrapping_add(128) };
        unsafe { *ptr.add(1) = (value >> 8) as u8 };
        self.pos += 2;
    }

    #[inline(always)]
    pub const fn p3_alt2(&mut self, value: u32) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value >> 16) as u8 };
        unsafe { *ptr.add(1) = value as u8 };
        unsafe { *ptr.add(2) = (value >> 8) as u8 };
        self.pos += 3;
    }

    #[inline(always)]
    pub const fn p4_alt1(&mut self, value: i32) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value >> 16) as u8 };
        unsafe { *ptr.add(1) = (value >> 24) as u8 };
        unsafe { *ptr.add(2) = value as u8 };
        unsafe { *ptr.add(3) = (value >> 8) as u8 };
        self.pos += 4;
    }

    #[inline(always)]
    pub const fn p4_alt2(&mut self, value: i32) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value >> 8) as u8 };
        unsafe { *ptr.add(1) = value as u8 };
        unsafe { *ptr.add(2) = (value >> 24) as u8 };
        unsafe { *ptr.add(3) = (value >> 16) as u8 };
        self.pos += 4;
    }

    #[inline(always)]
    pub const fn p4_alt3(&mut self, value: i32) {
        let ptr = unsafe { self.data.as_mut_ptr().add(self.pos) };
        unsafe { *ptr = (value >> 16) as u8 };
        unsafe { *ptr.add(1) = (value >> 24) as u8 };
        unsafe { *ptr.add(2) = value as u8 };
        unsafe { *ptr.add(3) = (value >> 8) as u8 };
        self.pos += 4;
    }

    #[inline(always)]
    pub const fn pjstr(&mut self, str: &str, terminator: u8) {
        let bytes = str.as_bytes();
        let len = bytes.len();
        let dst = unsafe { self.data.as_mut_ptr().add(self.pos) };
        if str.is_ascii() {
            unsafe { core::ptr::copy_nonoverlapping(bytes.as_ptr(), dst, len) };
            unsafe { *dst.add(len) = terminator };
            self.pos += len + 1;
        } else {
            let out = unsafe { encode_utf8_to_cp1252(bytes.as_ptr(), dst, len) };
            unsafe { *dst.add(out) = terminator };
            self.pos += out + 1;
        }
    }

    #[inline(always)]
    pub fn psmart1or2(&mut self, value: i32) {
        if (0..128).contains(&value) {
            self.p1(value as u8);
        } else if (0..32768).contains(&value) {
            self.p2((value + 32768) as u16);
        } else {
            panic!("Error psmart out of range: {value}");
        }
    }

    #[inline(always)]
    pub fn psmart1or2s(&mut self, value: i32) {
        if (-64..64).contains(&value) {
            self.p1((value + 64) as u8);
        } else if (-16384..16384).contains(&value) {
            self.p2((value + 49152) as u16);
        } else {
            panic!("Error psmarts out of range: {value}");
        }
    }

    #[inline(always)]
    pub fn psmart2or4(&mut self, value: i32) {
        if value < -1 {
            panic!("Error psmart2or4 out of range: {value}");
        } else if value == -1 {
            self.p2(32767);
        } else if value < 32767 {
            self.p2(value as u16);
        } else {
            self.p4(value);
            unsafe { *self.data.as_mut_ptr().add(self.pos - 4) |= 0x80 };
        }
    }

    #[inline(always)]
    pub const fn pdata(&mut self, src: &[u8], offset: usize, length: usize) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                src.as_ptr().add(offset),
                self.data.as_mut_ptr().add(self.pos),
                length,
            )
        };
        self.pos += length;
    }

    #[inline(always)]
    pub const fn g1(&mut self) -> u8 {
        self.pos += 1;
        unsafe { *self.data.as_ptr().add(self.pos - 1) }
    }

    #[inline(always)]
    pub const fn g1s(&mut self) -> i8 {
        self.pos += 1;
        (unsafe { *self.data.as_ptr().add(self.pos - 1) }) as i8
    }

    #[inline(always)]
    pub const fn g2(&mut self) -> u16 {
        let val = u16::from_be(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const u16)
        });
        self.pos += 2;
        val
    }

    #[inline(always)]
    pub const fn g2s(&mut self) -> i16 {
        let val = i16::from_be(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const i16)
        });
        self.pos += 2;
        val
    }

    #[inline(always)]
    pub const fn ig2(&mut self) -> u16 {
        let val = u16::from_le(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const u16)
        });
        self.pos += 2;
        val
    }

    #[inline(always)]
    pub const fn ig2s(&mut self) -> i16 {
        let val = i16::from_le(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const i16)
        });
        self.pos += 2;
        val
    }

    // java ints are always signed (java 8 added unsigned)
    #[inline(always)]
    pub const fn g3(&mut self) -> i32 {
        let ptr = unsafe { self.data.as_ptr().add(self.pos) };
        let val = ((unsafe { *ptr } as u32) << 16)
            | u16::from_be(unsafe { core::ptr::read_unaligned(ptr.add(1) as *const u16) }) as u32;
        self.pos += 3;
        val as i32
    }

    // java ints are always signed (java 8 added unsigned)
    #[inline(always)]
    pub const fn g4s(&mut self) -> i32 {
        let val = i32::from_be(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const i32)
        });
        self.pos += 4;
        val
    }

    // java ints are always signed (java 8 added unsigned)
    #[inline(always)]
    pub const fn ig4s(&mut self) -> i32 {
        let val = i32::from_le(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const i32)
        });
        self.pos += 4;
        val
    }

    // java longs are always signed (java 8 added unsigned)
    #[inline(always)]
    pub const fn g8s(&mut self) -> i64 {
        let val = i64::from_be(unsafe {
            core::ptr::read_unaligned(self.data.as_ptr().add(self.pos) as *const i64)
        });
        self.pos += 8;
        val
    }

    #[inline(always)]
    pub const fn g1_alt1(&mut self) -> u8 {
        self.pos += 1;
        (-(unsafe { *self.data.as_ptr().add(self.pos - 1) } as i8)) as u8
    }

    #[inline(always)]
    pub const fn g1_alt2(&mut self) -> u8 {
        self.pos += 1;
        128u8.wrapping_sub(unsafe { *self.data.as_ptr().add(self.pos - 1) })
    }

    #[inline(always)]
    pub const fn g1_alt3(&mut self) -> u8 {
        self.pos += 1;
        (unsafe { *self.data.as_ptr().add(self.pos - 1) }).wrapping_sub(128)
    }

    #[inline(always)]
    pub const fn g2_alt1(&mut self) -> u16 {
        let ptr = unsafe { self.data.as_ptr().add(self.pos) };
        let hi = unsafe { *ptr } as u16;
        let lo = (unsafe { *ptr.add(1) }).wrapping_sub(128) as u16;
        self.pos += 2;
        (hi << 8) | lo
    }

    #[inline(always)]
    pub const fn ig2_alt1(&mut self) -> u16 {
        let ptr = unsafe { self.data.as_ptr().add(self.pos) };
        let lo = (unsafe { *ptr }).wrapping_sub(128) as u16;
        let hi = unsafe { *ptr.add(1) } as u16;
        self.pos += 2;
        (hi << 8) | lo
    }

    #[inline(always)]
    pub const fn g4_alt1(&mut self) -> i32 {
        let ptr = unsafe { self.data.as_ptr().add(self.pos) };
        self.pos += 4;
        ((unsafe { *ptr } as i32) << 16)
            | ((unsafe { *ptr.add(1) } as i32) << 24)
            | (unsafe { *ptr.add(2) } as i32)
            | ((unsafe { *ptr.add(3) } as i32) << 8)
    }

    #[inline(always)]
    pub const fn g4_alt2(&mut self) -> i32 {
        let ptr = unsafe { self.data.as_ptr().add(self.pos) };
        self.pos += 4;
        ((unsafe { *ptr } as i32) << 8)
            | (unsafe { *ptr.add(1) } as i32)
            | ((unsafe { *ptr.add(2) } as i32) << 24)
            | ((unsafe { *ptr.add(3) } as i32) << 16)
    }

    #[inline(always)]
    pub fn gjstr(&mut self, terminator: u8) -> String {
        let pos = self.pos;
        while unsafe { *self.data.get_unchecked(self.pos) } != terminator {
            self.pos += 1;
        }
        let len = self.pos - pos;
        self.pos += 1;
        if len == 0 {
            return String::new();
        }
        decode(&self.data, pos, len)
    }

    #[inline(always)]
    pub const fn gsmart1or2(&mut self) -> i32 {
        if unsafe { *self.data.as_ptr().add(self.pos) } < 128 {
            self.g1() as i32
        } else {
            self.g2() as i32 - 32768
        }
    }

    #[inline(always)]
    pub const fn gsmart1or2s(&mut self) -> i32 {
        if unsafe { *self.data.as_ptr().add(self.pos) } < 128 {
            self.g1() as i32 - 64
        } else {
            self.g2() as i32 - 49152
        }
    }

    #[inline(always)]
    pub const fn gsmart2or4(&mut self) -> i32 {
        if unsafe { *self.data.as_ptr().add(self.pos) } < 128 {
            self.g2() as i32
        } else {
            self.g4s() & i32::MAX
        }
    }

    #[inline(always)]
    pub const fn gextended1or2(&mut self) -> i32 {
        let mut acc = 0;
        let mut val = self.gsmart1or2();
        while val == 32767 {
            acc += 32767;
            val = self.gsmart1or2();
        }
        acc + val
    }

    #[inline(always)]
    pub const fn gdata(&mut self, dest: &mut [u8], offset: usize, length: usize) {
        unsafe {
            core::ptr::copy_nonoverlapping(
                self.data.as_ptr().add(self.pos),
                dest.as_mut_ptr().add(offset),
                length,
            )
        };
        self.pos += length;
    }

    #[inline(always)]
    pub const fn psize1(&mut self, size: u8) {
        let pos = self.pos - size as usize - 1;
        unsafe { core::ptr::write_unaligned(self.data.as_mut_ptr().add(pos), size.to_be()) };
    }

    #[inline(always)]
    pub const fn psize2(&mut self, size: u16) {
        let pos = self.pos - size as usize - 2;
        unsafe {
            core::ptr::write_unaligned(self.data.as_mut_ptr().add(pos) as *mut u16, size.to_be())
        };
    }

    #[inline(always)]
    pub const fn psize4(&mut self, size: i32) {
        let pos = self.pos - size as usize - 4;
        unsafe {
            core::ptr::write_unaligned(self.data.as_mut_ptr().add(pos) as *mut i32, size.to_be())
        };
    }

    pub fn rsaenc(&mut self, frame: RsaFrame, rsa: &'static RsaKey) {
        let raw = BigInt::from_bytes_be(Sign::Plus, &self.data[..self.pos]);
        let enc = raw.modpow(&rsa.e, &rsa.n).to_bytes_be().1;

        self.pos = 0;
        match frame {
            RsaFrame::Byte => self.p1(enc.len() as u8),
            RsaFrame::Short => self.p2(enc.len() as u16),
        }
        self.pdata(&enc, 0, enc.len());
    }

    pub fn rsadec(&mut self, frame: RsaFrame, rsa: &'static RsaKey) {
        let len = match frame {
            RsaFrame::Byte => self.g1() as usize,
            RsaFrame::Short => self.g2() as usize,
        };
        let raw = BigInt::from_bytes_be(Sign::Plus, &self.data[self.pos..self.pos + len]);
        self.pos += len;

        let m1 = raw.modpow(&rsa.dp, &rsa.p);
        let m2 = raw.modpow(&rsa.dq, &rsa.q);
        let mut h = &rsa.qinv * (&m1 - &m2) % &rsa.p;
        if h.sign() == Sign::Minus {
            h += &rsa.p;
        }
        let dec = (m2 + h * &rsa.q).to_bytes_be().1;

        self.pos = 0;
        self.pdata(&dec, 0, dec.len());
        self.pos = 0;
    }
}

pub struct BitWriter {
    acc: u64,
    bits: u32,
    byte: usize,
}

impl BitWriter {
    #[allow(clippy::new_without_default)]
    #[inline(always)]
    pub const fn new() -> BitWriter {
        BitWriter {
            acc: 0,
            bits: 0,
            byte: 0,
        }
    }

    #[inline(always)]
    pub const fn reset(&mut self) {
        self.acc = 0;
        self.bits = 0;
        self.byte = 0;
    }

    #[inline(always)]
    pub const fn pbit<const N: usize>(&mut self, buf: &mut Packet, val: i32) {
        self.acc = (self.acc << N) | (val as u32 as u64 & ((1 << N) - 1));
        self.bits += N as u32;
        while self.bits >= 8 {
            self.bits -= 8;
            unsafe {
                *buf.data.as_mut_ptr().add(self.byte) = (self.acc >> self.bits) as u8;
            }
            self.byte += 1;
        }
    }

    #[inline(always)]
    pub const fn bitpos(&self) -> usize {
        (self.byte << 3) + self.bits as usize
    }

    #[inline(always)]
    pub const fn finish(&mut self, buf: &mut Packet) {
        if self.bits > 0 {
            unsafe {
                *buf.data.as_mut_ptr().add(self.byte) = (self.acc << (8 - self.bits)) as u8;
            }
            self.byte += 1;
            self.bits = 0;
        }
        buf.pos = self.byte;
    }
}

#[cfg(test)]
mod tests {
    use crate::Packet;
    use crate::packet::RsaFrame;
    use rs_crypto::rsa::{RsaKey, parse_rsa_key_from_pem};

    #[test]
    fn test_p1() {
        let mut packet: Packet = Packet::new(1);
        packet.p1(127);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(127, packet.g1s());
    }

    #[test]
    fn test_p2() {
        let mut packet: Packet = Packet::new(2);
        packet.p2(32767);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(32767, packet.g2s());
    }

    #[test]
    fn test_ip2() {
        let mut packet: Packet = Packet::new(2);
        packet.ip2(32767);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(32767, packet.ig2s());
    }

    #[test]
    fn test_p3() {
        let mut packet: Packet = Packet::new(3);
        packet.p3(16777215);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(16777215, packet.g3());
    }

    #[test]
    fn test_p4() {
        let mut packet: Packet = Packet::new(4);
        packet.p4(2147483647);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(2147483647, packet.g4s());
    }

    #[test]
    fn test_ip4() {
        let mut packet: Packet = Packet::new(4);
        packet.ip4(2147483647);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(2147483647, packet.ig4s());
    }

    #[test]
    fn test_p8() {
        let mut packet: Packet = Packet::new(8);
        packet.p8(9223372036854775807);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(9223372036854775807, packet.g8s());
    }

    #[test]
    fn test_pjstr() {
        let str: &str = "Hello World!";
        let mut packet: Packet = Packet::new(str.len() + 1);
        packet.pjstr(str, 0);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(str, packet.gjstr(0));
    }

    #[test]
    fn test_psmart_1() {
        let mut packet: Packet = Packet::new(1);
        packet.psmart1or2(69);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(69, packet.gsmart1or2());
    }

    #[test]
    fn test_psmart_2() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart1or2(3454);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(3454, packet.gsmart1or2());
    }

    #[test]
    fn test_psmarts_1() {
        let mut packet: Packet = Packet::new(1);
        packet.psmart1or2s(-13);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(-13, packet.gsmart1or2s());
    }

    #[test]
    fn test_psmarts_2() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart1or2s(-3454);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(-3454, packet.gsmart1or2s());
    }

    #[test]
    fn test_pdata() {
        let mut packet: Packet = Packet::new(3);
        let src: Vec<u8> = vec![1, 2, 3, 4, 5];
        packet.pdata(&src, 1, 3); // Copies bytes 2, 3, and 4 from `src` into the packet's buffer
        assert_eq!(packet.data, vec![2, 3, 4]);
    }

    #[test]
    fn test_g1() {
        let mut packet: Packet = Packet::new(1);
        packet.p1(255);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(255, packet.g1());
    }

    #[test]
    fn test_g1s() {
        let mut packet: Packet = Packet::new(1);
        packet.p1(127);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(127, packet.g1s());
    }

    #[test]
    fn test_g2() {
        let mut packet: Packet = Packet::new(2);
        packet.p2(65535);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(65535, packet.g2());
    }

    #[test]
    fn test_g2s() {
        let mut packet: Packet = Packet::new(2);
        packet.p2(32767);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(32767, packet.g2s());
    }

    #[test]
    fn test_ig2s() {
        let mut packet: Packet = Packet::new(2);
        packet.ip2(32767);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(32767, packet.ig2s());
    }

    #[test]
    fn test_g3() {
        let mut packet: Packet = Packet::new(3);
        packet.p3(16777215);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(16777215, packet.g3());
    }

    #[test]
    fn test_g4s() {
        let mut packet: Packet = Packet::new(4);
        packet.p4(2147483647);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(2147483647, packet.g4s());
    }

    #[test]
    fn test_ig4s() {
        let mut packet: Packet = Packet::new(4);
        packet.ip4(2147483647);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(2147483647, packet.ig4s());
    }

    #[test]
    fn test_g8s() {
        let mut packet: Packet = Packet::new(8);
        packet.p8(9223372036854775807);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(9223372036854775807, packet.g8s());
    }

    #[test]
    fn test_gjstr() {
        let str: &str = "Hello World!";
        let mut packet: Packet = Packet::new(str.len() + 1);
        packet.pjstr(str, 0);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(str, packet.gjstr(0));
    }

    #[test]
    fn test_gsmart_1() {
        let mut packet: Packet = Packet::new(1);
        packet.psmart1or2(69);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(69, packet.gsmart1or2());
    }

    #[test]
    fn test_gsmart_2() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart1or2(3454);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(3454, packet.gsmart1or2());
    }

    #[test]
    fn test_gsmarts_1() {
        let mut packet: Packet = Packet::new(1);
        packet.psmart1or2s(-13);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(-13, packet.gsmart1or2s());
    }

    #[test]
    fn test_gsmarts_2() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart1or2s(-3454);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(-3454, packet.gsmart1or2s());
    }

    #[test]
    fn test_psmart2or4_neg1() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart2or4(-1);
        packet.pos = 0;
        assert_eq!(32767, packet.gsmart2or4());
    }

    #[test]
    fn test_psmart2or4_small() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart2or4(100);
        packet.pos = 0;
        assert_eq!(100, packet.gsmart2or4());
    }

    #[test]
    fn test_psmart2or4_max_short() {
        let mut packet: Packet = Packet::new(2);
        packet.psmart2or4(32766);
        packet.pos = 0;
        assert_eq!(32766, packet.gsmart2or4());
    }

    #[test]
    fn test_psmart2or4_large() {
        let mut packet: Packet = Packet::new(4);
        packet.psmart2or4(50000);
        packet.pos = 0;
        assert_eq!(50000, packet.gsmart2or4());
    }

    #[test]
    #[should_panic]
    fn test_psmart2or4_out_of_range() {
        let mut packet: Packet = Packet::new(4);
        packet.psmart2or4(-2);
    }

    #[test]
    fn test_gdata() {
        let mut packet: Packet = Packet::from(vec![10, 20, 30, 40, 50]);
        let mut dest: Vec<u8> = vec![0u8; 3]; // Create a destination slice with enough space to copy 3 bytes
        packet.gdata(&mut dest, 1, 2); // Copy the first 3 bytes from the internal buffer to `dest`
        assert_eq!(dest, vec![0, 10, 20]); // Verify the correct data was copied
    }

    #[test]
    fn test_p1_alt1() {
        let mut packet = Packet::new(1);
        packet.p1_alt1(100);
        packet.pos = 0;
        assert_eq!(100, packet.g1_alt1());
    }

    #[test]
    fn test_p1_alt2() {
        let mut packet = Packet::new(1);
        packet.p1_alt2(100);
        packet.pos = 0;
        assert_eq!(100, packet.g1_alt2());
    }

    #[test]
    fn test_p1_alt3() {
        let mut packet = Packet::new(1);
        packet.p1_alt3(100);
        packet.pos = 0;
        assert_eq!(100, packet.g1_alt3());
    }

    #[test]
    fn test_p2_alt1() {
        let mut packet = Packet::new(2);
        packet.p2_alt1(32767);
        packet.pos = 0;
        assert_eq!(32767, packet.g2_alt1());
    }

    #[test]
    fn test_ip2_alt1() {
        let mut packet = Packet::new(2);
        packet.ip2_alt1(32767);
        packet.pos = 0;
        assert_eq!(32767, packet.ig2_alt1());
    }

    #[test]
    fn test_ig2() {
        let mut packet = Packet::new(2);
        packet.ip2(65535);
        packet.pos = 0;
        assert_eq!(65535, packet.ig2());
    }

    #[test]
    fn test_psize1() {
        let mut packet = Packet::new(2);
        packet.pos += 1;
        packet.p1(69);
        packet.psize1(1);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(1, packet.g1());
        assert_eq!(69, packet.g1());
    }

    #[test]
    fn test_psize2() {
        let mut packet = Packet::new(4);
        packet.pos += 2;
        packet.p2(65535);
        packet.psize2(2);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(2, packet.g2());
        assert_eq!(65535, packet.g2());
    }

    #[test]
    fn test_psize4() {
        let mut packet = Packet::new(8);
        packet.pos += 4;
        packet.p4(2147483647);
        packet.psize4(4);
        packet.pos = 0; // Resetting the packet for showing test case.
        assert_eq!(4, packet.g4s());
        assert_eq!(2147483647, packet.g4s());
    }

    #[test]
    fn test_rsaenc() {
        let pem = r#"
        -----BEGIN PRIVATE KEY-----
        MIIBcgIBADANBgkqhkiG9w0BAQEFAASCAVwwggFYAgEAAkEAiMOHSKWCKPcmHNw0
        C1aR19CXXe4OzbcXYJ5r+XHrP+cj750TDkaGgTc5dorZRy60bYv8wELBpfywXpMf
        Yy7qXQIhAIHzkLLPjKcDnuUHl1lR1aCxWoe/iz+ZyWaDQRjFD9lNAkBXH7BiBIth
        ch6/zx6HcVMkG3DDqibtsPnwahsr4HxOReq6T8NW6oBsvtKY04YTWQpT/eA4PDpB
        F1hRYpMkCSXlAiEA12bEXY1UEkjlCVg2WUOK14Ug0Kd8fKayvoFWOoUTahkCIQCi
        inQF+Sys+2JOzUx80OWHR/JqcF6eqc20u7PnfB1S5QIhAJIcknTm7h3OH3kbx5Dq
        AtzL3tEJyD83H3EMM8GRTmB9AiBb6wjlrcM3AIG08VSVyhxCTeUwS9ck5NaNV8LM
        LFx19QIgFdwct6Ho3H2nTDvthwudGhnE1rwbQEeTy9eOAMUMSSY=
        -----END PRIVATE KEY-----
        "#;
        let key: &'static RsaKey = Box::leak(Box::new(parse_rsa_key_from_pem(pem).unwrap()));
        let mut packet = Packet::new(65 + 1);
        packet.pjstr("hello", 0);
        packet.pjstr("world", 0);
        packet.rsaenc(RsaFrame::Byte, key); // Uses modulus and exponent from the private key to encrypt (client).
        let mut result = Packet::from(packet.data);
        result.rsadec(RsaFrame::Byte, key); // Uses CRT to decrypt (server).
        assert_eq!("hello", result.gjstr(0));
        assert_eq!("world", result.gjstr(0));
    }

    #[test]
    fn test_rsadec() {
        let pem = r#"
        -----BEGIN PRIVATE KEY-----
        MIIBcgIBADANBgkqhkiG9w0BAQEFAASCAVwwggFYAgEAAkEAiMOHSKWCKPcmHNw0
        C1aR19CXXe4OzbcXYJ5r+XHrP+cj750TDkaGgTc5dorZRy60bYv8wELBpfywXpMf
        Yy7qXQIhAIHzkLLPjKcDnuUHl1lR1aCxWoe/iz+ZyWaDQRjFD9lNAkBXH7BiBIth
        ch6/zx6HcVMkG3DDqibtsPnwahsr4HxOReq6T8NW6oBsvtKY04YTWQpT/eA4PDpB
        F1hRYpMkCSXlAiEA12bEXY1UEkjlCVg2WUOK14Ug0Kd8fKayvoFWOoUTahkCIQCi
        inQF+Sys+2JOzUx80OWHR/JqcF6eqc20u7PnfB1S5QIhAJIcknTm7h3OH3kbx5Dq
        AtzL3tEJyD83H3EMM8GRTmB9AiBb6wjlrcM3AIG08VSVyhxCTeUwS9ck5NaNV8LM
        LFx19QIgFdwct6Ho3H2nTDvthwudGhnE1rwbQEeTy9eOAMUMSSY=
        -----END PRIVATE KEY-----
        "#;
        let key: &'static RsaKey = Box::leak(Box::new(parse_rsa_key_from_pem(pem).unwrap()));
        let mut packet = Packet::new(65 + 1);
        packet.pjstr("hello", 0);
        packet.pjstr("world", 0);
        packet.rsaenc(RsaFrame::Byte, key); // Uses modulus and exponent from the private key to encrypt (client).
        let mut result = Packet::from(packet.data);
        result.rsadec(RsaFrame::Byte, key); // Uses CRT to decrypt (server).
        assert_eq!("hello", result.gjstr(0));
        assert_eq!("world", result.gjstr(0));
    }
}
