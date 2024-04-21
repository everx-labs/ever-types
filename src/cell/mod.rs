/*
* Copyright (C) 2019-2023 EverX. All Rights Reserved.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific EVERX DEV software governing permissions and
* limitations under the License.
*/

use crate::{error, fail, Sha256, types::{ExceptionCode, Result, UInt256, ByteOrderRead}, sha256_digest};
use std::{
    cmp::{max, min}, collections::HashSet, convert::TryInto, fmt::{self, Display, Formatter}, 
    io::{Read, Write, ErrorKind}, ops::{BitOr, BitOrAssign, Deref}, 
    sync::{Arc, Weak, atomic::{AtomicU64, Ordering}}
};
use num::{FromPrimitive, ToPrimitive};

pub const SHA256_SIZE: usize = 32;
pub const DEPTH_SIZE: usize = 2;
pub const MAX_REFERENCES_COUNT: usize = 4;
pub const MAX_DATA_BITS: usize = 1023;
pub const MAX_DATA_BYTES: usize = 128; // including tag
pub const MAX_BIG_DATA_BYTES: usize = 0xff_ff_ff; // 1024 * 1024 * 16 - 1
pub const MAX_LEVEL: usize = 3;
pub const MAX_LEVEL_MASK: u8 = 7;
pub const MAX_DEPTH: u16 = u16::MAX - 1;

// recommended maximum depth, this value is safe for stack. Use custom stack size
// to use bigger depths (see `test_max_depth`).
pub const MAX_SAFE_DEPTH: u16 = 2048; 

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy, Hash)]
#[derive(num_derive::FromPrimitive, num_derive::ToPrimitive)]
pub enum CellType {
    Unknown,
    #[default]
    Ordinary,
    PrunedBranch,
    LibraryReference,
    MerkleProof,
    MerkleUpdate,
    Big,
}

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy, Hash)]
pub struct LevelMask(u8);

impl LevelMask {
    pub fn with_level(level: u8) -> Self {
        LevelMask(match level {
            0 => 0,
            1 => 1,
            2 => 3,
            3 => 7,
            _ => {
                log::error!("{} {}", file!(), line!());
                0
            }
        })
    }

    pub fn is_valid(mask: u8) -> bool {
        mask <= 7
    }

    pub fn with_mask(mask: u8) -> Self {
        if Self::is_valid(mask) {
            LevelMask(mask)
        } else {
            log::error!("{} {}", file!(), line!());
            LevelMask(0)
        }
    }

    pub fn for_merkle_cell(children_mask: LevelMask) -> Self {
        LevelMask(children_mask.0 >> 1)
    }

    pub fn level(&self) -> u8 {
        if !Self::is_valid(self.0) {
            log::error!("{} {}", file!(), line!());
            255
        } else {
            // count of set bits (low three)
            (self.0 & 1) + ((self.0 >> 1) & 1) + ((self.0 >> 2) & 1)
        }
    }

    pub fn mask(&self) -> u8 {
        self.0
    }

    // if cell contains required hash() - it will be returned,
    // else = max avaliable, but less then index
    //
    // rows - cell mask
    //       0(0)  1(1)  2(3)  3(7)  columns - index(mask)
    // 000     0     0     0     0     cells - index(AND result)
    // 001     0     1(1)  1(1)  1(1)
    // 010     0     0(0)  1(2)  1(2)
    // 011     0     1(1)  2(3)  2(3)
    // 100     0     0(0)  0(0)  1(4)
    // 101     0     1(1)  0(0)  2(5)
    // 110     0     0(0)  1(2)  2(6)
    // 111     0     1(1)  2(3)  3(7)
    pub fn calc_hash_index(&self, mut index: usize) -> usize {
        index = min(index, 3);
        LevelMask::with_mask(self.0 & LevelMask::with_level(index as u8).0).level() as usize
    }

    pub fn calc_virtual_hash_index(&self, index: usize, virt_offset: u8) -> usize {
        LevelMask::with_mask(self.0 >> virt_offset)
            .calc_hash_index(index)
    }

    pub fn virtualize(&self, virt_offset: u8) -> Self {
        LevelMask::with_mask(self.0 >> virt_offset)
    }

    pub fn is_significant_index(&self, index: usize) -> bool {
        index == 0 || self.0 & LevelMask::with_level(index as u8).0 != 0
    }
}

impl BitOr for LevelMask {
    type Output = Self;

    // rhs is the "right-hand side" of the expression `a | b`
    fn bitor(self, rhs: Self) -> Self {
        LevelMask::with_mask(self.0 | rhs.0)
    }
}

impl BitOrAssign for LevelMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl Display for LevelMask {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{:03b}", self.0)
    }
}

impl TryFrom<u8> for CellType {
    type Error = crate::Error;
    fn try_from(num: u8) -> Result<CellType> {
        let typ = match num {
            1 => CellType::PrunedBranch,
            2 => CellType::LibraryReference,
            3 => CellType::MerkleProof,
            4 => CellType::MerkleUpdate,
            5 => CellType::Big,
            0xff => CellType::Ordinary,
            _ => fail!("unknown cell type {}", num)
        };
        Ok(typ)
    }
}

impl From<CellType> for u8 {
    fn from(ct: CellType) -> u8 {
        match ct {
            CellType::Unknown => 0,
            CellType::Ordinary => 0xff,
            CellType::PrunedBranch => 1,
            CellType::LibraryReference => 2,
            CellType::MerkleProof => 3,
            CellType::MerkleUpdate => 4,
            CellType::Big => 5,
        }
    }
}

impl fmt::Display for CellType {                                                       
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            CellType::Ordinary => "Ordinary",
            CellType::PrunedBranch => "Pruned branch",
            CellType::LibraryReference => "Library reference",
            CellType::MerkleProof => "Merkle proof",
            CellType::MerkleUpdate => "Merkle update",
            CellType::Big => "Big",
            CellType::Unknown => "Unknown",
        };
        f.write_str(msg)
    }
}

pub trait CellImpl: Sync + Send {
    fn data(&self) -> &[u8];
    fn raw_data(&self) -> Result<&[u8]>;
    fn cell_data(&self) -> &CellData;
    fn bit_length(&self) -> usize;
    fn references_count(&self) -> usize;
    fn reference(&self, index: usize) -> Result<Cell>;
    fn reference_repr_hash(&self, index: usize) -> Result<UInt256> {
        Ok(self.reference(index)?.hash(MAX_LEVEL))
    }
    fn cell_type(&self) -> CellType;
    fn level_mask(&self) -> LevelMask;
    fn hash(&self, index: usize) -> UInt256;
    fn depth(&self, index: usize) -> u16;
    fn store_hashes(&self) -> bool;

    fn level(&self) -> u8 {
        self.level_mask().level()
    }

    fn is_merkle(&self) -> bool {
        self.cell_type() == CellType::MerkleProof || self.cell_type() == CellType::MerkleUpdate
    }

    fn is_pruned(&self) -> bool {
        self.cell_type() == CellType::PrunedBranch
    }

    fn tree_bits_count(&self) -> u64 { 0 }

    fn tree_cell_count(&self) -> u64 { 0 }

    fn virtualization(&self) -> u8 { 0 }
}

pub struct Cell(Arc<dyn CellImpl>);

lazy_static::lazy_static!{
    pub(crate) static ref CELL_DEFAULT: Cell = Cell(Arc::new(DataCell::new()));
    static ref CELL_COUNT: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
    // static ref FINALIZATION_NANOS: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
}

impl Clone for Cell {
    fn clone(&self) -> Self {
        Cell::with_cell_impl_arc(self.0.clone())
    }
}

#[cfg(feature = "cell_counter")]
impl Drop for Cell {
    fn drop(&mut self) {
        CELL_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Cell {
    pub fn virtualize(self, offset: u8) -> Self {
        if self.level_mask().mask() == 0 {
            self
        } else {
            Cell::with_cell_impl(
                VirtualCell::with_cell_and_offset(self, offset)
            )
        }
    }

    pub fn virtualization(&self) -> u8 {
        self.0.virtualization()
    }

    pub fn with_cell_impl<T: 'static + CellImpl>(cell_impl: T) -> Self {
        let ret = Cell(Arc::new(cell_impl));
        #[cfg(feature = "cell_counter")]
        CELL_COUNT.fetch_add(1, Ordering::Relaxed);
        ret
    }

    pub fn with_cell_impl_arc(cell_impl: Arc<dyn CellImpl>) -> Self {
        let ret = Cell(cell_impl);
        #[cfg(feature = "cell_counter")]
        CELL_COUNT.fetch_add(1, Ordering::Relaxed);
        ret
    }

    pub fn cell_count() -> u64 {
        #[cfg(feature = "cell_counter")] {
            CELL_COUNT.load(Ordering::Relaxed)
        }
        #[cfg(not(feature = "cell_counter"))] {
            0
        }
    }

    pub fn cell_impl(&self) -> &Arc<dyn CellImpl> {
        &self.0
    }

    // pub fn finalization_nanos() -> u64 {
    //     FINALIZATION_NANOS.load(Ordering::Relaxed)
    // }

    pub fn reference(&self, index: usize) -> Result<Cell> {
        self.0.reference(index)
    }

    pub fn reference_repr_hash(&self, index: usize) -> Result<UInt256> {
        self.0.reference_repr_hash(index)
    }

    // TODO: make as simple clone
    pub fn clone_references(&self) -> SmallVec<[Cell;4]> {
        let count = self.0.references_count();
        let mut refs = SmallVec::with_capacity(count);
        for i in 0..count {
            refs.push(self.0.reference(i).unwrap())
        }
        refs
    }

    pub fn data(&self) -> &[u8] {
        self.0.data()
    }

    fn raw_data(&self) -> Result<&[u8]> {
        self.0.raw_data()
    }

    pub fn cell_data(&self) -> &CellData {
        self.0.cell_data()
    }

    pub fn bit_length(&self) -> usize {
        self.0.bit_length()
    }

    pub fn cell_type(&self) -> CellType {
        self.0.cell_type()
    }

    pub fn level(&self) -> u8 {
        self.0.level()
    }

    pub fn hashes_count(&self) -> usize {
        self.0.level() as usize + 1
    }

    pub fn count_cells(&self, max: usize) -> Result<usize> {
        let mut count = 0;
        let mut queue = vec!(self.clone());
        while let Some(cell) = queue.pop() {
            if count >= max {
                fail!("count exceeds max {}", max)
            }
            count += 1;
            let count = cell.references_count();
            for i in 0..count {
                queue.push(cell.reference(i)?);
            }
        }
        Ok(count)
    }

    pub fn level_mask(&self) -> LevelMask {
        self.0.level_mask()
    }

    pub fn references_count(&self) -> usize {
        self.0.references_count()
    }

    /// Returns cell's higher hash for given index (last one - representation hash)
    pub fn hash(&self, index: usize) -> UInt256 {
        self.0.hash(index)
    }

    /// Returns cell's depth for given index
    pub fn depth(&self, index: usize) -> u16 {
        self.0.depth(index)
    }

    /// Returns cell's hashes (representation and highers)
    pub fn hashes(&self) -> Vec<UInt256> {
        let mut hashes = Vec::new();
        let mut i = 0;
        while hashes.len() < self.level() as usize + 1 {
            if self.level_mask().is_significant_index(i) {
                hashes.push(self.hash(i))
            }
            i += 1;
        }
        hashes
    }

    /// Returns cell's depth (for current state and each level)
    pub fn depths(&self) -> Vec<u16> {
        let mut depths = Vec::new();
        let mut i = 0;
        while depths.len() < self.level() as usize + 1 {
            if self.level_mask().is_significant_index(i) {
                depths.push(self.depth(i))
            }
            i += 1;
        }
        depths
    }

    pub fn repr_hash(&self) -> UInt256 {
        self.0.hash(MAX_LEVEL)
    }

    pub fn repr_depth(&self) -> u16 {
        self.0.depth(MAX_LEVEL)
    }

    pub fn store_hashes(&self) -> bool {
        self.0.store_hashes()
    }

    #[allow(dead_code)]
    pub fn is_merkle(&self) -> bool {
        self.0.is_merkle()
    }

    #[allow(dead_code)]
    pub fn is_pruned(&self) -> bool {
        self.0.is_pruned()
    }

    pub fn to_hex_string(&self, lower: bool) -> String {
        let bit_length = self.bit_length();
        if bit_length % 8 == 0 {
            if lower {
                hex::encode(self.data())
            } else {
                hex::encode_upper(self.data())
            }
        } else {
            to_hex_string(self.data(), self.bit_length(), lower)
        }
    }

    fn print_indent(f: &mut fmt::Formatter, indent: &str, last_child: bool, first_line: bool) -> fmt::Result {
        let build = match (first_line, last_child) {
            (true, true) => " └─",
            (true, false) => " ├─",
            (false, true) => "   ",
            (false, false) => " │ "
        };
        write!(f, "{}{}", indent, build)
    }

    pub fn format_without_refs(&self, f: &mut fmt::Formatter, indent: &str, last_child: bool,
                               full: bool, root: bool) -> fmt::Result {

        if !root { Self::print_indent(f, indent, last_child, true)?; }

        if self.cell_type() == CellType::Big {
            let data_len = self.data().len();
            write!(f, "Big   bytes: {}", data_len)?;
            if data_len > 100 {
                writeln!(f)?;
                if !root { Self::print_indent(f, indent, last_child, false)?; }
            } else {
                write!(f, "   ")?;
            }
            if data_len < 128 {
                write!(f, "data: {}", hex::encode(self.data()))?;
            } else {
                write!(f, "data: {}...", hex::encode(&self.data()[..128]))?;
            }
            if full {
                writeln!(f)?;
                write!(f, "hash: {:x}", self.repr_hash())?;
            }
        } else {

            if full {
                write!(f, "{}   l: {:03b}   ", self.cell_type(), self.level_mask().mask())?;
            }

            write!(f, "bits: {}", self.bit_length())?;
            write!(f, "   refs: {}", self.references_count())?;

            if self.data().len() > 100 {
                writeln!(f)?;
                if !root { Self::print_indent(f, indent, last_child, false)?; }
            } else {
                write!(f, "   ")?;
            }

            write!(f, "data: {}", self.to_hex_string(true))?;

            if full {
                writeln!(f)?;
                if !root { Self::print_indent(f, indent, last_child, false)?; }
                write!(f, "hashes:")?;
                for h in self.hashes().iter() {
                    write!(f, " {:x}", h)?;
                }
                writeln!(f)?;
                if !root { Self::print_indent(f, indent, last_child, false)?; }
                write!(f, "depths:")?;
                for d in self.depths().iter() {
                    write!(f, " {}", d)?;
                }
            }
        }
        Ok(())
    }

    pub fn format_with_refs_tree(
        &self,
        f: &mut fmt::Formatter,
        mut indent: String,
        last_child: bool,
        full: bool,
        root: bool,
        remaining_depth: u16
    ) -> std::result::Result<String, fmt::Error> {
        self.format_without_refs(f, &indent, last_child, full, root)?;
        if remaining_depth > 0 {
            if !root {
                indent.push(' ');
                indent.push(if last_child {' '} else {'│'});
            }
            for i in 0..self.references_count() {
                let child = self.reference(i).unwrap();
                writeln!(f)?;
                indent = child.format_with_refs_tree(
                    f, indent, i == self.references_count() - 1, full, false, remaining_depth - 1)?;
            }
            if !root {
                indent.pop();
                indent.pop();
            }
        }
        Ok(indent)
    }
    fn tree_bits_count(&self) -> u64 { self.0.tree_bits_count() }

    fn tree_cell_count(&self) -> u64 { self.0.tree_cell_count() }
}

impl Deref for Cell {
    type Target = dyn CellImpl;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

#[cfg(test)]
impl Cell {
    pub fn read_from_file(file_name: &str) -> Self {
        let mut file = std::fs::File::open(file_name).unwrap();
        crate::BocReader::new().read(&mut file).unwrap().withdraw_single_root().unwrap()
    }
    pub fn write_to_file(&self, file_name: &str) {
        let mut file = std::fs::File::create(file_name).unwrap();
        crate::BocWriter::with_root(self).unwrap().write(&mut file).unwrap();
    }
}

impl Default for Cell {
    fn default() -> Self {
        CELL_DEFAULT.clone()
    }
}

impl PartialEq for Cell {
    fn eq(&self, other: &Cell) -> bool {
        self.repr_hash() == other.repr_hash()
    }
}

impl PartialEq<UInt256> for Cell {
    fn eq(&self, other_hash: &UInt256) -> bool {
        &self.repr_hash() == other_hash
    }
}

impl Eq for Cell {}

impl fmt::Debug for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.repr_hash())
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with_refs_tree(f, "".to_string(), true, f.alternate(), true,
                                   min(f.precision().unwrap_or(0), MAX_DEPTH as usize) as u16)?;
        Ok(())
    }
}

impl fmt::LowerHex for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex_string(true))
    }
}

impl fmt::UpperHex for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex_string(false))
    }
}

impl fmt::Binary for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let bitlen = self.bit_length();
        if bitlen % 8 == 0 {
            write!(
                f, 
                "{}", 
                self.data().iter()
                    .map(|x| format!("{:08b}", *x))
                    .collect::<Vec<_>>().join("")
            )
        } else {
            let data = self.data();
            for b in &data[..data.len() - 1] {
                write!(f, "{:08b}", b)?;
            }
            for i in (8 - (bitlen % 8)..8).rev() {
                write!(f, "{:b}", (data[data.len() - 1] >> i) & 1)?;
            }
            Ok(())
        }
    }
}

/// Calculates data's length in bits with respect to completion tag
pub fn find_tag(bitsting: &[u8]) -> usize {
    let mut length = bitsting.len() * 8;
    for x in bitsting.iter().rev() {
        if *x == 0 {
            length -= 8;
        } else {
            let mut skip = 1;
            let mut mask = 1;
            while (*x & mask) == 0 {
                skip += 1;
                mask <<= 1
            }
            length -= skip;
            break;
        }
    }
    length
}

pub fn append_tag(data: &mut SmallVec<[u8; 128]>, bits: usize) {
    let shift = bits % 8;
    if shift == 0 || data.is_empty() {
        data.truncate(bits / 8);
        data.push(0x80);
    } else {
        data.truncate(1 + bits / 8);
        let mut last_byte = data.pop().unwrap();
        if shift != 7 {
            last_byte >>= 7 - shift;
        }
        last_byte |= 1;
        if shift != 7 {
            last_byte <<= 7 - shift;
        }
        data.push(last_byte);
    }
}

// Cell layout:
// [D1] [D2] [data: 0..128 bytes] (hashes: 0..4 big endian u256) (depths: 0..4 big endian u16)
// first byte is so called desription byte 1:
// | level mask| store hashes| exotic| refs count|
// |      7 6 5|            4|      3|      2 1 0|
pub(crate) const LEVELMASK_D1_OFFSET: usize = 5;
pub(crate) const HASHES_D1_FLAG: u8 = 16;
pub(crate) const EXOTIC_D1_FLAG: u8 = 8;
pub(crate) const REFS_D1_MASK: u8 = 7;
pub(crate) const BIG_CELL_D1: u8 = 13; // 0b0000_1101
// next byte is desription byte 2 contains data size (in special encoding, see cell_data_len)

#[inline(always)]
pub(crate) fn calc_d1(
    level_mask: LevelMask,
    store_hashes: bool,
    cell_type: CellType,
    refs_count: usize
) -> u8 {
    (level_mask.mask() << LEVELMASK_D1_OFFSET) |
    (store_hashes as u8 * HASHES_D1_FLAG) |
    ((cell_type != CellType::Ordinary) as u8 * EXOTIC_D1_FLAG) |
    refs_count as u8
}

#[inline(always)]
pub(crate) fn calc_d2(data_bit_len: usize) -> u8{
    ((data_bit_len / 8) << 1) as u8 + (data_bit_len % 8 != 0) as u8
}

// A lot of helper-functions which incapsulates cell's layout.
// All this functions (except returning Result) can panic in case of going out of slice bounds.
#[inline(always)]
pub(crate) fn level(buf: &[u8]) -> u8 {
    level_mask(buf).level()
}

#[inline(always)]
pub(crate) fn level_mask(buf: &[u8]) -> LevelMask {
    debug_assert!(!buf.is_empty());
    LevelMask::with_mask(buf[0] >> LEVELMASK_D1_OFFSET)
}

#[inline(always)]
pub(crate) fn store_hashes(buf: &[u8]) -> bool {
    if is_big_cell(buf) {
        false
    } else {
        debug_assert!(!buf.is_empty());
        (buf[0] & HASHES_D1_FLAG) == HASHES_D1_FLAG
    }
}

#[inline(always)]
pub(crate) fn exotic(buf: &[u8]) -> bool {
    debug_assert!(!buf.is_empty());
    (buf[0] & EXOTIC_D1_FLAG) == EXOTIC_D1_FLAG
}

#[inline(always)]
pub(crate) fn cell_type(buf: &[u8]) -> CellType {
    // exotic?
    if !exotic(buf) { 
        // no
        CellType::Ordinary 
    } else if is_big_cell(buf) {
        CellType::Big
    } else {
        match cell_data(buf).first() {
            Some(byte) => CellType::try_from(*byte).unwrap_or(CellType::Unknown),
            None => {
                debug_assert!(false, "empty exotic cell data");
                CellType::Unknown
            }
        }
    }
}

#[inline(always)]
pub(crate) fn refs_count(buf: &[u8]) -> usize {
    if is_big_cell(buf) {
        0
    } else {
        debug_assert!(!buf.is_empty());
        (buf[0] & REFS_D1_MASK) as usize
    }
}

#[inline(always)]
pub(crate) fn is_big_cell(buf: &[u8]) -> bool {
    debug_assert!(!buf.is_empty());
    buf[0] == BIG_CELL_D1
}

#[inline(always)]
pub(crate) fn cell_data_len(buf: &[u8]) -> usize {
    if is_big_cell(buf) {
        debug_assert!(buf.len() >= 4);
        (buf[1] as usize) << 16 | (buf[2] as usize) << 8 | buf[3] as usize
    } else {
        debug_assert!(buf.len() >= 2);
        ((buf[1] >> 1) + (buf[1] & 1)) as usize
    }
}

#[inline(always)]
pub(crate) fn bit_len(buf: &[u8]) -> usize {
    if is_big_cell(buf) {
        debug_assert!(buf.len() >= 4);
        let bytes = (buf[1] as usize) << 16 | (buf[2] as usize) << 8 | buf[3] as usize;
        bytes * 8
    } else {
        debug_assert!(buf.len() >= 2);
        if buf[1] & 1 == 0 {
            (buf[1] >> 1) as usize * 8
        } else {
            find_tag(cell_data(buf))
        }
    }
}

#[inline(always)]
pub(crate) fn data_offset(buf: &[u8]) -> usize {
    if is_big_cell(buf) {
        4
    } else {
        2 + (store_hashes(buf) as usize) * hashes_count(buf) * (SHA256_SIZE + DEPTH_SIZE)
    }
}

#[inline(always)]
pub(crate) fn cell_data(buf: &[u8]) -> &[u8] {
    let data_offset = data_offset(buf);
    let cell_data_len = cell_data_len(buf);
    debug_assert!(buf.len() >= data_offset + cell_data_len);
    &buf[data_offset..data_offset + cell_data_len]
}

#[inline(always)]
pub(crate) fn hashes_count(buf: &[u8]) -> usize {
    // Hashes count depends on cell's type and level
    // - for pruned branch it's always 1
    // - for other types it's level + 1
    // To get cell type we need to calculate data's offset, but we can't do it without hashes_count.
    // So we will recognise pruned branch cell by some indirect signs - 0 refs and level != 0

    if exotic(buf) && refs_count(buf) == 0 && level(buf) != 0 {
        // pruned branch
        1
    } else {
        level(buf) as usize + 1
    }
}

#[inline(always)]
pub(crate) fn full_len(buf: &[u8]) -> usize {
    data_offset(buf) + cell_data_len(buf)
}

#[inline(always)]
pub(crate) fn hashes_len(buf: &[u8]) -> usize {
    hashes_count(buf) * SHA256_SIZE
}

#[allow(dead_code)]
#[inline(always)]
pub(crate) fn hashes(buf: &[u8]) -> &[u8] {
    debug_assert!(store_hashes(buf));
    let hashes_len = hashes_len(buf);
    debug_assert!(buf.len() >= 2 + hashes_len);
    &buf[2..2 + hashes_len]
}

#[inline(always)]
pub(crate) fn hash(buf: &[u8], index: usize) -> &[u8] {
    debug_assert!(store_hashes(buf));
    let offset = 2 + index * SHA256_SIZE;
    debug_assert!(buf.len() >= offset + SHA256_SIZE);
    &buf[offset..offset + SHA256_SIZE]
}

#[inline(always)]
pub(crate) fn depths_offset(buf: &[u8]) -> usize {
    2 + hashes_len(buf)
}

#[allow(dead_code)]
#[inline(always)]
pub(crate) fn depths_len(buf: &[u8]) -> usize {
    hashes_count(buf) * DEPTH_SIZE
}

#[allow(dead_code)]
#[inline(always)]
pub(crate) fn depths(buf: &[u8]) -> &[u8] {
    debug_assert!(store_hashes(buf));
    let offset = depths_offset(buf);
    let depths_len = depths_len(buf);
    debug_assert!(buf.len() >= offset + depths_len);
    &buf[offset..offset + depths_len]
}

#[inline(always)]
pub(crate) fn depth(buf: &[u8], index: usize) -> u16 {
    debug_assert!(store_hashes(buf));
    let offset = depths_offset(buf) + index * DEPTH_SIZE;
    let d = &buf[offset..offset + DEPTH_SIZE];
    ((d[0] as u16) << 8) | (d[1] as u16) 
}

fn build_big_cell_buf(
    data: &[u8], // without completion tag, all data will use as cell's data
    level_mask: u8,
    refs: usize,
    store_hashes: bool,
    hashes: Option<[UInt256; 4]>,
    depths: Option<[u16; 4]>
) -> Result<Vec<u8>> {
    if level_mask != 0 {
        fail!("Big cell must have level_mask 0");
    }
    if refs != 0 {
        fail!("Big cell must have 0 refs");
    }
    if store_hashes | hashes.is_some() | depths.is_some() {
        fail!("Big cell doesn't support stored hashes");
    }
    if data.len() > MAX_BIG_DATA_BYTES {
        fail!("Data is too big for big cell: {} > {}", data.len(), MAX_BIG_DATA_BYTES);
    }

    let full_len = 4 + data.len();
    let mut buf = Vec::with_capacity(full_len);
    buf.write_all(&[BIG_CELL_D1])?;
    buf.write_all(&data.len().to_be_bytes()[5..8])?;
    buf.write_all(data)?;

    Ok(buf)
}

fn build_cell_buf(
    cell_type: CellType,
    data: &[u8], // with completion tag
    level_mask: u8,
    refs: usize,
    store_hashes: bool,
    hashes: Option<[UInt256; 4]>,
    depths: Option<[u16; 4]>
) -> Result<Vec<u8>> {
    if cell_type == CellType::Big {
        fail!("CellType::Big is not supported, use build_big_cell_buf function instead");
    }
    if cell_type != CellType::Ordinary && data.len() == 1 {
        fail!("Exotic cell can't have empty data");
    }
    if data.len() > MAX_DATA_BYTES {
        fail!("Cell's data can't has {} length", data.len());
    }
    if refs > MAX_REFERENCES_COUNT {
        fail!("Cell can't has {} refs", refs);
    }
    if level_mask > MAX_LEVEL_MASK {
        fail!("Level mask can't be {}", level_mask);
    }

    let data_bit_len = find_tag(data);
    let data_len = (data_bit_len / 8) + (data_bit_len % 8 != 0) as usize;
    let level_mask = LevelMask::with_mask(level_mask);
    let level = level_mask.level();
    let hashes_count = if store_hashes {
        if cell_type == CellType::PrunedBranch { 1 } else { level as usize + 1 }
    } else {
        0
    };
    let full_length = 2 + data_len + hashes_count * (SHA256_SIZE + DEPTH_SIZE);

    debug_assert!(refs <= MAX_REFERENCES_COUNT);
    debug_assert!(data.len() <= MAX_DATA_BYTES);
    debug_assert!(hashes.is_some() == depths.is_some());
    debug_assert!(level_mask.mask() <= MAX_LEVEL_MASK);
    debug_assert!(data.len() >= data_len);

    let mut buf = vec![0; full_length];
    buf[0] = calc_d1(level_mask, store_hashes, cell_type, refs);
    buf[1] = calc_d2(data_bit_len);
    let mut offset = 2;
    if store_hashes {
        if hashes.is_none() || depths.is_none() {
            fail!("`hashes` or `depths` can't be none while `store_hashes` is true");
        }
        if let Some(hashes) = hashes {
            for hash in hashes.iter().take(hashes_count) {
                buf[offset..offset + SHA256_SIZE].copy_from_slice(hash.as_slice());
                offset += SHA256_SIZE;
            }
        }
        if let Some(depths) = depths {
            for depth in depths.iter().take(hashes_count) {
                buf[offset] = (depth >> 8) as u8;
                buf[offset + 1] = (depth & 0xff) as u8;
                offset += DEPTH_SIZE;
            }
        }
    }
    buf[offset..offset + data_len].copy_from_slice(&data[..data_len]);
    Ok(buf)
}

#[inline(always)]
fn set_hash(buf: &mut [u8], index: usize, hash: &[u8]) {
    debug_assert!(index <= level(buf) as usize);
    debug_assert!(hash.len() == SHA256_SIZE);
    let offset = 2 + index * SHA256_SIZE;
    debug_assert!(buf.len() >= offset + SHA256_SIZE);
    buf[offset..offset + SHA256_SIZE].copy_from_slice(hash);
}

#[inline(always)]
fn set_depth(buf: &mut [u8], index: usize, depth: u16) {
    debug_assert!(index <= level(buf) as usize);
    let offset = depths_offset(buf) + index * DEPTH_SIZE;
    debug_assert!(buf.len() >= offset + DEPTH_SIZE);
    buf[offset] = (depth >> 8) as u8;
    buf[offset + 1] = (depth & 0xff) as u8;
}

fn check_cell_buf(buf: &[u8], unbounded: bool) -> Result<()> {
    if buf.len() < 2 {
        fail!("Buffer is too small to read description bytes")
    }

    if is_big_cell(buf) {
        if buf.len() < 4 {
            fail!("Buffer is too small to read big cell's length (min 4 bytes)");
        }
        let full_data_len = full_len(buf);
        if buf.len() < full_data_len {
            fail!("buf is too small ({}) to fit this big cell ({})", buf.len(), full_data_len);
        }
        if !unbounded && buf.len() > full_data_len {
            fail!("buf is too big ({}) for this big cell ({})", buf.len(), full_data_len);
        }
    } else {

        let refs_count = refs_count(buf);
        if refs_count > MAX_REFERENCES_COUNT {
            fail!("Too big references count: {}", refs_count);
        }

        let full_data_len = full_len(buf);
        if buf.len() < full_data_len {
            fail!("Buffer is too small ({}) to fit cell ({})", buf.len(), full_data_len);
        }
        if !unbounded && buf.len() > full_data_len {
            log::warn!("Buffer is too big ({}), needed only {} to fit cell", buf.len(), full_data_len);
        }

        let cell_data = cell_data(buf);
        if exotic(buf) && cell_data.is_empty() {
            fail!("exotic cells must have non zero data length")
        }
        let data_bit_len = bit_len(buf);
        let expected_len = data_bit_len / 8 + (data_bit_len % 8 != 0) as usize;
        if cell_data.len() != expected_len {
            log::warn!(
                "Data len wrote in description byte 2 ({} bytes) does not correspond to real length \
                calculated by tag ({} bytes, {} bits, data: {})",
                cell_data.len(), expected_len, data_bit_len, hex::encode(cell_data)
            );
        }
    }

    Ok(())
}

#[derive(Clone, Debug, PartialEq)]
enum CellBuffer {
    Local(Vec<u8>),
    External{
        buf: Arc<Vec<u8>>,
        offset: usize,
    }
}

impl CellBuffer {
    pub fn data(&self) -> &[u8] {
        match &self {
            CellBuffer::Local(d) => d,
            CellBuffer::External{ buf, offset} => &buf[*offset..*offset + full_len(&buf[*offset..])]
        }
    }
    pub fn unbounded_data(&self) -> &[u8] {
        match &self {
            CellBuffer::Local(d) => d,
            CellBuffer::External{ buf, offset} => &buf[*offset..]
        }
    }
    pub fn unbounded_data_mut(&mut self) -> Result<&mut [u8]> {
        match self {
            CellBuffer::Local(d) => Ok(d),
            CellBuffer::External{ buf: _, offset: _} => fail!("Can't change extarnal buffer")
        }
    }
}

#[derive(Clone, Debug, PartialEq)]
pub struct CellData {
    buf: CellBuffer,
    hashes_depths: Vec<(UInt256, u16)>,
}

impl Default for CellData {
    fn default() -> Self {
        Self::new()
    }
}

impl CellData {
    pub fn new() -> Self {
        Self::with_params(
            CellType::Ordinary,
            &[80],
            0,
            0,
            false,
            None,
            None
        ).unwrap()
    }

    pub fn with_params(
        cell_type: CellType,
        data: &[u8], // with complition tag!
        level_mask: u8,
        refs: u8,
        store_hashes: bool,
        hashes: Option<[UInt256; 4]>,
        depths: Option<[u16; 4]>
    ) -> Result<Self> {
        let buffer = if cell_type == CellType::Big {
            build_big_cell_buf(data, level_mask, refs as usize, store_hashes, hashes.clone(), depths)?
        } else {
            build_cell_buf(cell_type, data, level_mask, refs as usize, store_hashes, hashes.clone(), depths)?
        };
        #[cfg(test)]
        check_cell_buf(&buffer[..], false)?;
        let hashes_count = if cell_type == CellType::PrunedBranch {
            1
        } else {
            level(&buffer) as usize + 1
        };
        let allocate_for_hashes = (!store_hashes) as usize * hashes_count;
        let mut hashes_depths = Vec::with_capacity(allocate_for_hashes);
        match (store_hashes, hashes, depths) {
            (true, _, _) => (),
            (_, None, None) => (),
            (false, Some(hashes), Some(depths)) => {
                for i in 0..hashes_count {
                    hashes_depths.push((hashes[i].clone(), depths[i]));
                }
            }
            _ => fail!("`hashes` and `depths` existence are not correspond each other")
        }
        Ok(Self{
            buf: CellBuffer::Local(buffer),
            hashes_depths
        })
    }

    pub fn with_external_data(buffer: &Arc<Vec<u8>>, offset: usize) -> Result<Self> {

        check_cell_buf(&buffer[offset..], true)?;

        let allocate_for_hashes = (!store_hashes(&buffer[offset..])) as usize * (level(&buffer[offset..]) as usize + 1);
        Ok(Self{
            buf: CellBuffer::External{
                buf: buffer.clone(),
                offset,
            },
            hashes_depths: Vec::with_capacity(allocate_for_hashes)
        })
    }

    pub fn with_raw_data(data: Vec<u8>) -> Result<Self> {

        check_cell_buf(&data, false)?;

        let allocate_for_hashes = (!store_hashes(&data)) as usize * (level(&data) as usize + 1);
        Ok(Self{
            buf: CellBuffer::Local(data),
            hashes_depths: Vec::with_capacity(allocate_for_hashes)
        })
    }

    pub fn raw_data(&self) -> &[u8] {
        self.buf.data()
    }

    pub fn cell_type(&self) -> CellType {
        cell_type(self.buf.unbounded_data())
    }

    // Might be without tag!!!
    pub fn data(&self) -> &[u8] {
        cell_data(self.buf.unbounded_data())
    }

    pub fn bit_length(&self) -> usize {
        bit_len(self.buf.unbounded_data())
    }

    pub fn level(&self) -> u8 {
        level(self.buf.unbounded_data())
    }

    pub fn level_mask(&self) -> LevelMask {
        level_mask(self.buf.unbounded_data())
    }

    pub fn store_hashes(&self) -> bool {
        store_hashes(self.buf.unbounded_data())
    }

    pub fn references_count(&self) -> usize {
        refs_count(self.buf.unbounded_data())
    }

    fn set_hash_depth(&mut self, index: usize, hash: &[u8], depth: u16) -> Result<()> {
        if self.store_hashes() {
            set_hash(self.buf.unbounded_data_mut()?, index, hash);
            set_depth(self.buf.unbounded_data_mut()?, index, depth);
        } else {
            debug_assert!(self.hashes_depths.len() == index);
            self.hashes_depths.push((hash.into(), depth));
        }
        Ok(())
    }

    pub fn hash(&self, index: usize) -> UInt256 {
        self.raw_hash(index).into()
    }

    pub fn raw_hash(&self, mut index: usize) -> &[u8] {
        index = self.level_mask().calc_hash_index(index);
        if self.cell_type() == CellType::PrunedBranch {
            // pruned cell stores all hashes (except representation) in data
            if index != self.level() as usize {
                let offset = 1 + 1 + index * SHA256_SIZE;
                return &self.data()[offset..offset + SHA256_SIZE]
            } else {
                index = 0;
            }
        }
        if self.store_hashes() {
            hash(self.buf.unbounded_data(), index)
        } else {
            self.hashes_depths[index].0.as_slice()
        }
    }

    pub fn depth(&self, mut index: usize) -> u16 {
        index = self.level_mask().calc_hash_index(index);
        if self.cell_type() == CellType::PrunedBranch {
            // pruned cell stores all depth except "representetion" in data
            if index != self.level() as usize {
                // type + level_mask + level * (hashes + depths)
                let offset = 1 + 1 + (self.level() as usize) * SHA256_SIZE + index * DEPTH_SIZE;
                let data = self.data();
                return ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
            } else {
                index = 0;
            }
        } 
        if self.store_hashes() {
            depth(self.buf.unbounded_data(), index)
        } else {
            self.hashes_depths[index].1
        }
    }

    /// Binary serialization of cell data.
    /// Strange things here were made for compatibility
    pub fn serialize<T: Write>(&self, writer: &mut T) -> Result<()> {
        writer.write_all(&[self.cell_type().to_u8().unwrap()])?;
        if self.cell_type() == CellType::Big {
            writer.write_all(&self.data().len().to_le_bytes()[0..3])?;
            writer.write_all(self.data())?;
        } else {
            let bitlen = self.bit_length();
            writer.write_all(&(bitlen as u16).to_le_bytes())?;
            writer.write_all(&self.data()[0..bitlen / 8 + (bitlen % 8 != 0) as usize])?;
            if bitlen % 8 == 0 {
                writer.write_all(&[0])?;// for compatibility
            }
            writer.write_all(&[self.level_mask().0])?;
            writer.write_all(&[self.store_hashes() as u8])?;
            let hashes_count = hashes_count(self.buf.unbounded_data());
            writer.write_all(&[1])?;
            writer.write_all(&[hashes_count as u8])?;
            if self.store_hashes() {
                for i in 0..hashes_count {
                    let hash = hash(self.buf.unbounded_data(), i);
                    writer.write_all(hash)?;
                }
            } else {
                debug_assert!(hashes_count == self.hashes_depths.len());
                for (hash, _depth) in &self.hashes_depths {
                    writer.write_all(hash.as_slice())?;
                }
            }
            writer.write_all(&[1])?;
            writer.write_all(&[hashes_count as u8])?;
            if self.store_hashes() {
                for i in 0..hashes_count {
                    let depth = depth(self.buf.unbounded_data(), i);
                    writer.write_all(&depth.to_le_bytes())?;
                }
            } else {
                for (_hash, depth) in &self.hashes_depths {
                    writer.write_all(&depth.to_le_bytes())?;
                }
            }
            writer.write_all(&[self.references_count() as u8])?;
        }
        Ok(())
    }

    /// Binary deserialization of cell data
    pub fn deserialize<T: Read>(reader: &mut T) -> Result<Self> {
        let cell_type: CellType = FromPrimitive::from_u8(reader.read_byte()?)
            .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?;
        if cell_type == CellType::Big {
            let mut data = vec![0; reader.read_le_uint(3)? as usize];
            reader.read_exact(&mut data)?;
            let mut cd = Self::with_params(cell_type, &data, 0, 0, false, None, None)?;
            let hash = sha256_digest(&data[..]);
            cd.set_hash_depth(0, &hash, 0)?;
            Ok(cd)
        } else {
            let bitlen = reader.read_le_u16()? as usize;
            let data_len = bitlen / 8 + (bitlen % 8 != 0) as usize;
            let data = if bitlen % 8 == 0 {
                let mut data = vec![0; data_len + 1];
                reader.read_exact(&mut data[..data_len])?;
                let _ = reader.read_byte()?; // for compatibility
                data[data_len] = 0x80;
                data
            } else {
                let mut data = vec![0; data_len];
                reader.read_exact(&mut data)?;
                data
            };
            let level_mask = reader.read_byte()?;
            let store_hashes = Self::read_bool(reader)?;

            let hashes = Self::read_short_array_opt(reader,
                                                    |reader| Ok(UInt256::from(reader.read_u256()?)))?;
            let depths = Self::read_short_array_opt(reader,
                                                    |reader| Ok(reader.read_le_u16()?))?;

            let refs = reader.read_byte()?;

            Self::with_params(cell_type, &data, level_mask, refs, store_hashes, hashes, depths)
        }
    }

    fn read_short_array_opt<R, T, F>(reader: &mut R, read_func: F) -> Result<Option<[T; 4]>>
        where
            R: Read,
            T: Default,
            F: Fn(&mut R) -> Result<T>
    {
        if Self::read_bool(reader)? {
            Ok(Some(Self::read_short_array(reader, read_func)?))
        } else {
            Ok(None)
        }
    }

    fn read_short_array<R, T, F>(reader: &mut R, read_func: F) -> Result<[T; 4]>
    where
        R: Read,
        T: Default,
        F: Fn(&mut R) -> Result<T>
    {
        let count = reader.read_byte()?;
        if count > 4 {
            fail!("count too big {}", count)
        }
        let mut result = [T::default(), T::default(), T::default(), T::default()];
        for i in 0..count {
            result[i as usize] = read_func(reader)?;
        }
        Ok(result)
    }

    fn read_bool<R: Read>(reader: &mut R) -> Result<bool> {
        match reader.read_byte()? {
            1 => Ok(true),
            0 => Ok(false),
            _ => fail!(std::io::Error::from(ErrorKind::InvalidData))
        }
    }
}

#[derive(Clone, Debug)]
pub struct DataCell {
    cell_data: CellData,
    references: Vec<Cell>, // TODO make array - you already know cells refs count, or may be vector
    tree_bits_count: u64,
    tree_cell_count: u64,
}

impl Default for DataCell {
    fn default() -> Self {
        Self::new()
    }
}

impl DataCell {
    pub fn new() -> Self {
        Self::with_refs_and_data(vec!(), &[0x80]).unwrap()
    }

    pub fn with_refs_and_data(
        references: Vec<Cell>,
        data: &[u8], // with completion tag (for big cell - without)!
    ) -> Result<DataCell> {
        Self::with_params(references, data, CellType::Ordinary, 0, None, None, None)
    }

    pub fn with_params(
        references: Vec<Cell>,
        data: &[u8], // with completion tag (for big cell - without)!
        cell_type: CellType,
        level_mask: u8,
        max_depth: Option<u16>,
        hashes: Option<[UInt256; 4]>,
        depths: Option<[u16; 4]>
    ) -> Result<DataCell> {
        assert_eq!(hashes.is_some(), depths.is_some());
        let store_hashes = hashes.is_some();
        let cell_data = CellData::with_params(cell_type, data, level_mask, references.len() as u8, 
            store_hashes, hashes, depths)?;
        Self::construct_cell(cell_data, references, max_depth)
    }

    pub fn with_external_data(
        references: Vec<Cell>,
        buffer: &Arc<Vec<u8>>,
        offset: usize,
        max_depth: Option<u16>,
    ) -> Result<DataCell> {
        let cell_data = CellData::with_external_data(buffer, offset)?;
        Self::construct_cell(cell_data, references, max_depth)
    }

    pub fn with_raw_data(
        references: Vec<Cell>,
        data: Vec<u8>,
        max_depth: Option<u16>,
    ) -> Result<DataCell> {
        let cell_data = CellData::with_raw_data(data)?;
        Self::construct_cell(cell_data, references, max_depth)
    }

    fn construct_cell(
        cell_data: CellData, 
        references: Vec<Cell>,
        max_depth: Option<u16>,
    ) -> Result<DataCell> {
        const MAX_56_BITS: u64 = 0x00FF_FFFF_FFFF_FFFFu64;
        let mut tree_bits_count = cell_data.bit_length() as u64;
        let mut tree_cell_count = 1u64;
        for reference in &references {
            tree_bits_count = tree_bits_count.saturating_add(reference.tree_bits_count());
            tree_cell_count = tree_cell_count.saturating_add(reference.tree_cell_count());
        }
        if tree_bits_count > MAX_56_BITS {
            tree_bits_count = MAX_56_BITS;
        }
        if tree_cell_count > MAX_56_BITS {
            tree_cell_count = MAX_56_BITS;
        }
        let mut cell = DataCell {
            cell_data,
            references,
            tree_bits_count,
            tree_cell_count,
        };
        cell.finalize(true, max_depth)?;
        Ok(cell)
    }

    fn finalize(&mut self, force: bool, max_depth: Option<u16>) -> Result<()> {
        if !force && self.store_hashes() {
            return Ok(());
        }

        //let now = std::time::Instant::now();

        // Check data size and references count

        let bit_len = self.bit_length();
        let cell_type = self.cell_type();
        let store_hashes = self.store_hashes();

        // println!("{} {}bits {:03b}", self.cell_type(), bit_len, self.level_mask().mask());

        match cell_type {
            CellType::PrunedBranch => {
                // type + level_mask + level * (hashes + depths)
                let expected = 8 * (1 + 1 + (self.level() as usize) * (SHA256_SIZE + DEPTH_SIZE));
                if bit_len != expected {
                    fail!("fail creating pruned branch cell: {} != {}", bit_len, expected)
                }
                if !self.references.is_empty() {
                    fail!("fail creating pruned branch cell: references {} != 0", self.references.len())
                }
                if self.data()[0] != u8::from(CellType::PrunedBranch) {
                    fail!("fail creating pruned branch cell: data[0] {} != {}", self.data()[0], u8::from(CellType::PrunedBranch))
                }
                if self.data()[1] != self.cell_data.level_mask().0 {
                    fail!("fail creating pruned branch cell: data[1] {} != {}", self.data()[1], self.cell_data.level_mask().0)
                }
                let level = self.level() as usize;
                if level == 0 {
                    fail!("Pruned branch cell must have non zero level");
                }
                let data = self.data();
                let mut offset = 1 + 1 + level * SHA256_SIZE;
                for _ in 0..level {
                    let depth = ((data[offset] as u16) << 8) | (data[offset + 1] as u16);
                    if depth > MAX_DEPTH {
                        fail!("Depth of pruned branch cell is too big");
                    }
                    offset += DEPTH_SIZE;
                }
                if store_hashes {
                    fail!("store_hashes flag is not supported for pruned branch cell");
                }
            }
            CellType::MerkleProof => {
                // type + hash + depth
                if bit_len != 8 * (1 + SHA256_SIZE + 2) {
                    fail!("fail creating merkle proof cell: bit_len {} != {}", bit_len, 8 * (1 + SHA256_SIZE + 2))
                }
                if self.references.len() != 1 {
                    fail!("fail creating merkle proof cell: references {} != 1", self.references.len())
                }
            }
            CellType::MerkleUpdate => {
                // type + 2 * (hash + depth)
                if bit_len != 8 * (1 + 2 * (SHA256_SIZE + 2)) {
                    fail!("fail creating merkle unpdate cell: bit_len {} != {}", bit_len, 8 * (1 + 2 * (SHA256_SIZE + 2)))
                }
                if self.references.len() != 2 {
                    fail!("fail creating merkle unpdate cell: references {} != 2", self.references.len())
                }
            }
            CellType::Ordinary => {
                if bit_len > MAX_DATA_BITS {
                    fail!("fail creating ordinary cell: bit_len {} > {}", bit_len, MAX_DATA_BITS)
                }
                if self.references.len() > MAX_REFERENCES_COUNT {
                    fail!("fail creating ordinary cell: references {} > {}", self.references.len(), MAX_REFERENCES_COUNT)
                }
            }
            CellType::LibraryReference => {
                if bit_len != 8 * (1 + SHA256_SIZE) {
                    fail!("fail creating libray reference cell: bit_len {} != {}", bit_len, 8 * (1 + SHA256_SIZE))
                }
                if !self.references.is_empty() {
                    fail!("fail creating libray reference cell: references {} != 0", self.references.len())
                }
            }
            CellType::Big => {
                // all checks were performed before finalization
            }
            CellType::Unknown => {
                fail!("fail creating unknown cell")
            }
        }

        // Check level

        let mut children_mask = LevelMask::with_mask(0);
        for child in self.references.iter() {
            children_mask |= child.level_mask();
        }
        let level_mask = match cell_type {
            CellType::Ordinary => children_mask,
            CellType::PrunedBranch => self.level_mask(),
            CellType::LibraryReference => LevelMask::with_mask(0),
            CellType::MerkleProof => LevelMask::for_merkle_cell(children_mask),
            CellType::MerkleUpdate => LevelMask::for_merkle_cell(children_mask),
            CellType::Big => LevelMask::with_mask(0),
            CellType::Unknown => fail!(ExceptionCode::RangeCheckError)
        };
        if self.cell_data.level_mask() != level_mask {
            fail!("Level mask mismatch {} != {}, type: {}", 
                self.cell_data.level_mask(), level_mask, cell_type);
        }

        // calculate hashes and depths

        let is_merkle_cell = self.is_merkle();
        let is_pruned_cell = self.is_pruned();

        let mut d1d2: [u8; 2] = self.raw_data()?[..2].try_into()?;
        
        // Hashes are calculated started from smallest indexes. 
        // Representation hash is calculated last and "includes" all previous hashes
        // For pruned branch cell only representation hash is calculated
        let mut hash_array_index = 0;
        for i in 0..=3 {

            // Hash is calculated only for "1" bits of level mask.
            // Hash for i = 0 is calculated anyway.
            // For example if mask = 0b010 i = 0, 2
            // for example if mask = 0b001 i = 0, 1
            // for example if mask = 0b011 i = 0, 1, 2
            if i != 0 && (is_pruned_cell || ((1 << (i - 1)) & level_mask.mask()) == 0) {
                continue;
            }

            let mut hasher = Sha256::new();
            let mut depth = 0;

            if cell_type == CellType::Big {
                // For big cell representation hash is calculated only from data
                hasher.update(self.data());
            } else {
                // descr bytes
                let level_mask = if is_pruned_cell {
                    self.level_mask()
                } else {
                    LevelMask::with_level(i as u8)
                };
                d1d2[0] = calc_d1(level_mask, false, cell_type, self.references.len());
                hasher.update(d1d2);

                // data
                if i == 0 {
                    let data_size = (bit_len / 8) + usize::from(bit_len % 8 != 0);
                    hasher.update(&self.data()[..data_size]);
                } else {
                    hasher.update(self.cell_data.raw_hash(i - 1));
                }

                // depth
                for child in self.references.iter() {
                    let child_depth = child.depth(i + is_merkle_cell as usize);
                    depth = max(depth, child_depth + 1);
                    let max_depth = max_depth.unwrap_or(MAX_DEPTH);
                    if depth > max_depth {
                        fail!("fail creating cell: depth {} > {}", depth, max_depth.min(MAX_DEPTH))
                    }
                    hasher.update(child_depth.to_be_bytes());
                }

                // hashes
                for child in self.references.iter() {
                    let child_hash = child.hash(i + is_merkle_cell as usize);
                    hasher.update(child_hash.as_slice());
                }
            }

            let hash = hasher.finalize();
            if store_hashes {
                let stored_depth = self.cell_data.depth(i);
                if depth != stored_depth {
                    fail!("Calculated depth is not equal stored one ({} != {})", depth, stored_depth);
                }
                let stored_hash = self.cell_data.raw_hash(i);
                if hash.as_slice() != stored_hash {
                    fail!("Calculated hash is not equal stored one");
                }
            } else {
                self.cell_data.set_hash_depth(hash_array_index, hash.as_slice(), depth)?;
                hash_array_index += 1;
            }
        }

        //FINALIZATION_NANOS.fetch_add(now.elapsed().as_nanos() as u64, Ordering::Relaxed);

        Ok(())
    }

    pub fn cell_data(&self) -> &CellData {
        &self.cell_data
    }
}

impl CellImpl for DataCell {
    fn data(&self) -> &[u8] {
        self.cell_data.data()
    }

    fn raw_data(&self) -> Result<&[u8]> {
        Ok(self.cell_data.raw_data())
    }

    fn cell_data(&self) -> &CellData {
        self.cell_data()
    }

    fn bit_length(&self) -> usize {
        self.cell_data.bit_length()
    }

    fn references_count(&self) -> usize {
        self.references.len()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        self.references.get(index).cloned().ok_or_else(|| error!(ExceptionCode::CellUnderflow))
    }

    fn cell_type(&self) -> CellType {
        self.cell_data.cell_type()
    }

    fn level_mask(&self) -> LevelMask {
        self.cell_data.level_mask()
    }

    fn hash(&self, index: usize) -> UInt256 {
        self.cell_data().hash(index)
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell_data().depth(index)
    }

    fn store_hashes(&self) -> bool {
        self.cell_data().store_hashes()
    }

    fn tree_bits_count(&self) -> u64 { self.tree_bits_count }

    fn tree_cell_count(&self) -> u64 { self.tree_cell_count }
}

#[derive(Clone)]
struct UsageCell {
    cell: Cell,
    visit_on_load: bool,
    visited: Weak<lockfree::map::Map<UInt256, Cell>>,
}

impl UsageCell {
    fn new(inner: Cell, visit_on_load: bool, visited: Weak<lockfree::map::Map<UInt256, Cell>>) -> Self {
        let cell = Self {
            cell: inner,
            visit_on_load,
            visited,
        };
        if visit_on_load {
            cell.visit();
        }
        cell
    }
    fn visit(&self) -> bool {
        if let Some(visited) = self.visited.upgrade() {
            visited.insert(self.cell.repr_hash(), self.cell.clone());
            return true;
        }
        false
    }
}

impl CellImpl for UsageCell {
    fn data(&self) -> &[u8] {
        if !self.visit_on_load {
            self.visit();
        }
        self.cell.data()
    }

    fn raw_data(&self) -> Result<&[u8]> {
        if !self.visit_on_load {
            self.visit();
        }
        self.cell.raw_data()
    }

    fn cell_data(&self) -> &CellData {
        if !self.visit_on_load {
            self.visit();
        }
        self.cell.cell_data()
    }

    fn bit_length(&self) -> usize {
        self.cell.bit_length()
    }

    fn references_count(&self) -> usize {
        self.cell.references_count()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        if self.visit_on_load && self.visited.upgrade().is_some() ||
            self.visit() {
            let cell = UsageCell::new(
                self.cell.reference(index)?, self.visit_on_load, self.visited.clone());
            Ok(Cell::with_cell_impl(cell))
        } else {
            self.cell.reference(index)
        }
    }

    fn cell_type(&self) -> CellType {
        self.cell.cell_type()
    }

    fn level_mask(&self) -> LevelMask {
        self.cell.level_mask()
    }

    fn hash(&self, index: usize) -> UInt256 {
        self.cell.hash(index)
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell.depth(index)
    }

    fn store_hashes(&self) -> bool {
        self.cell.store_hashes()
    }

    fn tree_bits_count(&self) -> u64 { self.cell.tree_bits_count() }

    fn tree_cell_count(&self) -> u64 { self.cell.tree_cell_count() }
}

#[derive(Clone)]
pub struct VirtualCell {
    offset: u8,
    cell: Cell,
}

impl VirtualCell {
    pub fn with_cell_and_offset(cell: Cell, offset: u8) -> Self {
        VirtualCell {
            offset,
            cell,
        }
    }
}

impl CellImpl for VirtualCell {
    fn data(&self) -> &[u8] {
        self.cell.data()
    }

    fn raw_data(&self) -> Result<&[u8]> {
        fail!("Virtual cell doesn't support raw_data()");
    }

    fn cell_data(&self) -> &CellData {
        self.cell.cell_data()
    }

    fn bit_length(&self) -> usize {
        self.cell.bit_length()
    }

    fn references_count(&self) -> usize {
        self.cell.references_count()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        Ok(self.cell.reference(index)?.virtualize(self.offset))
    }

    fn cell_type(&self) -> CellType {
        self.cell.cell_type()
    }

    fn level_mask(&self) -> LevelMask {
        self.cell.level_mask().virtualize(self.offset)
    }

    fn hash(&self, index: usize) -> UInt256 {
        self.cell.hash(self.level_mask().calc_virtual_hash_index(index, self.offset))
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell.depth(self.level_mask().calc_virtual_hash_index(index, self.offset))
    }

    fn store_hashes(&self) -> bool {
        self.cell.store_hashes()
    }

    fn tree_bits_count(&self) -> u64 { self.cell.tree_bits_count() }

    fn tree_cell_count(&self) -> u64 { self.cell.tree_cell_count() }

    fn virtualization(&self) -> u8 { self.offset }

}

#[derive(Default)]
pub struct UsageTree {
    root: Cell,
    visited: Arc<lockfree::map::Map<UInt256, Cell>>,
}

impl UsageTree {

    pub fn with_root(root: Cell) -> Self {
        let visited = Arc::new(lockfree::map::Map::new());
        let usage_cell = UsageCell::new(root, false, Arc::downgrade(&visited));
        let root = Cell::with_cell_impl_arc(Arc::new(usage_cell));
        Self { root, visited }
    }

    pub fn with_params(root: Cell, visit_on_load: bool) -> Self {
        let visited = Arc::new(lockfree::map::Map::new());
        let root = Cell::with_cell_impl_arc(Arc::new(
            UsageCell::new(root, visit_on_load, Arc::downgrade(&visited))
        ));
        Self { root, visited }
    }

    pub fn use_cell(&self, cell: Cell, visit_on_load: bool) -> Cell {
        let usage_cell = UsageCell::new(cell, visit_on_load, Arc::downgrade(&self.visited));
        usage_cell.visit();
        Cell::with_cell_impl(usage_cell)
    }

    pub fn use_cell_opt(&self, cell_opt: &mut Option<Cell>, visit_on_load: bool) {
        if let Some(cell) = cell_opt.as_mut() {
            *cell = self.use_cell(cell.clone(), visit_on_load);
        }
    }

    pub fn root_cell(&self) -> Cell {
        self.root.clone()
    }

    pub fn contains(&self, hash: &UInt256) -> bool {
        self.visited.get(hash).is_some()
    }

    pub fn build_visited_subtree(
        &self,
        is_include: &impl Fn(&UInt256) -> bool
    ) -> Result<HashSet<UInt256>> {
        let mut subvisited = HashSet::new();
        for guard in self.visited.iter() {
            if is_include(guard.key()) {
                self.visit_subtree(guard.val(), &mut subvisited)?
            }
        }
        Ok(subvisited)
    }

    fn visit_subtree(&self, cell: &Cell, subvisited: &mut HashSet<UInt256>) -> Result<()> {
        if subvisited.insert(cell.repr_hash()) {
            for i in 0..cell.references_count() {
                let child_hash = cell.reference_repr_hash(i)?;
                if let Some(guard) = self.visited.get(&child_hash) {
                    self.visit_subtree(guard.val(), subvisited)?
                }
            }
        }
        Ok(())
    }

    pub fn build_visited_set(&self) -> HashSet<UInt256> {
        let mut visited = HashSet::new();
        for guard in self.visited.iter() {
            visited.insert(guard.key().clone());
        }
        visited
    }
}

mod slice;

pub use self::slice::*;

pub mod builder;

pub use self::builder::*;

mod builder_operations;

pub use self::builder_operations::*;
use smallvec::SmallVec;

pub(crate) fn to_hex_string(data: impl AsRef<[u8]>, len: usize, lower: bool) -> String {
    if len == 0 {
        return String::new();
    }
    let mut result = if lower {
        hex::encode(data)
    } else {
        hex::encode_upper(data)
    };
    match len % 8 {
        0 => {
            result.pop();
            result.pop();
        }
        1..=3 => {
            result.pop();
            result.push('_')
        }
        4 => {
            result.pop();
        }
        _ => result.push('_')
    }
    result
}

pub fn create_cell(
    references: Vec<Cell>,
    data: &[u8], // with completion tag (for big cell - without)!
) -> Result<Cell> {
    Ok(Cell::with_cell_impl(DataCell::with_refs_and_data(references, data)?))
}

pub fn create_big_cell(data: &[u8]) -> Result<Cell> {
    Ok(Cell::with_cell_impl(
        DataCell::with_params(vec!(), data, CellType::Big, 0, None, None, None)?
    ))
}

#[cfg(test)]
#[path = "tests/test_cell.rs"]
mod tests;
