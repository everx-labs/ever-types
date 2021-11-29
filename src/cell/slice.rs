/*
* Copyright 2018-2020 TON DEV SOLUTIONS LTD.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

use std::cmp;
use std::convert::TryInto;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Bound, Range, RangeBounds};

use crate::{error, fail, cell::{BuilderData, Cell, CellType, IBitstring, LevelMask}, parse_slice_base};
use crate::types::{ExceptionCode, Result, UInt256};
use smallvec::SmallVec;

#[derive(Eq, Clone)]
pub struct SliceData {
    pub(super) cell: Cell,
    data_window: Range<usize>,
    references_window: Range<usize>,
}

impl PartialOrd for SliceData {
    fn partial_cmp(&self, other: &Self) -> Option<cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for SliceData {
    fn cmp(&self, other: &Self) -> cmp::Ordering {
        match self.remaining_bits().cmp(&other.remaining_bits()) {
            cmp::Ordering::Equal => {
                let vec1 = self.get_bytestring(0);
                let vec2 = other.get_bytestring(0);
                let len = vec1.len();
                for i in 0..len {
                    let ordering = vec1[i].cmp(&vec2[i]);
                    if ordering != cmp::Ordering::Equal {
                        return ordering
                    }
                }
                cmp::Ordering::Equal
            }
            ordering => ordering
        }
    }
}

impl Hash for SliceData {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.get_bytestring(0).hash(state);
        for i in self.references_window.clone() {
            state.write(self.cell.reference(i).unwrap().repr_hash().as_slice());
        }
    }
}
impl PartialEq for SliceData {
    fn eq(&self, slice: &SliceData) -> bool {
        let refs_count = self.remaining_references();
        let bit_len = self.remaining_bits();
        if (bit_len != slice.remaining_bits()) || 
           (refs_count != slice.remaining_references()) {
            return false;
        }
        let mut offset = 0;
        while (offset + 8) <= bit_len {
            if self.get_byte(offset).unwrap() != slice.get_byte(offset).unwrap() {
                return false;
            }
            offset += 8
        }
        if (bit_len > offset) && (self.get_bits(offset, bit_len - offset).unwrap() != slice.get_bits(offset, bit_len - offset).unwrap()) {
            return false;
        }
        for i in 0..refs_count {
            let ref1 = self.reference(i).unwrap();
            let ref2 = slice.reference(i).unwrap();
            if ref1 != ref2 {
                return false;
            } 
        }
        true
    }
}

impl Default for SliceData {
    fn default() -> Self {
        Self {
            cell: Cell::default(),
            data_window: 0..0,
            references_window: 0..0,
    }
}
}

// TBD
impl From<Vec<u8>> for SliceData {
    fn from(data: Vec<u8>) -> SliceData {
        let len = data.len();
        SliceData::from_raw(data, len * 8)
    }
}

// TBD
impl From<&[u8]> for SliceData {
    fn from(data: &[u8]) -> SliceData {
        let len = data.len();
        SliceData::from_raw(data.to_vec(), len * 8)
    }
}

// TBD
impl From<&Cell> for SliceData {
    fn from(cell: &Cell) -> SliceData {
        SliceData {
            cell: cell.clone(),
            references_window: 0..cell.references_count(),
            data_window: 0..cell.bit_length(),
        }
    }
}

impl From<Cell> for SliceData {
    fn from(cell: Cell) -> SliceData {
        SliceData {
            references_window: 0..cell.references_count(),
            data_window: 0..cell.bit_length(),
            cell
        }
    }
}

impl SliceData {
    // TODO: need to be const
    pub fn default() -> SliceData {
        Self {
            cell: Cell::default(),
            data_window: 0..0,
            references_window: 0..0,
        }
    }
    pub fn new_empty() -> SliceData {
        SliceData::default()
    }

    pub fn from_string(value: &str) -> Result<SliceData> {
        let vec = parse_slice_base(value, 0, 16).ok_or_else(|| error!(ExceptionCode::FatalError))?;
        Ok(BuilderData::with_bitstring(vec)?.into_cell()?.into())
    }

    pub fn remaining_references(&self) -> usize {
        if self.references_window.start > self.references_window.end {
            return 0;
        }
        self.references_window.end - self.references_window.start
    }

    pub fn remaining_bits(&self) -> usize {
        if self.data_window.start > self.data_window.end {
            return 0;
        }
        self.data_window.end - self.data_window.start
    }

    /// shrinks data_window: range - subrange of current window, returns prefix of suffix
    pub fn shrink_data<T: RangeBounds<usize>>(&mut self, range: T) -> SliceData {
        let data_len = self.remaining_bits();
        let start = match range.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start + 1,
            Bound::Unbounded => 0
        };
        let end = match range.end_bound() {
            Bound::Included(end) => end + 1,
            Bound::Excluded(end) => *end,
            Bound::Unbounded => data_len
        };
        if (start <= end) && (end <= data_len) {
            let mut slice = self.clone();
            if start != 0 { // return prefix
                slice.data_window.end = slice.data_window.start + start;
            } else { // return suffix
                slice.data_window.start += end;
            }
            slice.references_window = 0..0;
            self.data_window.end = self.data_window.start + end;
            self.data_window.start += start;
            slice
        } else {
            SliceData::default()
        }
    }

    /// shrinks references_window: range - subrange of current window, returns shrinked references
    pub fn shrink_references<T: RangeBounds<usize>>(&mut self, range: T) -> Vec<Cell> {
        let refs_count = self.remaining_references();
        let start = match range.start_bound() {
            Bound::Included(start) => *start,
            Bound::Excluded(start) => start + 1,
            Bound::Unbounded => 0
        };
        let end = match range.end_bound() {
            Bound::Included(end) => end + 1,
            Bound::Excluded(end) => *end,
            Bound::Unbounded => refs_count
        };

        let mut vec = vec![];
        if (start <= end) && (end <= refs_count) {
            (0..start).for_each(|i| vec.push(self.reference(i).unwrap()));
            (end..refs_count).for_each(|i| vec.push(self.reference(i).unwrap()));
            self.references_window.end = self.references_window.start + end;
            self.references_window.start += start;
        }
        vec
    }

    pub fn remaining_data(&self) -> BuilderData {
        let start = self.data_window.start / 8;
        let end = self.data_window.end / 8;
        if self.data_window.start >= self.data_window.end {
            return BuilderData::new()
        }
        let trailing = self.data_window.start % 8;
        if trailing == 0 {
            BuilderData::with_raw(
                SmallVec::from_slice(&self.cell.data()[start..=end]),
                self.remaining_bits()
            ).unwrap()
        } else if trailing + self.remaining_bits() <= 8 {
            let vec = vec![self.cell.data()[start] << trailing];
            BuilderData::with_raw(vec, self.remaining_bits()).unwrap()
        } else {
            let vec = vec![self.cell.data()[start] << trailing];
            let mut builder = BuilderData::with_raw(vec, 8 - trailing).unwrap();
            builder.append_raw(& self.cell.data()[start + 1..=end], trailing + self.remaining_bits() - 8).unwrap();
            builder
        }
    }

    pub fn shrink_by_remainder(&mut self, other: &SliceData) {
        if self.data_window.start <= other.data_window.start {
            self.data_window.end = other.data_window.start
        }
        if self.references_window.start <= other.references_window.start {
            self.references_window.end = other.references_window.start
        }
    }
    /// trim zeros from right to first one
    pub fn trim_right(&mut self) {
        for offset in (0..self.remaining_bits()).rev() {
            if self.get_bit_opt(offset) == Some(true) {
                self.data_window.end = self.data_window.start + offset;
                break
            }
        }
    }

    pub fn reference(&self, i: usize) -> Result<Cell> {
        Ok(self.reference_opt(i).ok_or(ExceptionCode::CellUnderflow)?)
    }

    pub fn reference_opt(&self, i: usize) -> Option<Cell> {
        if self.references_window.start + i < self.references_window.end {
            self.cell.reference(self.references_window.start + i).ok()
        } else {
            None
        }
    }

    pub fn storage(&self) -> &[u8] {
        self.cell.data()
    }
    /// returns internal cell regardless window settings
    pub fn cell(&self) -> &Cell {
        &self.cell
    }
    /// constructs new cell trunking original regarding window settings
    pub fn into_cell(self) -> Cell {
        if self.references_window.start == 0 && self.data_window.start == 0
            && self.references_window.end == self.cell.references_count()
            && self.data_window.end == self.cell.bit_length() {
            self.cell
        } else {
            BuilderData::from_slice(&self).into_cell().expect("it must not fail because builder made from cell cut by slice")
        }
    }

    pub fn checked_drain_reference(&mut self) -> Result<Cell> {
        if self.remaining_references() != 0 {
            Ok(self.drain_reference())
        } else {
            fail!(ExceptionCode::CellUnderflow)
        }
    }
    fn drain_reference(&mut self) -> Cell {
        self.references_window.start += 1;
        self.cell.reference(self.references_window.start - 1).unwrap()
    }

    pub fn get_references(&self) -> Range<usize> {
        self.references_window.clone()
    }

    pub fn undrain_reference(&mut self) {
        if self.references_window.start > 0 {
            self.references_window.start -= 1;
        }
    }

    /// Returns subslice of current slice
    pub fn get_slice(&self, offset: usize, size: usize) -> Result<SliceData> {
        if offset + size > self.remaining_bits() {
            fail!(ExceptionCode::CellUnderflow)
        }
        let mut slice = self.clone();
        slice.shrink_data(offset..offset + size);
        slice.shrink_references(..0);
        Ok(slice)
    }

    pub fn get_bit_opt(&self, offset: usize) -> Option<bool> {
        if offset >= self.remaining_bits() {
            None
        } else {
            let index = self.data_window.start + offset;
            let q = index / 8;
            let r = index % 8;
            Some((self.cell.data()[q] >> (7 - r) & 1) != 0)
        }
    }

    pub fn get_bit(&self, offset: usize) -> Result<bool> {
        self.get_bit_opt(offset).ok_or_else(|| error!(ExceptionCode::CellUnderflow))
    }

    pub fn get_bits(&self, offset: usize, bits: usize) -> Result<u8> {
        if offset + bits > self.remaining_bits() {
            fail!(ExceptionCode::CellUnderflow)
        }
        if bits == 0 || bits > 8 {
            fail!(ExceptionCode::RangeCheckError)
        }
        let index = self.data_window.start + offset;
        let q = index / 8;
        let r = index % 8;
        if r == 0 {
            Ok(self.cell.data()[q] >> (8 - r - bits))
        } else if bits <= (8 - r) {
            Ok(self.cell.data()[q] >> (8 - r - bits) & ((1 << bits) - 1))
        } else {
            let mut ret = 0u16;
            if q < self.cell.data().len() {
                ret |= (self.cell.data()[q] as u16) << 8;
            }
            if q < self.cell.data().len() - 1 {
                ret |= self.cell.data()[q + 1] as u16;
            }
            Ok(((ret >> (8 - r)) as u8 >> (8 - bits)) as u8)
        }
    }

    pub fn get_byte(&self, offset: usize) -> Result<u8> {
        self.get_bits(offset, 8)
    }

    pub fn get_next_bits(&mut self, bits: usize) -> Result<Vec<u8>> {
        if bits > self.remaining_bits() {
            fail!(ExceptionCode::CellUnderflow)
        }
        let bytes = bits / 8;
        let mut vec = (0..bytes).map(|i| self.get_byte(i * 8).unwrap()).collect::<Vec<_>>();
        let remainder = bits % 8;
        if remainder != 0 {
            let v = self.get_bits(bytes * 8, remainder)?;
            vec.push(v << (8 - remainder));
        }
        self.move_by(bits)?;
        Ok(vec)
    }

    pub fn get_next_bit(&mut self) -> Result<bool> {
        let bit = self.get_bit(0)?;
        self.move_by(1)?;
        Ok(bit)
    }

    pub fn get_next_bit_int(&mut self) -> Result<usize> {
        Ok(self.get_next_bit_opt().ok_or(ExceptionCode::CellUnderflow)?)
    }

    pub fn get_next_bit_opt(&mut self) -> Option<usize> {
        let bit = self.get_bit_opt(0)?;
        self.move_by(1).ok()?;
        Some(bit as usize)
    }

    pub fn get_next_byte(&mut self) -> Result<u8> {
        let value = self.get_byte(0)?;
        self.move_by(8)?;
        Ok(value)
    }

    pub fn get_next_int(&mut self, bits: usize) -> Result<u64> {
        if bits > self.remaining_bits() {
            fail!(ExceptionCode::CellUnderflow)
        }
        if bits == 0 {
            return Ok(0)
        }
        if bits > 64 {
            // get_next_int_bytes
            fail!("too many bits {} > 64", bits)
        }
        let mut value: u64 = 0;
        let bytes = bits / 8;
        for i in 0..bytes {
            value |= (self.get_byte(8 * i)? as u64) << (8 * (7 - i));
        }
        let remainder = bits % 8;
        if remainder != 0 {
            let r = self.get_bits(bytes * 8, remainder)? as u64;
            value |= r << (8 * (7 - bytes) + (8 - remainder));
        }
        self.move_by(bits)?;
        Ok(value >> (64 - bits))
    }

    pub fn get_next_size(&mut self, max_value: usize) -> Result<u64> {
        if max_value == 0 {
            return Ok(0);
        }
        let bits = 16 - (max_value as u16).leading_zeros() as usize;
        self.get_next_int(bits)
    }

    pub fn get_next_u16(&mut self) -> Result<u16> {
        let mut value: u16 = 0;
        for i in 0..2 {
            value |= (self.get_byte(8 * i)? as u16) << (8 * (1 - i));
        }
        self.move_by(16)?;
        Ok(value)
    }

    pub fn get_next_i16(&mut self) -> Result<i16> {
        let mut value: i16 = 0;
        for i in 0..2 {
            value |= (self.get_byte(8 * i)? as i16) << (8 * (1 - i));
        }
        self.move_by(16)?;
        Ok(value)
    }

    pub fn get_next_u32(&mut self) -> Result<u32> {
        let mut value: u32 = 0;
        for i in 0..4 {
            value |= (self.get_byte(8 * i)? as u32) << (8 * (3 - i));
        }
        self.move_by(32)?;
        Ok(value)
    }

    pub fn get_next_i32(&mut self) -> Result<i32> {
        let mut value: i32 = 0;
        for i in 0..4 {
            value |= (self.get_byte(8 * i)? as i32) << (8 * (3 - i));
        }
        self.move_by(32)?;
        Ok(value)
    }

    pub fn get_next_u64(&mut self) -> Result<u64> {
        let mut value: u64 = 0;
        for i in 0..8 {
            value |= (self.get_byte(8 * i)? as u64) << (8 * (7 - i));
        }
        self.move_by(64)?;
        Ok(value)
    }

    pub fn get_next_u128(&mut self) -> Result<u128> {
        let mut value: u128 = 0;
        for i in 0..16 {
            value |= (self.get_byte(8 * i)? as u128) << (8 * (15 - i));
        }
        self.move_by(128)?;
        Ok(value)
    }

    pub fn get_next_hash(&mut self) -> Result<UInt256> {
        let hash: [u8; 32] = self.get_next_bytes(32)?.try_into().unwrap();
        Ok(UInt256::from(hash))
    }

    pub fn get_next_bytes(&mut self, bytes: usize) -> Result<Vec<u8>> {
        if bytes * 8 > self.remaining_bits() {
            fail!(ExceptionCode::CellUnderflow)
        }
        Ok((0..bytes).map(|_| self.get_next_byte().unwrap()).collect::<Vec<_>>())
    }

    pub fn get_bytestring(&self, mut offset: usize) -> Vec<u8> {
        let mut ret = Vec::new();
        while (self.data_window.start + offset + 8) <= self.data_window.end {
            ret.push(self.get_byte(offset).unwrap());
            offset += 8
        }
        if (self.data_window.start + offset) < self.data_window.end {
            let remainder = self.data_window.end - self.data_window.start - offset;
            ret.push(self.get_bits(offset, remainder).unwrap() << (8 - remainder));
        }
        ret
    }

    /// Returns subslice of current slice and moves pointer
    pub fn get_next_slice(&mut self, size: usize) -> Result<SliceData> {
        let slice = self.get_slice(0, size)?;
        self.shrink_data(size..);
        Ok(slice)
    }

    pub fn is_empty(&self) -> bool {
        self.data_window.start >= self.data_window.end
    }

    pub fn move_by(&mut self, offset: usize) -> Result<()> {
        if self.data_window.start + offset <= self.data_window.end {
            self.data_window.start += offset;
            Ok(())
        } else {
            fail!(ExceptionCode::CellUnderflow)
        }
    }

    pub fn pos(&self) -> usize {
        self.data_window.start
    }

    /// returns false if prefix is not fully in self
    pub fn erase_prefix(&mut self, prefix: &SliceData) -> bool {
        if self.is_empty() || (self.remaining_bits() < prefix.remaining_bits()) {
            false
        } else if prefix.is_empty() {
            true
        } else if *self == *prefix {
            self.shrink_data(0..0);
            true
        } else {
            match SliceData::common_prefix(self, prefix) {
                (_, _, Some(_)) => false, // prefix should be fully in self
                (_, Some(remainder), _) => {
                    *self = remainder;
                    true
                }
                (_, None, _) => {
                    log::warn!(target: "tvm", "unreachable in erase_prefix {} {}", self, prefix);
                    self.shrink_data(0..0);
                    true
                },
            }
        }
    }

    pub fn common_prefix(a: &SliceData, b: &SliceData) -> (Option<SliceData>, Option<SliceData>, Option<SliceData>) {
        let mut offset = 0;
        let max_possible_prefix_length_in_bits = cmp::min(a.remaining_bits(), b.remaining_bits());
        while (offset + 8) <= max_possible_prefix_length_in_bits {
            if a.get_byte(offset).unwrap() != b.get_byte(offset).unwrap() {
                break;
            }
            offset += 8;
        }
        let (mut prefix, mut rem_a, mut rem_b);
        if offset >= max_possible_prefix_length_in_bits {
            if a.remaining_bits() < b.remaining_bits() {
                prefix = a.clone();
            } else {
                prefix = b.clone();
            }
            prefix.shrink_references(0..0);
            rem_a = a.clone();
            rem_a.shrink_data((max_possible_prefix_length_in_bits)..);
            rem_b = b.clone();
            rem_b.shrink_data((max_possible_prefix_length_in_bits)..);
        } else {
            let mut last_bits_len = max_possible_prefix_length_in_bits - offset;
            if last_bits_len > 8 {
                last_bits_len = 8;
            }
            let a_bits = a.get_bits(offset, last_bits_len).unwrap();
            let b_bits = b.get_bits(offset, last_bits_len).unwrap();
            let diff = (a_bits ^ b_bits) as u8;
            let mut diff = diff.leading_zeros() as usize;
            diff -= 8 - last_bits_len;
            let diff = cmp::min(diff, last_bits_len);

            prefix = a.clone();
            let end = offset + diff;
            prefix.shrink_data(..end);
            prefix.shrink_references(0..0);
            rem_a = a.clone();
            rem_a.shrink_data(offset + diff..);
            rem_b = b.clone();
            rem_b.shrink_data(offset + diff..);
        }

        (
            if prefix.remaining_bits() > 0 { Some(prefix) } else { None },
            if rem_a.remaining_bits() > 0 { Some(rem_a) } else { None },
            if rem_b.remaining_bits() > 0 { Some(rem_b) } else { None },
        )
    }

    pub fn overwrite_prefix(&mut self, prefix: &SliceData) -> Result<()> {
        if prefix.is_empty() {
            Ok(())

        } else if self.remaining_bits() < prefix.remaining_bits() {
            fail!("Prefix should be fully in self")
        } else {
            let mut builder = BuilderData::from_slice(prefix);
            self.move_by(prefix.remaining_bits())?;
            builder.append_bytestring(self)?;
            *self = builder.into_cell()?.into();
            Ok(())
        }
    }

    pub fn cell_type(&self) -> CellType {
        self.cell.cell_type()
    }
    pub fn level(&self) -> u8 {
        self.cell.level()
    }
    pub fn level_mask(&self) -> LevelMask {
        self.cell.level_mask()
    }

    /// Returns cell's higher hash for given index (last one - representation hash)
    pub fn hash(&self, index: usize) -> UInt256 {
        Cell::hash(&self.cell, index)
    }

    /// Returns cell's depth for given index
    pub fn depth(&self, index: usize) -> u16 {
        self.cell.depth(index)
    }

    /// Returns cell's hashes (representation and highers)
    pub fn hashes(&self) -> Vec<UInt256> {
        self.cell.hashes()
    }

    /// Returns cell's depth (for current state and each level)
    pub fn depths(&self) -> Vec<u16> {
        self.cell.depths()
    }

    // #[deprecated]
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex_string(&self) -> String { self.as_hex_string() }

    pub fn as_hex_string(&self) -> String {
        let len = self.remaining_bits();
        let mut data: SmallVec<[u8; 128]> = self.get_bytestring(0).into();
        super::append_tag(&mut data, len);
        super::to_hex_string(data.as_slice(), len, true)
    }

    pub fn is_full_cell_slice(&self) -> bool {
        self.data_window.start == 0 && 
        self.data_window.end == self.cell.bit_length() &&
        self.remaining_references() == self.cell.references_count()
    }
}

/// subject to move to tests
/// it used from other repos
/// need task
impl SliceData {
    pub fn new(data: Vec<u8>) -> SliceData {
        match crate::find_tag(data.as_slice()) {
            0 => SliceData::default(),
            length_in_bits => BuilderData::with_raw(data, length_in_bits).unwrap().into_cell().unwrap().into()
        }
    }

    pub fn from_raw(data: Vec<u8>, length_in_bits: usize) -> SliceData {
        BuilderData::with_raw(data, length_in_bits).unwrap().into_cell().unwrap().into()
    }

    pub fn append_reference(&mut self, other: SliceData) -> &mut SliceData {
        let mut builder = BuilderData::from_slice(self);
        builder.append_reference_cell(other.into_cell());
        *self = builder.into_cell().expect("it should be used only in tests").into();
        self
    }

    pub fn withdraw(&mut self) -> SliceData {
        std::mem::replace(self, SliceData::new_empty())
    }
}

// impl FromStr for SliceData {
//     type Err = failure::Error;
//     fn from_str(s: &str) -> Result<Self> {
//         let vec = parse_slice_base(s, 0, 16).ok_or_else(|| error!(ExceptionCode::FatalError))?;
//         Ok(BuilderData::with_bitstring(vec)?.into_cell()?.into())
//     }
// }

impl fmt::Debug for SliceData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

#[rustfmt::skip]
impl fmt::Display for SliceData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        writeln!(f, "data: {}..{}, references: {}..{}, data slice:{}, cell:{}", 
                self.data_window.start,
                self.data_window.end,
                self.references_window.start,
                self.references_window.end,
                hex::encode(&self.get_bytestring(0)),
                self.cell)
    }
}

impl fmt::LowerHex for SliceData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.as_hex_string())
    }
}

impl fmt::UpperHex for SliceData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let len = self.remaining_bits();
        let mut data: SmallVec<[u8; 128]> = self.get_bytestring(0).into();
        super::append_tag(&mut data, len);
        write!(f, "{}", super::to_hex_string(data.as_slice(), len, false))
    }
}

