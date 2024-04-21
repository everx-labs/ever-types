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

use std::cmp;
use std::convert::TryInto;
use std::fmt;
use std::hash::{Hash, Hasher};
use std::ops::{Bound, Range, RangeBounds};

use super::SmallData;
use crate::{error, fail, cell::{BuilderData, Cell, CellType, IBitstring, LevelMask}, parse_slice_base};
use crate::types::{ExceptionCode, Result, UInt256};
use smallvec::SmallVec;

#[derive(Eq, PartialEq, Clone, Default)]
enum InternalData {
    #[default]
    None,
    Cell(Cell),
    Data(SmallData, usize) // bitstring variant which optimizes storage of data without references
}

#[derive(Eq, Clone, Default)]
pub struct SliceData {
    data: InternalData,
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
        for i in 0..self.remaining_references() {
            state.write(self.reference(i).unwrap().repr_hash().as_slice());
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

impl SliceData {
    pub const fn new_empty() -> SliceData {
        Self {
            data: InternalData::None,
            data_window: 0..0,
            references_window: 0..0,
        }
    }

    pub fn load_builder(builder: BuilderData) -> Result<SliceData> {
        SliceData::load_cell(builder.into_cell()?)
    }

    pub fn load_cell(cell: Cell) -> Result<SliceData> {
        if cell.is_pruned() {
            fail!(ExceptionCode::PrunedCellAccess)
        } else if cell.cell_type() == CellType::Big {
            fail!(ExceptionCode::BigCellAccess)
        } else {
            Ok(SliceData {
                references_window: 0..cell.references_count(),
                data_window: 0..cell.bit_length(),
                data: InternalData::Cell(cell)
            })
        }
    }

    pub fn with_bitstring(data: impl Into<SmallData>, length_in_bits: usize) -> Self {
        Self {
            data: InternalData::Data(data.into(), length_in_bits.min(super::MAX_DATA_BITS)),
            references_window: 0..0,
            data_window: 0..length_in_bits,
        }
    }

    pub fn load_bitstring(builder: BuilderData) -> Result<SliceData> {
        if builder.cell_type != CellType::Ordinary {
            fail!("cell type should be ordinary but it is {}", builder.cell_type)
        }
        if builder.length_in_bits() > super::MAX_DATA_BITS {
            fail!("length should be less or equal to {} but it is {}", super::MAX_DATA_BITS, builder.length_in_bits())
        }
        if builder.references_used() != 0 {
            fail!("should not have any references but it has {}", builder.references_used())
        }
        Ok(builder.into_bitstring())
    }

    pub fn load_cell_ref(cell: &Cell) -> Result<SliceData> {
        SliceData::load_cell(cell.clone())
    }

    pub fn from_string(value: &str) -> Result<SliceData> {
        let vec = parse_slice_base(value, 0, 16).ok_or_else(|| error!(ExceptionCode::FatalError))?;
        SliceData::load_bitstring(BuilderData::with_bitstring(vec)?)
    }

    pub fn remaining_references(&self) -> usize {
        if self.references_window.start >= self.references_window.end {
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

    pub fn clear_all_references(&mut self) {
        self.references_window.end = self.references_window.start
    }

    /// shrinks references_window: range - subrange of current window, returns shrinked references
    pub fn shrink_references<T: RangeBounds<usize>>(&mut self, range: T) -> Vec<Cell> {
        let mut vec = vec![];
        if let InternalData::Cell(cell) = &self.data {
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

            if (start <= end) && (end <= refs_count) {
                (0..start).for_each(|i| vec.push(cell.reference(i).unwrap()));
                (end..refs_count).for_each(|i| vec.push(cell.reference(i).unwrap()));
                self.references_window.end = self.references_window.start + end;
                self.references_window.start += start;
            }
        }
        vec
    }

    fn remaining_data(self) -> (SmallData, usize) {
        if self.data_window.start >= self.data_window.end {
            return (SmallVec::new(), 0)
        }
        let data = match self.data {
            InternalData::None => return (SmallVec::new(), 0),
            InternalData::Data(data, length_in_bits) => {
                if self.data_window.start == 0 && self.data_window.end == length_in_bits {
                    return (data, length_in_bits);
                }
                data
            }
            InternalData::Cell(cell) => {
                if self.references_window.start == 0 && self.data_window.start == 0
                    && self.references_window.end == cell.references_count()
                    && self.data_window.end == cell.bit_length() {
                        return (SmallVec::from_slice(cell.data()), cell.bit_length())
                }
                SmallVec::from_slice(cell.data())
            }
        };
        let length_in_bits = self.data_window.end - self.data_window.start;
        let start = self.data_window.start / 8;
        let end = (self.data_window.end + 7) / 8;
        let trailing = self.data_window.start % 8;
        if trailing == 0 {
            return (SmallVec::from_slice(&data[start..end]), length_in_bits);
        }
        let mut vec = SmallVec::from_slice(&[data[start] << trailing]);
        if trailing + length_in_bits > 8 {
            let mut new_length = 8 - trailing;
            let bits = length_in_bits - new_length;
            BuilderData::append_raw_data(&mut vec, &mut new_length, &data[start + 1..end], bits).unwrap();
        }
        (vec, length_in_bits)
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
        if self.references_window.start + i < self.references_window.end {
            if let InternalData::Cell(cell) = &self.data {
                return cell.reference(self.references_window.start + i)
            }
        }
        fail!(ExceptionCode::CellUnderflow)
    }

    pub fn reference_opt(&self, i: usize) -> Option<Cell> {
        if self.references_window.start + i < self.references_window.end {
            if let InternalData::Cell(cell) = &self.data {
                return cell.reference(self.references_window.start + i).ok()
            }
        }
        None
    }

    pub fn storage(&self) -> &[u8] {
        match &self.data {
            InternalData::None => &[],
            InternalData::Data(data, _length_in_bits) => data,
            InternalData::Cell(cell) => cell.data()
        }
    }
    /// returns internal cell regardless window settings
    /// use this function carefully
    /// it may create new real cell if SliceData was a bitstring
    pub fn cell(&self) -> Cell {
        match &self.data {
            InternalData::None => Cell::default(),
            InternalData::Cell(cell) => cell.clone(),
            _ => self.as_builder().into_cell().unwrap() // it is safe because simple bitstring
        }
    }
    /// returns internal cell regardless window settings
    /// don't use this function
    pub fn cell_opt(&self) -> Option<&Cell> {
        match &self.data {
            InternalData::None => Some(&crate::CELL_DEFAULT),
            InternalData::Cell(cell) => Some(cell),
            _ => None
        }
    }
    /// constructs new cell trunking original regarding window settings
    pub fn into_cell(self) -> Cell {
        match &self.data {
            InternalData::None => return Cell::default(),
            InternalData::Cell(cell) => {
                if self.data_window.start == 0
                    && self.data_window.end == cell.bit_length()
                    && self.references_window.start == 0
                    && self.references_window.end == cell.references_count() {
                    return cell.clone();
                }
            }
            _ => ()
        }
        self.into_builder().into_cell().unwrap()
    }
    /// constructs builder trunking original cell regarding window settings
    pub fn into_builder(self) -> BuilderData {
        let cell_type = self.cell_type();
        let slice = &self;
        let refs: SmallVec<[Cell; 4]> = (0..self.remaining_references()).map(|index| slice.reference(index).unwrap()).collect::<SmallVec<_>>();
        let (data, length_in_bits) = self.remaining_data();
        let mut builder = BuilderData::with_raw_and_refs(data, length_in_bits, refs).unwrap();
        builder.cell_type = cell_type;
        builder
    }

    pub fn as_builder(&self) -> BuilderData {
        self.clone().into_builder()
    }

    pub fn checked_drain_reference(&mut self) -> Result<Cell> {
        if let InternalData::Cell(cell) = &self.data {
            if self.references_window.start < self.references_window.end {
                self.references_window.start += 1;
                return cell.reference(self.references_window.start - 1);
            }
        }
        fail!(ExceptionCode::CellUnderflow)
    }

    pub fn get_references(&self) -> Range<usize> {
        self.references_window.clone()
    }

    // TBD: remove using in TVM first
    #[deprecated]
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
            Some((self.storage()[q] >> (7 - r) & 1) != 0)
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
            Ok(self.storage()[q] >> (8 - r - bits))
        } else if bits <= (8 - r) {
            Ok(self.storage()[q] >> (8 - r - bits) & ((1 << bits) - 1))
        } else {
            // We shall have here at least two bytes to read
            let data = self.storage();
            let mut ret = (data[q] as u16) << 8;
            ret |= data[q + 1] as u16;
            Ok((ret >> (8 - r)) as u8 >> (8 - bits))
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

    pub fn get_next_bytes_to_slice(&mut self, buffer: &mut [u8]) -> Result<()> {
        if buffer.len() * 8 > self.remaining_bits() {
            fail!(ExceptionCode::CellUnderflow)
        }
        for b in buffer {
            *b = self.get_next_byte()?;
        }
        Ok(())
    }

    pub fn get_bytestring(&self, offset: usize) -> Vec<u8> {
        let mut head = self.data_window.start + offset;
        if self.data_window.end <= head {
            return vec![];
        }
        let data = self.storage();
        let r_rev = 8 - head % 8;
        let mut ret = if r_rev == 8 {
            let range = (head / 8) .. (self.data_window.end / 8);
            head = self.data_window.end / 8 * 8;
            Vec::from(&data[range])
        } else {
            let mut ret = Vec::with_capacity((self.data_window.end - head + 7) / 8);
            let mut r = data[head / 8] as u16;
            while head + 8 <= self.data_window.end {
                head += 8;
                r = (r << 8) | (data[head / 8] as u16);
                ret.push((r >> r_rev) as u8);
            }
            ret
        };
        if head < self.data_window.end {
            let remainder = self.data_window.end - head;
            ret.push(
                self.get_bits(head - self.data_window.start, remainder).unwrap() << (8 - remainder)
            );
        }
        ret
    }

    /// Returns Cell from references if present and next bit in slice is one
    pub fn get_next_maybe_reference(&mut self) -> Result<Option<Cell>> {
        if self.get_next_bit()? {
            let cell = self.checked_drain_reference()?;
            Ok(Some(cell))
        } else {
            Ok(None)
        }
    }

    /// Returns Cell from references if present and next bit in slice is one
    pub fn get_next_dictionary(&mut self) -> Result<Option<Cell>> {
        self.get_next_maybe_reference()
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
        let max_possible_prefix_length_in_bits = a.remaining_bits().min(b.remaining_bits());
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
            let diff = a_bits ^ b_bits;
            let mut diff = diff.leading_zeros() as usize;
            diff -= 8 - last_bits_len;
            let diff = diff.min(last_bits_len);

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

    // TBD
    pub fn overwrite_prefix(&mut self, prefix: &SliceData) -> Result<()> {
        if prefix.is_empty() {
            Ok(())

        } else if self.remaining_bits() < prefix.remaining_bits() {
            fail!("Prefix should be fully in self")
        } else {
            let mut builder = prefix.as_builder();
            self.move_by(prefix.remaining_bits())?;
            builder.append_bytestring(self)?;
            *self = SliceData::load_builder(builder)?;
            Ok(())
        }
    }

    pub fn cell_type(&self) -> CellType {
        match &self.data {
            InternalData::Cell(cell) => cell.cell_type(),
            _ => Default::default()
        }
    }
    pub fn level(&self) -> u8 {
        match &self.data {
            InternalData::Cell(cell) => cell.level(),
            _ => Default::default()
        }
    }
    pub fn level_mask(&self) -> LevelMask {
        match &self.data {
            InternalData::Cell(cell) => cell.level_mask(),
            _ => Default::default()
        }
    }

    /// Returns cell's higher hash for given index (last one - representation hash)
    pub fn hash(&self, index: usize) -> UInt256 {
        match &self.data {
            InternalData::Cell(cell) => Cell::hash(cell, index),
            _ => Default::default()
        }
    }

    /// Returns cell's representation hash
    pub fn repr_hash(&self) -> UInt256 {
        match &self.data {
            InternalData::Cell(cell) => cell.repr_hash(),
            _ => Default::default()
        }
    }

    /// Returns cell's depth for given index
    pub fn depth(&self, index: usize) -> u16 {
        match &self.data {
            InternalData::Cell(cell) => cell.depth(index),
            _ => Default::default()
        }
    }

    /// Returns cell's hashes (representation and highers)
    pub fn hashes(&self) -> Vec<UInt256> {
        match &self.data {
            InternalData::Cell(cell) => cell.hashes(),
            _ => Default::default()
        }
    }

    /// Returns cell's depth (for current state and each level)
    pub fn depths(&self) -> Vec<u16> {
        match &self.data {
            InternalData::Cell(cell) => cell.depths(),
            _ => Default::default()
        }
    }

    // #[deprecated]
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex_string(&self) -> String { self.as_hex_string() }

    pub fn as_hex_string(&self) -> String {
        let len = self.remaining_bits();
        let mut data = self.get_bytestring(0);
        if len % 8 == 0 {
            data.push(0x80);
            super::to_hex_string(data, len, true)
        } else {
            let mut data: SmallData = data.into();
            super::append_tag(&mut data, len);
            super::to_hex_string(data, len, true)
        }
    }

    #[cfg(test)]
    fn is_full_cell_slice(&self) -> bool {
        match &self.data {
            InternalData::None => true,
            InternalData::Cell(cell) => {
                self.data_window.start == 0
                    && self.data_window.end == cell.bit_length()
                    && self.references_window.start == 0
                    && self.references_window.end == cell.references_count()
            }
            InternalData::Data(_data, length_in_bits, ) => {
                self.data_window.start == 0
                    && self.data_window.end == *length_in_bits
                    && self.references_window.start == 0
                    && self.references_window.end == 0
            }
        }
    }
}

/// subject to move to tests
/// it used from other repos
/// need task
impl SliceData {
    pub fn new(data: Vec<u8>) -> SliceData {
        match crate::find_tag(data.as_slice()) {
            0 => SliceData::default(),
            length_in_bits => SliceData::from_raw(data, length_in_bits)
        }
    }

    pub fn from_raw(data: Vec<u8>, length_in_bits: usize) -> SliceData {
        SliceData::load_builder(BuilderData::with_raw(data, length_in_bits).unwrap()).unwrap()
    }

    pub fn append_reference(&mut self, other: SliceData) -> &mut SliceData {
        let mut builder = self.as_builder();
        builder.checked_append_reference(other.into_cell()).unwrap();
        *self = SliceData::load_builder(builder).expect("it should be used only in tests");
        self
    }

    pub fn withdraw(&mut self) -> SliceData {
        std::mem::replace(self, SliceData::new_empty())
    }
}

impl fmt::Debug for SliceData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self)
    }
}

#[rustfmt::skip]
impl fmt::Display for SliceData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "data: {}..{}, references: {}..{}, data slice:{}", 
            self.data_window.start,
            self.data_window.end,
            self.references_window.start,
            self.references_window.end,
            hex::encode(self.get_bytestring(0)),
        )?;
        match &self.data {
            InternalData::None => writeln!(f, "cell: empty"),
            InternalData::Cell(cell) => writeln!(f, "cell: {}", cell),
            InternalData::Data(data, length_in_bits, ) => writeln!(f, "cell: {} - {length_in_bits}", hex::encode(data)),
        }
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
        let mut data: SmallData = self.get_bytestring(0).into();
        super::append_tag(&mut data, len);
        write!(f, "{}", super::to_hex_string(data.as_slice(), len, false))
    }
}

#[cfg(test)]
#[path = "tests/test_slice.rs"]
mod tests;
