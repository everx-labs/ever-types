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

use std::convert::From;
use std::fmt;

use smallvec::SmallVec;
pub(super) type SmallData = SmallVec<[u8; 128]>;

use crate::cell::{
    append_tag, find_tag, Cell, CellType, DataCell, LevelMask, SliceData, MAX_DATA_BITS,
    MAX_SAFE_DEPTH,
};
use crate::types::{ExceptionCode, Result};
use crate::{error, fail};

const EXACT_CAPACITY: usize = 128;

#[derive(Debug, Default, PartialEq, Clone, Eq)]
pub struct BuilderData {
    data: SmallData,
    length_in_bits: usize,
    pub(super) references: SmallVec<[Cell; 4]>,
    pub(super) cell_type: CellType,
}

impl BuilderData {
    pub const fn default() -> Self {
        Self::new()
    }
    pub const fn new() -> Self {
        BuilderData {
            data: SmallVec::new_const(),
            length_in_bits: 0,
            references: SmallVec::new_const(),
            cell_type: CellType::Ordinary,
        }
    }

    pub fn with_raw(
        data: impl Into<SmallData>,
        length_in_bits: usize,
    ) -> Result<BuilderData> {
        let mut data = data.into();
        if length_in_bits > data.len() * 8 {
            fail!(ExceptionCode::FatalError)
        } else if length_in_bits > BuilderData::bits_capacity() {
            fail!(ExceptionCode::CellOverflow)
        }
        let data_shift = length_in_bits % 8;
        if data_shift == 0 {
            data.truncate(length_in_bits / 8);
        } else {
            data.truncate(1 + length_in_bits / 8);
            if let Some(last_byte) = data.last_mut() {
                *last_byte = (*last_byte >> (8 - data_shift)) << (8 - data_shift);
            }
        }
        data.reserve_exact(EXACT_CAPACITY - data.len());
        Ok(BuilderData {
            data,
            length_in_bits,
            references: SmallVec::new(),
            cell_type: CellType::Ordinary,
        })
    }

    pub fn with_raw_and_refs(
        data: impl Into<SmallData>,
        length_in_bits: usize,
        refs: impl IntoIterator<Item = Cell>,
    ) -> Result<BuilderData> {
        let mut builder = BuilderData::with_raw(data, length_in_bits)?;
        builder.references = refs.into_iter().collect();
        Ok(builder)
    }

    pub fn with_bitstring(data: impl Into<SmallData>) -> Result<BuilderData> {
        let data = data.into();
        let length_in_bits = find_tag(data.as_slice());
        if length_in_bits == 0 {
            Ok(BuilderData::new())
        } else if length_in_bits > data.len() * 8 {
            fail!(ExceptionCode::FatalError)
        } else if length_in_bits > BuilderData::bits_capacity() {
            fail!(ExceptionCode::CellOverflow)
        } else {
            BuilderData::with_raw(data, length_in_bits)
        }
    }

    /// finalize cell with default max depth
    pub fn into_cell(self) -> Result<Cell> {
        self.finalize(MAX_SAFE_DEPTH)
    }

    /// loads builder as bitstring to slice
    /// maximum length 1023 bits, type must be Ordinary, no references
    pub(super) fn into_bitstring(self) -> SliceData {
        SliceData::with_bitstring(self.data, self.length_in_bits)
    }
    /// use max_depth to limit depth
    pub fn finalize(mut self, max_depth: u16) -> Result<Cell> {
        let mut children_level_mask = LevelMask::with_level(0);
        for r in self.references.iter() {
            children_level_mask |= r.level_mask();
        }
        let level_mask = match self.cell_type {
            CellType::Unknown => fail!("failed to finalize a cell of unknown type"),
            CellType::Ordinary => children_level_mask,
            CellType::PrunedBranch => {
                if self.bits_used() < 16 {
                    fail!("failed to get level mask for pruned branch cell");
                }
                // mask validity gets checked later
                LevelMask::with_mask(self.data[1])
            }
            CellType::LibraryReference => LevelMask::with_level(0),
            CellType::MerkleProof | CellType::MerkleUpdate =>
                children_level_mask.virtualize(1),
            CellType::Big => fail!("Big cell creation by builder is prohibited"),
        };
        append_tag(&mut self.data, self.length_in_bits);

        Ok(Cell::with_cell_impl(DataCell::with_params(
            self.references.to_vec(),
            &self.data,
            self.cell_type,
            level_mask.mask(),
            Some(max_depth),
            None,
            None,
        )?))
    }

    pub fn references(&self) -> &[Cell] {
        self.references.as_slice()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn cell_type(&self) -> CellType {
        self.cell_type
    }

    pub fn compare_data(&self, other: &Self) -> Result<(Option<usize>, Option<usize>)> {
        if self == other {
            return Ok((None, None));
        }
        let label1 = SliceData::load_bitstring(self.clone())?;
        let label2 = SliceData::load_bitstring(other.clone())?;
        let (_prefix, rem1, rem2) = SliceData::common_prefix(&label1, &label2);
        // unwraps are safe because common_prefix returns None if slice is empty
        Ok((
            rem1.map(|rem| rem.get_bit(0).expect("check common_prefix function") as usize),
            rem2.map(|rem| rem.get_bit(0).expect("check common_prefix function") as usize),
        ))
    }

    pub fn from_cell(cell: &Cell) -> Result<BuilderData> {
        if cell.cell_type() == CellType::Big {
            fail!("Can't create a builder from a big cell");
        }
        let data = SmallVec::from_slice(cell.data());
        let mut builder = BuilderData::with_raw(data, cell.bit_length())?;
        builder.references = cell.clone_references();
        builder.cell_type = cell.cell_type();
        Ok(builder)
    }

    #[deprecated]
    pub fn from_slice(slice: &SliceData) -> BuilderData {
        slice.as_builder()
    }

    pub fn length_in_bits(&self) -> usize {
        self.length_in_bits
    }

    pub fn can_append(&self, x: &BuilderData) -> bool {
        self.bits_free() >= x.bits_used() && self.references_free() >= x.references_used()
    }

    pub fn prepend_raw(&mut self, slice: &[u8], bits: usize) -> Result<&mut Self> {
        if bits != 0 {
            let mut buffer = BuilderData::with_raw(SmallVec::from_slice(slice), bits)?;
            buffer.append_raw(self.data(), self.length_in_bits())?;
            self.length_in_bits = buffer.length_in_bits;
            self.data = buffer.data;
        }
        Ok(self)
    }

    pub fn append_raw(&mut self, slice: &[u8], bits: usize) -> Result<&mut Self> {
        Self::append_raw_data(&mut self.data, &mut self.length_in_bits, slice, bits)?;
        Ok(self)
    }

    // TODO: move it to builder operations to bitstring
    pub(super) fn append_raw_data(
        data: &mut SmallData,
        length_in_bits: &mut usize,
        slice: &[u8],
        bits: usize,
    ) -> Result<()> {
        if slice.len() * 8 < bits {
            fail!(ExceptionCode::FatalError)
        } else if (*length_in_bits + bits) > BuilderData::bits_capacity() {
            fail!(ExceptionCode::CellOverflow)
        } else if bits != 0 {
            if (*length_in_bits % 8) == 0 {
                if (bits % 8) == 0 {
                    Self::append_without_shift(data, length_in_bits, slice, bits);
                } else {
                    Self::append_with_shift(data, length_in_bits, slice, bits);
                }
            } else {
                Self::append_with_double_shift(data, length_in_bits, slice, bits);
            }
        }
        assert!(*length_in_bits <= BuilderData::bits_capacity());
        assert!(data.len() * 8 <= BuilderData::bits_capacity() + 1);
        Ok(())
    }

    fn append_without_shift(
        data: &mut SmallData,
        length_in_bits: &mut usize,
        slice: &[u8],
        bits: usize,
    ) {
        assert_eq!(bits % 8, 0);
        assert_eq!(*length_in_bits % 8, 0);

        data.truncate(*length_in_bits / 8);
        data.extend(slice.iter().copied());
        *length_in_bits += bits;
        data.truncate(*length_in_bits / 8);
    }

    fn append_with_shift(
        data: &mut SmallData,
        length_in_bits: &mut usize,
        slice: &[u8],
        bits: usize,
    ) {
        assert!(bits % 8 != 0);
        assert_eq!(*length_in_bits % 8, 0);

        data.truncate(*length_in_bits / 8);
        data.extend(slice.iter().copied());
        *length_in_bits += bits;
        data.truncate(1 + *length_in_bits / 8);

        let slice_shift = bits % 8;
        let mut last_byte = data.pop().expect("Empty slice going to another way");
        last_byte >>= 8 - slice_shift;
        last_byte <<= 8 - slice_shift;
        data.push(last_byte);
    }

    fn append_with_double_shift(
        data: &mut SmallData,
        length_in_bits: &mut usize,
        slice: &[u8],
        bits: usize,
    ) {
        let self_shift = *length_in_bits % 8;
        data.truncate(1 + *length_in_bits / 8);
        *length_in_bits += bits;

        let last_bits = data.pop().unwrap() >> (8 - self_shift);
        let mut y: u16 = last_bits.into();
        for x in slice.iter() {
            y = (y << 8) | (*x as u16);
            data.push((y >> self_shift) as u8);
        }
        data.push((y << (8 - self_shift)) as u8);

        let shift = *length_in_bits % 8;
        if shift == 0 {
            data.truncate(*length_in_bits / 8);
        } else {
            data.truncate(*length_in_bits / 8 + 1);
            let mut last_byte = data.pop().unwrap();
            last_byte >>= 8 - shift;
            last_byte <<= 8 - shift;
            data.push(last_byte);
        }
    }

    pub fn checked_append_reference(&mut self, cell: Cell) -> Result<&mut Self> {
        if self.references_free() == 0 {
            fail!(ExceptionCode::CellOverflow)
        } else {
            self.references.push(cell);
            Ok(self)
        }
    }

    pub fn checked_prepend_reference(&mut self, cell: Cell) -> Result<&mut Self> {
        if self.references_free() == 0 {
            fail!(ExceptionCode::CellOverflow)
        } else {
            self.references.insert(0, cell);
            Ok(self)
        }
    }

    pub fn replace_data(&mut self, data: impl Into<SmallData>, length_in_bits: usize) {
        let data = data.into();
        self.length_in_bits = length_in_bits.min(MAX_DATA_BITS).min(data.len() * 8);
        self.data = data;
    }

    pub fn replace_reference_cell(&mut self, index: usize, child: Cell) {
        match self.references.get_mut(index) {
            None => {
                log::error!(
                    "replacing not existed cell by index {} with cell hash {:x}",
                    index,
                    child.repr_hash()
                );
            }
            Some(old) => *old = child,
        }
    }

    pub fn set_type(&mut self, cell_type: CellType) {
        // TODO: big cells ?

        self.cell_type = cell_type;
    }

    pub fn is_empty(&self) -> bool {
        self.length_in_bits() == 0 && self.references().is_empty()
    }

    pub fn trunc(&mut self, length_in_bits: usize) -> Result<()> {
        if self.length_in_bits < length_in_bits {
            fail!(ExceptionCode::FatalError)
        } else {
            self.length_in_bits = length_in_bits;
            self.data.truncate(1 + length_in_bits / 8);
            Ok(())
        }
    }
}

// use only for test purposes
#[cfg(test)]
impl BuilderData {
    pub(crate) fn append_reference(&mut self, child: BuilderData) {
        self.references.push(child.into_cell().unwrap());
    }
}

impl fmt::Display for BuilderData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "data: {} len: {} reference count: {}",
            hex::encode(&self.data),
            self.length_in_bits,
            self.references.len()
        )
    }
}

impl fmt::UpperHex for BuilderData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", hex::encode_upper(&self.data))
    }
}

impl fmt::Binary for BuilderData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.data.iter().try_for_each(|x| write!(f, "{:08b}", x))
    }
}
