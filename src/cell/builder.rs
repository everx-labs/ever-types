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

use std::convert::From;
use std::fmt;

use crate::{error, fail};
use crate::cell::{append_tag, Cell, CellType, DataCell, find_tag, LevelMask, SliceData};
use crate::types::{ExceptionCode, Result};

const EXACT_CAPACITY: usize = 128;

#[derive(Debug, PartialEq, Clone, Eq)]
pub struct BuilderData {
    data: Vec<u8>,
    length_in_bits: usize,
    references: Vec<Cell>,
    cell_type: CellType,
    level_mask: LevelMask,
}

impl From<BuilderData> for Cell {
    fn from(builder: BuilderData) -> Self {
        builder.into_cell().unwrap()
    }
}

impl From<BuilderData> for SliceData {
    fn from(builder: BuilderData) -> Self {
        builder.into_cell().unwrap().into()
    }
}

impl From<&BuilderData> for Cell {
    fn from(builder: &BuilderData) -> Self {
        builder.clone().into_cell().unwrap()
    }
}

impl From<&mut BuilderData> for Cell {
    fn from(builder: &mut BuilderData) -> Self {
        builder.clone().into_cell().unwrap()
    }
}

impl From<&BuilderData> for SliceData {
    fn from(builder: &BuilderData) -> Self {
        builder.clone().into_cell().unwrap().into()
    }
}

impl From<&mut BuilderData> for SliceData {
    fn from(builder: &mut BuilderData) -> Self {
        builder.clone().into_cell().unwrap().into()
    }
}

impl From<&&Cell> for BuilderData {
    fn from(cell: &&Cell) -> Self {
        let mut builder = BuilderData::with_bitstring(cell.data().to_vec()).unwrap();
        builder.references = cell.clone_references();
        builder.cell_type = cell.cell_type();
        builder.level_mask = cell.level_mask();
        builder
    }
}

impl From<&Cell> for BuilderData {
    fn from(cell: &Cell) -> Self {
        let mut builder = BuilderData::with_bitstring(cell.data().to_vec()).unwrap();
        builder.references = cell.clone_references();
        builder.cell_type = cell.cell_type();
        builder.level_mask = cell.level_mask();
        builder
    }
}

impl From<Cell> for BuilderData {
    fn from(cell: Cell) -> Self {
        let mut builder = BuilderData::with_bitstring(cell.data().to_vec()).unwrap();
        builder.references = cell.clone_references();
        builder.cell_type = cell.cell_type();
        builder.level_mask = cell.level_mask();
        builder
    }
}

impl Default for BuilderData {
    fn default() -> Self {
        BuilderData::new()
    }
}

impl BuilderData {
    pub const fn default() -> Self { Self::new() }
    pub const fn new() -> Self {
        BuilderData {
            data: Vec::new(),
            length_in_bits: 0,
            references: vec![],
            cell_type: CellType::Ordinary,
            level_mask: LevelMask(0),
        }
    }

    pub fn with_raw(mut data: Vec<u8>, length_in_bits: usize) -> Result<BuilderData> {
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
            data.last_mut().map(|last_byte| *last_byte = (*last_byte >> (8 - data_shift)) << (8 - data_shift));
        }
        data.reserve_exact(EXACT_CAPACITY - data.len());
        Ok(BuilderData {
            data,
            length_in_bits,
            references: vec![],
            cell_type: CellType::Ordinary,
            level_mask: LevelMask::with_mask(0),
        })
    }

    pub fn with_raw_and_refs<TRefs>(data: Vec<u8>, length_in_bits: usize, refs: TRefs) -> Result<BuilderData>
    where
        TRefs: IntoIterator<Item = Cell>
    {
        let mut builder = BuilderData::with_raw(data, length_in_bits)?;
        let mut iter = refs.into_iter();
        while let Some(value) = iter.next() {
            builder.checked_append_reference(value)?;
        }
        Ok(builder)
    }

    pub fn with_bitstring(data: Vec<u8>) -> Result<BuilderData> {
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

    pub fn into_cell(mut self) -> Result<Cell> {
        if self.cell_type == CellType::Ordinary {
            // For Ordinary cells - level is set automatically,
            // for other types - it must be set manually by set_level_mask()
            for r in self.references.iter() {
                self.level_mask |= r.level_mask();
            }
        }
        append_tag(&mut self.data, self.length_in_bits);

        Ok(Cell::with_cell_impl(
            DataCell::with_params(
                self.references,
                self.data,
                self.cell_type,
                self.level_mask.mask(),
                None,
                None,
            )?
        ))
    }

    pub fn references(&self) -> &[Cell] {
        self.references.as_slice()
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    // TODO: refactor it compare directly in BuilderData
    pub fn compare_data(&self, other: &Self) -> (Option<usize>, Option<usize>) {
        if self == other {
            return (None, None)
        }
        let label1 = SliceData::from(self);
        let label2 = SliceData::from(other);
        let (_prefix, rem1, rem2) = SliceData::common_prefix(&label1, &label2);
        // unwraps are safe because common_prefix returns None if slice is empty
        (
            rem1.map(|rem| rem.get_bits(0, 1).expect("check common_prefix function") as usize),
            rem2.map(|rem| rem.get_bits(0, 1).expect("check common_prefix function") as usize)
        )
    }

    pub fn from_slice(slice: &SliceData) -> BuilderData {
        let refs_count = slice.remaining_references();
        let references = (0..refs_count)
            .map(|i| slice.reference(i).unwrap().clone())
            .collect::<Vec<_>>();
        
        let mut builder = slice.remaining_data();
        builder.references = references;
        builder.cell_type = slice.cell_type();
        builder.level_mask = slice.level_mask();
        builder
    }

    pub fn update_cell<T, P, R>(&mut self, mutate: T, args: P) -> R
    where
        T: Fn(&mut Vec<u8>, &mut usize, &mut Vec<Cell>, P)  -> R
    {
        let result = mutate(&mut self.data, &mut self.length_in_bits, &mut self.references, args);

        debug_assert!(self.length_in_bits <= BuilderData::bits_capacity());
        debug_assert!(self.data.len() * 8 <= BuilderData::bits_capacity() + 1);
        result
    }

    /// returns data of cell
    pub fn cell_data(&mut self, data: &mut Vec<u8>, bits: &mut usize, children: &mut Vec<Cell>) {
        *data = self.data.clone();
        *bits = self.length_in_bits;
        children.clear();
        let n = self.references.len();
        for i in 0..n {
            children.push(self.references[i].clone())
        }
    }

    pub fn length_in_bits(&self) -> usize {
        self.length_in_bits
    }

    pub fn can_append(&self, x: &BuilderData) -> bool {
        self.bits_free() >= x.bits_used() && self.references_free() >= x.references_used()
    }

    pub fn prepend_raw(&mut self, slice: &[u8], bits: usize) -> Result<&mut Self> {
        if bits != 0 {
            let mut buffer = BuilderData::with_raw(slice.to_vec(), bits)?;
            buffer.append_raw(self.data(), self.length_in_bits())?;
            self.length_in_bits = buffer.length_in_bits;
            self.data = buffer.data;
        }
        Ok(self)
    }

    pub fn append_raw(&mut self, slice: &[u8], bits: usize) -> Result<&mut Self> {
        if slice.len() * 8 < bits {
            fail!(ExceptionCode::FatalError)
        } else if (self.length_in_bits() + bits) > BuilderData::bits_capacity() {
            fail!(ExceptionCode::CellOverflow)
        } else if bits != 0 {
            if (self.length_in_bits() % 8) == 0 {
                if (bits % 8) == 0 {
                    self.append_without_shifting(slice, bits);
                } else {
                    self.append_with_slice_shifting(slice, bits);
                }
            } else {
                self.append_with_double_shifting(slice, bits);
            }
        }
        assert!(self.length_in_bits() <= BuilderData::bits_capacity());
        assert!(self.data().len() * 8 <= BuilderData::bits_capacity() + 1);
        Ok(self)
    }

    fn append_without_shifting(&mut self, slice: &[u8], bits: usize) {
        assert_eq!(bits % 8, 0);
        assert_eq!(self.length_in_bits() % 8, 0);

        self.data.truncate(self.length_in_bits / 8);
        self.data.extend(slice);
        self.length_in_bits += bits;
        self.data.truncate(self.length_in_bits / 8);
    }

    fn append_with_slice_shifting(&mut self, slice: &[u8], bits: usize) {
        assert!(bits % 8 != 0);
        assert_eq!(self.length_in_bits() % 8, 0);

        self.data.truncate(self.length_in_bits / 8);
        self.data.extend(slice);
        self.length_in_bits += bits;
        self.data.truncate(1 + self.length_in_bits / 8);

        let slice_shift = bits % 8;
        let mut last_byte = self.data.pop().expect("Empty slice going to another way");
        last_byte >>= 8 - slice_shift;
        last_byte <<= 8 - slice_shift;
        self.data.push(last_byte);
    }

    fn append_with_double_shifting(&mut self, slice: &[u8], bits: usize) {
        let self_shift = self.length_in_bits % 8;
        self.data.truncate(1 + self.length_in_bits / 8);
        self.length_in_bits += bits;

        let last_bits = self.data.pop().unwrap() >> (8 - self_shift);
        let mut y: u16 = last_bits.into();
        for x in slice.iter() {
            y = (y << 8) | (*x as u16);
            self.data.push((y >> self_shift) as u8);
        }
        self.data.push((y << (8 - self_shift)) as u8);

        let shift = self.length_in_bits % 8;
        if shift == 0 {
            self.data.truncate(self.length_in_bits / 8);
        } else {
            self.data.truncate(self.length_in_bits / 8 + 1);
            let mut last_byte = self.data.pop().unwrap();
            last_byte >>= 8 - shift;
            last_byte <<= 8 - shift;
            self.data.push(last_byte);
        }
    }

    pub fn level(&self) -> u8 {
        self.level_mask.level()
    }

    pub fn level_mask(&self) -> LevelMask {
        self.level_mask
    }

    pub fn level_mask_mut(&mut self) -> &mut LevelMask {
        &mut self.level_mask
    }

    pub fn append_reference(&mut self, child: BuilderData) {
        self.references.push(Cell::from(child));
    }

    pub fn append_reference_cell(&mut self, child: Cell) {
        self.references.push(child);
    }

    pub fn prepend_reference(&mut self, child: BuilderData) {
        self.references.insert(0, Cell::from(child));
    }

    pub fn set_type(&mut self, cell_type: CellType) {
        self.cell_type = cell_type;
    }

    pub fn set_level_mask(&mut self, mask: LevelMask) {
        self.level_mask = mask;
    }

    pub fn is_empty(&self) -> bool {
        self.length_in_bits() == 0 && self.references().len() == 0
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

impl fmt::Display for BuilderData {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let cell: Cell = self.into();
        write!(f, "{}", cell)
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
