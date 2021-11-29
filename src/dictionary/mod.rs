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

use std::{cmp, iter::Iterator, marker::PhantomData};

use crate::{error, fail};
use crate::cell::{BuilderData, Cell, IBitstring, SliceData};
use crate::GasConsumer;
use crate::Mask;
use crate::types::{ExceptionCode, Result};

pub use self::hashmap::HashmapE;
pub use self::pfxhashmap::PfxHashmapE;
use smallvec::SmallVec;

mod hashmap;
mod pfxhashmap;

pub type Leaf = Result<Option<SliceData>>;

pub const ADD: u8 = 0x01;
pub const REPLACE: u8 = 0x02;
#[allow(clippy::unusual_byte_groupings)]
const EMPTY_LABEL_MARKER: u8 = 0b00_000000;
#[allow(clippy::unusual_byte_groupings)]
const SHORT_LABEL_PREFIX: u8 = 0b0_0000000; // hml_short constructor, binary 0
#[allow(clippy::unusual_byte_groupings)]
const LONG_LABEL_PREFIX: u8 = 0b10_000000; // hml_long, binary 10
#[allow(clippy::unusual_byte_groupings)]
const SAME_LABEL_PREFIX: u8 = 0b11_000000; // hml_same, binary 11

// hml_long$10 n:(#<= m) s:n*bit = HmLabel ~n m;
fn hml_long(key: &SliceData, len: usize) -> Result<BuilderData> {
    let mut label = BuilderData::with_raw(SmallVec::from_slice(&[LONG_LABEL_PREFIX]), 2)?;
    label.append_bits(key.remaining_bits(), len)?;
    label.append_bytestring(key)?;
    Ok(label)
}

// hml_short$0 {n:#} len:(Unary ~n) s:n*bit = HmLabel ~n m;
fn hml_short(key: &SliceData) -> Option<BuilderData> {
    let mut label = BuilderData::with_raw(SmallVec::from_slice(&[SHORT_LABEL_PREFIX]), 1).ok()?;
    let length = key.remaining_bits();
    for _ in 0..length / 32 {
        label.append_bits(std::u32::MAX as usize, 32).ok()?;
    }
    let remainder = length % 32;
    if remainder != 0 {
        label.append_bits(std::u32::MAX as usize, remainder).ok()?;
    }
    label.append_bit_zero().ok()?;
    label.append_bytestring(key).ok()?;
    Some(label)
}

// hml_same$11 v:bit n:(#<= m) = HmLabel ~n m;
fn hml_same(key: &SliceData, len: usize) -> Option<BuilderData> {
    let mut zero_bit_found = false;
    let mut one_bit_found = false;
    let bits = key.remaining_bits();
    for offset in 0..bits {
        match key.get_bit_opt(offset)? {
            false if one_bit_found => return None,
            false => zero_bit_found = true,
            true if zero_bit_found => return None,
            true => one_bit_found = true,
        }
    }

    let mut label = BuilderData::with_raw(SmallVec::from_slice(&[SAME_LABEL_PREFIX]), 2).ok()?;
    label.append_bit_bool(!zero_bit_found).ok()?;
    label.append_bits(bits, len).ok()?;
    Some(label)
}

pub fn hm_empty() -> Result<BuilderData> {
    BuilderData::with_raw(SmallVec::from_slice(&[EMPTY_LABEL_MARKER]), 2)
}

pub fn hm_label(key: &SliceData, max: usize) -> Result<BuilderData> {
    debug_assert!(max > 0 || key.is_empty());
    if key.is_empty() || max == 0 {
        return hm_empty()
    }
    let len = 16 - (max as u16).leading_zeros() as usize;
    let length_of_long = 2 + len + key.remaining_bits(); // len == key.remaining_bits() + 1
    let length_of_short = 1 + 2 * key.remaining_bits() + 1;
    let length_of_same = 2 + 1 + len;

    let long_label = hml_long(key, len)?;
    debug_assert_eq!(length_of_long, long_label.length_in_bits());
    if let Some(short_label) = hml_short(key) {
        debug_assert_eq!(length_of_short, short_label.length_in_bits());
        if let Some(same_label) = hml_same(key, len) {
            debug_assert_eq!(length_of_same, same_label.length_in_bits());
            let length = cmp::min(long_label.length_in_bits(), short_label.length_in_bits());
            if same_label.length_in_bits() < length {
                return Ok(same_label)
            }
        }
        if short_label.length_in_bits() <= long_label.length_in_bits() {
            return Ok(short_label)
        }
    } else if let Some(same_label) = hml_same(key, len) {
        debug_assert_eq!(length_of_same, same_label.length_in_bits());
        if same_label.length_in_bits() < long_label.length_in_bits() {
            return Ok(same_label)
        }
    }
    Ok(long_label)
}

// reading hmLabel from SliceData
#[derive(Clone, Debug, Eq, PartialEq)]
pub struct LabelReader {
    cursor: SliceData,
    already_read: bool,
}

impl LabelReader {
    fn get_label_short(&mut self, max: &mut usize) -> Result<SliceData> {
        let mut len = 0;
        while self.cursor.get_next_bit()? {
            len += 1;
        }
        *max = max.checked_sub(len).ok_or(ExceptionCode::CellUnderflow)?;
        let mut label = self.cursor.clone();
        self.cursor.shrink_data(len..);
        label.shrink_references(..0);
        label.shrink_data(..len);
        Ok(label)
    }
    fn get_label_long(&mut self, max: &mut usize) -> Result<SliceData> {
        let len = self.cursor.get_next_size(*max)? as usize;
        let mut label = self.cursor.clone();
        self.cursor.shrink_data(len..);
        label.shrink_references(..0);
        label.shrink_data(..len);
        *max = max.checked_sub(len).ok_or(ExceptionCode::CellUnderflow)?;
        Ok(label)
    }
    fn get_label_same(&mut self, max: &mut usize, mut key: BuilderData) -> Result<BuilderData> {
        let value = if self.cursor.get_next_bit()? { 0xFF } else { 0 };
        let len = self.cursor.get_next_size(*max)? as usize;
        key.append_raw(&vec![value; len / 8 + 1], len)?;
        *max = max.checked_sub(len).ok_or(ExceptionCode::CellUnderflow)?;
        Ok(key)
    }
    pub fn new(cursor: SliceData) -> Self {
        Self {
            cursor,
            already_read: false
        }
    }
    pub fn with_cell(cursor: &Cell) -> Self {
        Self::new(cursor.into())
    }
    pub fn next_reader<T: HashmapType + ?Sized>(&mut self, index: usize, gas_consumer: &mut dyn GasConsumer) -> Result<Self> {
        if !self.is_fork::<T>()? {
            fail!("this edge must contain fork")
        }
        Ok(Self::new(gas_consumer.load_cell(self.reference(index)?)?))
    }
    pub fn already_read(&self) -> bool {
        self.already_read
    }
    pub fn remainder(self) -> Result<SliceData> {
        if !self.already_read {
            fail!("label not yet read!")
        }
        Ok(self.cursor)
    }
    pub fn reference(&self, index: usize) -> Result<Cell> {
        if !self.already_read {
            fail!("label not yet read!")
        }
        self.cursor.reference(index)
    }
    pub fn get_label_raw(&mut self, max: &mut usize, mut key: BuilderData) -> Result<BuilderData> {
        if self.already_read {
            fail!("label already read!")
        }
        self.already_read = true;
        if self.cursor.is_empty() {
        } else if !self.cursor.get_next_bit()? {
            key.append_bytestring(&self.get_label_short(max)?)?;
        } else if !self.cursor.get_next_bit()? {
            key.append_bytestring(&self.get_label_long(max)?)?;
        } else {
            key = self.get_label_same(max, key)?;
        }
        Ok(key)
    }
    pub fn get_label(&mut self, mut max: usize) -> Result<SliceData> {
        if self.already_read {
            fail!("label already read!")
        }
        self.already_read = true;
        // note: in case of max is 0 it is normal to read bits from the slice
        // but if you mistakely pass 0 to this function it causes undefined behavoiur
        if self.cursor.is_empty() {
            Ok(SliceData::default())
        } else if !self.cursor.get_next_bit()? {
            self.get_label_short(&mut max)
        } else if !self.cursor.get_next_bit()? {
            self.get_label_long(&mut max)
        } else {
            Ok(self.get_label_same(&mut max, BuilderData::default())?.into_cell()?.into())
        }
    }
    pub fn skip_label(&mut self, max: &mut usize) -> Result<()> {
        if self.already_read {
            fail!("label already read!")
        }
        self.already_read = true;
        let mut len = 0;
        // note: in case of max is 0 it is normal to read bits from the slice
        // but if you mistakely pass 0 to this function it causes undefined behavoiur
        if self.cursor.is_empty() {
        } else if !self.cursor.get_next_bit()? {
            while self.cursor.get_next_bit()? {
                len += 1;
            }
            self.cursor.move_by(len)?;
        } else if !self.cursor.get_next_bit()? {
            len = self.cursor.get_next_size(*max)? as usize;
            self.cursor.move_by(len)?;
        } else {
            self.cursor.get_next_bit()?;
            len = self.cursor.get_next_size(*max)? as usize;
        }
        *max = max.checked_sub(len).ok_or(ExceptionCode::CellUnderflow)?;
        Ok(())
    }
    pub fn is_fork<T: HashmapType + ?Sized>(&mut self) -> Result<bool> {
        T::is_fork(&mut self.cursor)
    }
    pub fn is_leaf<T: HashmapType + ?Sized>(&mut self) -> Result<bool> {
        Ok(T::is_leaf(&mut self.cursor))
    }
}

// reading hmLabel from SliceData
// obsolete - don't use, to be removed
// use LabelReader adapter
impl SliceData {
    pub fn get_label_raw(&mut self, max: &mut usize, key: BuilderData) -> Result<BuilderData> {
        let mut cursor = LabelReader::new(std::mem::replace(self, SliceData::default()));
        let key = cursor.get_label_raw(max, key)?;
        *self = cursor.remainder()?;
        Ok(key)
    }
    pub fn get_label(&mut self, max: usize) -> Result<SliceData> {
        let mut cursor = LabelReader::new(std::mem::replace(self, SliceData::default()));
        let key = cursor.get_label(max)?;
        *self = cursor.remainder()?;
        Ok(key)
    }
}

// methods working with root
impl SliceData {
    pub fn is_empty_root(&self) -> bool {
        self.is_empty() || matches!(self.get_bit_opt(0), Some(false))
    }
    pub fn get_dictionary(&mut self) -> Result<SliceData> {
        self.get_dictionary_opt().ok_or_else(|| error!(ExceptionCode::CellUnderflow))
    }

    pub fn get_dictionary_opt(&mut self) -> Option<SliceData> {
        let mut root = self.clone();
        if self.get_next_bit_opt()? == 0 {
            root.shrink_references(..0);
        } else if self.remaining_references() == 0 {
            return None
        } else {
            self.checked_drain_reference().ok()?;
            root.shrink_references(..1);
        }
        root.shrink_data(..1);
        Some(root)
    }
}

#[allow(clippy::too_many_arguments)]
fn find_leaf<T: HashmapType + ?Sized>(
    mut data: Cell,
    path: &mut BuilderData,
    mut bit_len: usize,
    mut key: SliceData,
    next_index: usize,
    eq: bool,
    signed_int: bool,
    gas_consumer: &mut dyn GasConsumer
) -> Result<Option<SliceData>> {
    let mut cursor = gas_consumer.load_cell(data.clone())?;
    let label = cursor.get_label(bit_len)?;
    match SliceData::common_prefix(&key, &label) {
        (_, None, Some(_)) => fail!(ExceptionCode::DictionaryError),
        (prefix_opt, Some(remainder), Some(_)) => { // hm_edge is sliced
            let key_bit = remainder.get_bit(0)? as usize;
            let next = match signed_int && path.is_empty() && prefix_opt.is_none() {
                false => next_index,
                true => 1 - next_index,
            };
            if key_bit != next {
                Ok(None)
            } else {
                get_min_max::<T>(data, path, bit_len, next_index, next, gas_consumer)
            }
        }
        (_, None, None) => if eq { // same leaf found
            path.append_bytestring(&label)?;
            Ok(Some(cursor))
        } else {
            Ok(None)
        }
        (prefix_opt, Some(remainder), None) => { // label fully in key
            if !T::is_fork(&mut cursor)? {
                fail!(ExceptionCode::DictionaryError)
            }
            let next = match signed_int && path.is_empty() && prefix_opt.is_none() {
                false => next_index,
                true => 1 - next_index,
            };
            path.append_bytestring(&label)?;
            key = remainder;
            let key_bit = key.get_next_bit_int()?;
            bit_len = bit_len.checked_sub(label.remaining_bits() + 1).ok_or(ExceptionCode::CellUnderflow)?;
            let length_in_bits = path.length_in_bits();
            path.append_bit_bool(key_bit == 1)?;
            let res = find_leaf::<T>(cursor.reference(key_bit)?, path, bit_len, key, next_index, eq, false, gas_consumer)?;
            if res.is_some() || key_bit != next {
                return Ok(res)
            }
            path.trunc(length_in_bits)?;
            path.append_bit_bool(key_bit == 0)?;
            data = cursor.reference(1 - key_bit)?;
            get_min_max::<T>(data, path, bit_len, next_index, next_index, gas_consumer)
        }
    }
}

/// search min or max element from current subtree. Append path and returns element if found
pub fn get_min_max<T: HashmapType + ?Sized>(
    mut data: Cell,
    path: &mut BuilderData,
    mut bit_len: usize,
    next_index: usize, // 0 - for min, 1 - for max
    mut index: usize,
    gas_consumer: &mut dyn GasConsumer
) -> Result<Option<SliceData>> {
    loop {
        let mut cursor = gas_consumer.load_cell(data)?;
        let label = cursor.get_label(bit_len)?;
        let label_length = label.remaining_bits();
        if path.is_empty() && !label.is_empty() {
            index = next_index;
        }
        path.append_bytestring(&label)?;
        if T::is_fork(&mut cursor)? && bit_len > label_length {
            bit_len -= label_length + 1;
            path.append_bit_bool(index == 1)?;
            data = cursor.reference(index)?;
        } else if bit_len == label_length {
            return Ok(Some(cursor))
        } else {
            fail!(ExceptionCode::DictionaryError)
        }
        index = next_index;
    }
}

// difference for different hashmap types
pub trait HashmapType {
    fn write_hashmap_data(&self, cell: &mut BuilderData) -> Result<()> {
        if let Some(root) = self.data() {
            cell.append_bit_one()?;
            cell.checked_append_reference(root.clone())?;
        } else {
            cell.append_bit_zero()?;
        }
        Ok(())
    }
    fn read_hashmap_data(&mut self, slice: &mut SliceData) -> Result<()> {
        let data = slice.get_dictionary()?;
        *self.data_mut() = data.reference_opt(0);
        Ok(())
    }
    fn is_empty(&self) -> bool {
        self.data().is_none()
    }

    fn check_key(bit_len: usize, key: &SliceData) -> bool;
    fn check_key_fail(bit_len: usize, key: &SliceData) -> Result<()> {
        match !key.is_empty() && Self::check_key(bit_len, key) {
            true => Ok(()),
            false => fail!("Bad key {} for dict", key)
        }
    }
    fn make_cell_with_label(key: SliceData, max: usize) -> Result<BuilderData> { hm_label(&key, max) }
    fn make_cell_with_label_and_data(key: SliceData, max: usize, _is_leaf: bool, data: &SliceData) -> Result<BuilderData> {
        let mut builder = Self::make_cell_with_label(key, max)?;
        builder.checked_append_references_and_data(data)?;
        Ok(builder)
    }
    fn make_cell_with_label_and_builder(key: SliceData, max: usize, _is_leaf: bool, data: &BuilderData) -> Result<BuilderData> {
        let mut builder = Self::make_cell_with_label(key, max)?;
        builder.append_builder(data)?;
        Ok(builder)
    }
    fn make_cell_with_remainder(key: SliceData, max: usize, remainder: &SliceData) -> Result<BuilderData> {
        let mut builder = Self::make_cell_with_label(key, max)?;
        builder.checked_append_references_and_data(remainder)?;
        Ok(builder)
    }
    fn make_edge(key: &SliceData, bit_len: usize, is_left: bool, mut next: SliceData) -> Result<BuilderData> {
        let mut next_bit_len = bit_len.checked_sub(key.remaining_bits() + 1).ok_or(ExceptionCode::CellUnderflow)?;
        let mut label = BuilderData::from_slice(key);
        label.append_bit_bool(!is_left)?;
        label = next.get_label_raw(&mut next_bit_len, label)?;
        let is_leaf = Self::is_leaf(&mut next);
        Self::make_cell_with_label_and_data(label.into_cell()?.into(), bit_len, is_leaf, &next)
    }
    fn make_fork(key: &SliceData, bit_len: usize, mut left: Cell, mut right: Cell, swap: bool) -> Result<(BuilderData, SliceData)> {
        let mut builder = hm_label(key, bit_len)?;
        let mut remainder = BuilderData::new();
        if swap {
            std::mem::swap(&mut left, &mut right);
        }
        remainder.checked_append_reference(left)?;
        remainder.checked_append_reference(right)?;
        builder.append_builder(&remainder)?;
        Ok((builder, remainder.into_cell()?.into()))
    }
    fn make_leaf(key: &SliceData, bit_len: usize, value: &SliceData) -> Result<BuilderData> {
        let mut builder = hm_label(key, bit_len)?;
        builder.checked_append_references_and_data(value)?;
        Ok(builder)
    }
    fn is_fork(slice: &mut SliceData) -> Result<bool>;
    fn is_leaf(slice: &mut SliceData) -> bool;
    fn data(&self) -> Option<&Cell>;
    fn data_mut(&mut self) -> &mut Option<Cell>;
    fn bit_len(&self) -> usize;
    fn bit_len_mut(&mut self) -> &mut usize;
    fn iter(&self) -> HashmapIterator<Self> {
        HashmapIterator::from_hashmap(self)
    }
    fn count_cells(&self, max: usize) -> Result<usize> {
        match self.data() {
            Some(root) => root.count_cells(max),
            None => Ok(0)
        }
    }
    fn hashmap_get(&self, mut key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        let mut bit_len = self.bit_len();
        Self::check_key_fail(bit_len, &key)?;
        let mut cursor = match self.data().cloned() {
            Some(root) => gas_consumer.load_cell(root)?,
            _ => return Ok(None)
        };
        let mut label = cursor.get_label(bit_len)?;
        while key.erase_prefix(&label) && !key.is_empty() {
            if !Self::is_fork(&mut cursor)? {
                return Ok(None)
            }
            let next_index = key.get_next_bit_int()?;
            cursor = gas_consumer.load_cell(cursor.reference(next_index)?)?;
            bit_len = bit_len.checked_sub(label.remaining_bits() + 1).ok_or(ExceptionCode::CellUnderflow)?;
            label = cursor.get_label(bit_len)?;
        }
        if key.is_empty() && Self::is_leaf(&mut cursor) {
            Ok(Some(cursor))
        } else {
            Ok(None)
        }
    }

    fn hashmap_get_new(&self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        let bit_len = self.bit_len();
        Self::check_key_fail(bit_len, &key)?;
        if let Some(root) = self.data() {
            let mut cursor = LabelReader::new(gas_consumer.load_cell(root.clone())?);
            let (_key, rem_prefix) = down_by_tree::<Self>(&key, &mut cursor, self.bit_len(), gas_consumer)?;
            if rem_prefix.is_none() {
                let mut remainder = cursor.remainder()?;
                if Self::is_leaf(&mut remainder) {
                    return Ok(Some(remainder))
                }
            }
        }
        Ok(None)
    }

    fn hashmap_set_with_mode(
        &mut self,
        key: SliceData,
        leaf: &BuilderData,
        gas_consumer: &mut dyn GasConsumer,
        mode: u8
    ) -> Leaf {
        let bit_len = self.bit_len();
        Self::check_key_fail(bit_len, &key)?;
        if let Some(root) = self.data() {
            let mut root = root.clone();
            let result = put_to_node_with_mode::<Self>(&mut root, bit_len, key, leaf, gas_consumer, mode);
            *self.data_mut() = Some(root);
            result
        } else if mode.bit(ADD) {
            let cell = gas_consumer.finalize_cell(Self::make_cell_with_label_and_builder(key, bit_len, true, leaf)?)?;
            *self.data_mut() = Some(cell);
            Ok(None)
        } else {
            Ok(None)
        }
    }

    fn hashmap_setref_with_mode(
        &mut self,
        key: SliceData,
        value: &Cell,
        gas_consumer: &mut dyn GasConsumer,
        mode: u8
    ) -> Leaf {
        let mut builder = BuilderData::default();
        builder.checked_append_reference(value.clone())?;
        self.hashmap_set_with_mode(key, &builder, gas_consumer, mode)
    }

    /// iterate all elements with callback function
    fn iterate_slices<F> (&self, mut p: F) -> Result<bool>
    where F: FnMut(SliceData, SliceData) -> Result<bool> {
        if let Some(root) = self.data() {
            iterate_internal::<Self, _>(
                LabelReader::with_cell(root),
                BuilderData::default(),
                self.bit_len(),
                &mut |k, v| p(k.into_cell()?.into(), v))
        } else {
            Ok(true)
        }
    }

    /// returns count of objects in tree - don't use it - try is_empty()
    fn len(&self) -> Result<usize> {
        match self.data() {
            Some(root) => {
                let mut len = 0;
                let cursor = LabelReader::with_cell(root);
                count_internal::<Self>(cursor, self.bit_len(), &mut len, std::usize::MAX)?;
                Ok(len)
            }
            None => Ok(0)
        }
    }
    /// counts elements to max counter - can be used as validate
    fn count(&self, max: usize) -> Result<usize> {
        match self.data() {
            Some(root) => {
                let mut len = 0;
                let cursor = LabelReader::with_cell(root);
                count_internal::<Self>(cursor, self.bit_len(), &mut len, max)?;
                Ok(len)
            }
            None => Ok(0)
        }
    }
    /// determines if hashmap contains one element
    fn is_single(&self) -> Result<Option<(BuilderData, SliceData)>> {
        if let Some(root) = self.data() {
            let mut bit_len = self.bit_len();
            let mut cursor = LabelReader::with_cell(root);
            let key = cursor.get_label_raw(&mut bit_len, BuilderData::default())?;
            if bit_len == 0 {
                return Ok(Some((key, cursor.remainder()?)))
            }
        }
        Ok(None)
    }
    // split
    fn hashmap_split(&self, key: &SliceData) -> Result<(Option<Cell>, Option<Cell>)> {
        let mut bit_len = self.bit_len();
        let data = match self.data() {
            Some(data) => data,
            _ => return Ok((None, None))
        };
        let mut cursor = SliceData::from(data.clone());
        let label = cursor.get_label(bit_len)?;
        let (left, right) = match SliceData::common_prefix(&label, key) {
            // normal case label == key
            (_prefix, None, None) => {
                bit_len = bit_len.checked_sub(label.remaining_bits() + 1).ok_or(ExceptionCode::CellUnderflow)?;
                (cursor.reference(0)?, cursor.reference(1)?)
            }
            // normal case with empty branch
            (_prefix, Some(mut label_remainder), None) => match label_remainder.get_next_bit()? {
                false => return Ok((Some(data.clone()), None)),
                true  => return Ok((None, Some(data.clone()))),
            }
            // wrong hashmap tree
            _ => fail!("split fail: root label: x{:x} and key: x{:x}", label, key),
        };
        cursor = SliceData::from(left);
        let label = cursor.get_label(bit_len)?;
        let mut builder = BuilderData::from_slice(key);
        builder.append_bit_zero()?;
        builder.append_bytestring(&label)?;
        let left = Self::make_cell_with_label_and_data(builder.into_cell()?.into(), self.bit_len(), false, &cursor)?;

        cursor = SliceData::from(right);
        let label = cursor.get_label(bit_len)?;
        let mut builder = BuilderData::from_slice(key);
        builder.append_bit_one()?;
        builder.append_bytestring(&label)?;
        let right = Self::make_cell_with_label_and_data(builder.into_cell()?.into(), self.bit_len(), false, &cursor)?;

        Ok((Some(left.into_cell()?), Some(right.into_cell()?)))
    }
    // merge
    fn hashmap_merge(&mut self, other: &Self, key: &SliceData) -> Result<()> {
        let bit_len = self.bit_len();
        if bit_len != other.bit_len() || key.remaining_bits() > bit_len {
            return Ok(()) // fail!("data in hashmaps do not correspond each other or key too long")
        }
        let mut cursor = match self.data() {
            Some(data) => SliceData::from(data),
            None => {
                *self.data_mut() = other.data().cloned();
                return Ok(())
            }
        };
        let mut other = match other.data() {
            Some(data) => SliceData::from(data),
            None => return Ok(())
        };
        let label1 = cursor.get_label(bit_len)?;
        let label2 = other.get_label(bit_len)?;
        match SliceData::common_prefix(&label1, &label2) {
            (prefix, Some(mut left), Some(mut right)) => {
                let prefix = prefix.unwrap_or_default();
                if let (_, _, Some(_)) = SliceData::common_prefix(&prefix, key) {
                    fail!("common prefix of merging hashmaps is too short")
                }
                let left_bit = left.get_next_bit()?;
                let right_bit = right.get_next_bit()?;
                if left_bit && !right_bit {
                    std::mem::swap(&mut left, &mut right);
                    std::mem::swap(&mut cursor, &mut other);
                }
                let is_leaf1 = Self::is_leaf(&mut cursor);
                let is_leaf2 = Self::is_leaf(&mut other);

                let next_bit_len = bit_len.checked_sub(prefix.remaining_bits() + 1).ok_or(ExceptionCode::CellUnderflow)?;
                let left = Self::make_cell_with_label_and_data(left, next_bit_len, is_leaf1, &cursor)?;
                let right = Self::make_cell_with_label_and_data(right, next_bit_len, is_leaf2, &other)?;
                let (root, _) = Self::make_fork(&prefix, bit_len, left.into_cell()?, right.into_cell()?, false)?;
                *self.data_mut() = Some(root.into_cell()?);
            }
            _ => fail!("Cannot merge")
        }
        Ok(())
    }

    fn scan_diff<F>(&self, other: &Self, mut func: F) -> Result<bool> 
    where F: FnMut(SliceData, Option<SliceData>, Option<SliceData>) -> Result<bool> {
        let bit_len = self.bit_len();
        if bit_len != other.bit_len() {
            fail!("Different bitlen")
        }
        dict_scan_diff::<Self, _>(self.data().cloned(), other.data().cloned(), BuilderData::default(), bit_len, bit_len, &mut func)
    }

    /// combine all items from two hashamps
    /// will fail if trees have different items with same key
    fn combine_with(&mut self, other: &Self) -> Result<bool> {
        let bit_len = self.bit_len();
        if bit_len != other.bit_len() {
            fail!("Different bitlen")
        }
        match (self.data().cloned(), other.data().cloned()) {
            (Some(mut cell1), Some(cell2)) => {
                if dict_combine_with_cell::<Self>(&mut cell1, cell2, bit_len)? {
                    *self.data_mut() = Some(cell1);
                    return Ok(true)
                }
                Ok(false)
            }
            (None, Some(cell2)) => {
                *self.data_mut() = Some(cell2);
                Ok(true)
            }
            (_, None) => Ok(false)
        }
    }
}

fn dict_combine_with_cell<T: HashmapType + ?Sized>(cell1: &mut Cell, cell2: Cell, bit_len: usize) -> Result<bool> {
    let mut cursor2 = SliceData::from(cell2);
    let label2 = cursor2.get_label(bit_len)?;
    let bit_len2 = bit_len.checked_sub(label2.remaining_bits()).ok_or(ExceptionCode::CellUnderflow)?;
    dict_combine_with::<T>(cell1, bit_len, cursor2, label2, bit_len2)
}

fn dict_combine_with<T: HashmapType + ?Sized>(
    cell1: &mut Cell, bit_len: usize,
    mut cursor2: SliceData, label2: SliceData, bit_len2: usize
) -> Result<bool> {
    let mut cursor1 = SliceData::from(cell1.clone());
    let label1 = cursor1.get_label(bit_len)?;
    let bit_len1 = bit_len.checked_sub(label1.remaining_bits()).ok_or(ExceptionCode::CellUnderflow)?;
    match SliceData::common_prefix(&label1, &label2) {
        (_prefix_opt, None, None) => {
            if cursor1 == cursor2 { // same level
                return Ok(false)
            } else if bit_len1 == 0 { // do not allow to replace leafs
                fail!(ExceptionCode::DictionaryError)
            } else { // continue like with two separate trees
                let mut left1 = cursor1.checked_drain_reference()?;
                let left2 = cursor2.checked_drain_reference()?;
                let mut right1 = cursor1.checked_drain_reference()?;
                let right2 = cursor2.checked_drain_reference()?;
                if dict_combine_with_cell::<T>(&mut left1, left2, bit_len1 - 1)? |
                    dict_combine_with_cell::<T>(&mut right1, right2, bit_len1 - 1)? {
                    *cell1 = T::make_fork(&label1, bit_len, left1, right1, false)?.0.into_cell()?;
                    return Ok(true)
                }
            }
        }
        (prefix_opt, Some(mut rem1), rem2_opt) => { // slice edge
            let next_index = rem1.get_next_bit_int()?;
            *cell1 = if let Some(mut rem2) = rem2_opt { // simple slice of both trees and make new fork
                rem2.get_next_bit_int()?; // == 1 - next_index
                let prefix = prefix_opt.unwrap_or_default(); // 
                let bit_len1 = bit_len - prefix.remaining_bits() - 1;
                let left = T::make_cell_with_remainder(rem1, bit_len1, &cursor1)?.into_cell()?;
                let right = T::make_cell_with_remainder(rem2, bit_len1, &cursor2)?.into_cell()?;
                T::make_fork(&prefix, bit_len, left, right, next_index != 0)?.0.into_cell()?
            } else if bit_len2 == 0 { // second should not stop here
                fail!(ExceptionCode::DictionaryError)
            } else { // slice edge of first and add items from first to second, then make new fork
                let mut next = cursor2.reference(next_index)?;
                let other = cursor2.reference(1 - next_index)?;
                dict_combine_with::<T>(&mut next, bit_len2 - 1, cursor1, rem1, bit_len1)?;
                T::make_fork(&label2, bit_len, next, other, next_index != 0)?.0.into_cell()?
            };
            return Ok(true)
        }
        (_prefix_opt, None, Some(mut rem2)) => {
            if bit_len1 == 0 { // it should not be leaf
                fail!(ExceptionCode::DictionaryError)
            } else { // select branch and continue, then make new fork
                let next_index = rem2.get_next_bit_int()?;
                let mut next = cursor1.reference(next_index)?;
                let other = cursor1.reference(1 - next_index)?;
                if !dict_combine_with::<T>(&mut next, bit_len1 - 1, cursor2, rem2, bit_len2)? {
                    return Ok(false)
                }
                *cell1 = T::make_fork(&label1, bit_len, next, other, next_index != 0)?.0.into_cell()?;
                return Ok(true)
            }
        }
    }
    Ok(false)
}

fn scan_diff_leaf_reched<T, F>(
    cursor_1: LabelReader,
    cursor_2: LabelReader,
    key1: BuilderData,
    key2: BuilderData,
    bit_len_1: usize,
    bit_len_2: usize,
    func: &mut F
) -> Result<bool>
where
    T: HashmapType + ?Sized,
    F: FnMut(SliceData, Option<SliceData>, Option<SliceData>) -> Result<bool> {
    debug_assert!(bit_len_1 == 0 || bit_len_2 == 0, "should be called only if one leaf reached");
    if bit_len_1 == 0 && bit_len_2 == 0 { // 1 and 2 leaves reached
        if key1 == key2 {
            if cursor_1 != cursor_2 {
                return func(key1.into_cell()?.into(), Some(cursor_1.remainder()?), Some(cursor_2.remainder()?))
            }
        } else if !func(key1.into_cell()?.into(), Some(cursor_1.remainder()?), None)? || !func(key2.into_cell()?.into(), None, Some(cursor_2.remainder()?))? {
            return Ok(false)
        }
    } else if bit_len_1 == 0 { // leaf of 1 is reached
        let mut chk = false;
        let cursor_1 = cursor_1.remainder()?;
        if !iterate_internal::<T, _>(
            cursor_2,
            key2,
            bit_len_2,
            &mut |key, cursor| if key1 != key {
                func(key.into_cell()?.into(), None, Some(cursor))
            } else { 
                chk = true; 
                match cursor == cursor_1 {
                    true => Ok(true),
                    false => func(key.into_cell()?.into(), Some(cursor_1.clone()), Some(cursor))
                }
            }
        )? || (!chk && !func(key1.into_cell()?.into(), Some(cursor_1.clone()), None)?) {
            return Ok(false)
        }
    } else { // leaf of 2 is reached
        debug_assert_eq!(bit_len_2, 0);
        let mut chk = false;
        let cursor_2 = cursor_2.remainder()?;
        if !iterate_internal::<T, _>(
            cursor_1,
            key1,
            bit_len_1,
            &mut |key, cursor| if key2 != key {
                func(key.into_cell()?.into(), Some(cursor), None)
            } else {
                chk = true;
                match cursor == cursor_2 {
                    true => Ok(true),
                    false => func(key.into_cell()?.into(), Some(cursor), Some(cursor_2.clone()))
                }
            }
        )? || (!chk && !func(key2.into_cell()?.into(), None, Some(cursor_2.clone()))?) {
            return Ok(false)
        }
    }
    Ok(true)
}
fn dict_scan_diff<T, F>(
    cell_1: Option<Cell>,
    cell_2: Option<Cell>,
    key: BuilderData,
    mut bit_len_1 : usize,
    mut bit_len_2 : usize,
    func: &mut F
) -> Result<bool>
where
    F: FnMut(SliceData, Option<SliceData>, Option<SliceData>) -> Result<bool>,
    T: HashmapType + ?Sized {
    let (mut cursor_1, mut cursor_2) = match (cell_1, cell_2) {
        (Some(cell_1), Some(cell_2)) => if cell_1 == cell_2 {
            return Ok(true)
        } else {
            (LabelReader::new(SliceData::from(cell_1)), LabelReader::new(SliceData::from(cell_2)))
        }
        (Some(cell), None) => return iterate_internal::<T, _>( // only 1 leaves
            LabelReader::with_cell(&cell),
            key,
            bit_len_1,
            &mut |key, cursor| func(key.into_cell()?.into(), Some(cursor), None)
        ),
        (None, Some(cell)) => return iterate_internal::<T, _>( // only 2 leaves
            LabelReader::with_cell(&cell),
            key,
            bit_len_2,
            &mut |key, cursor| func(key.into_cell()?.into(), None, Some(cursor))
        ),
        _ => return Ok(true)
    };
    let mut key1 = cursor_1.get_label_raw(&mut bit_len_1, key.clone())?;
    let mut key2 = cursor_2.get_label_raw(&mut bit_len_2, key)?;
    loop {
        if bit_len_1 == 0 || bit_len_2 == 0 { // 1 and/or 2 leaf reached
            return scan_diff_leaf_reched::<T, _>(cursor_1, cursor_2, key1, key2, bit_len_1, bit_len_2, func)
        } else if key1 == key2 { // same level is reached
            if cursor_1 == cursor_2 {
                return Ok(true)
            } else if bit_len_1 == 0 { // same 1 and 2 leaves reached
                return func(key1.into_cell()?.into(), Some(cursor_1.remainder()?), Some(cursor_2.remainder()?))
            } else { // same branch reached - continue scan_diff as from start
                debug_assert_eq!(bit_len_1, bit_len_2);
                bit_len_1 -= 1;
                for i in 0..2 {
                    let mut key = key1.clone();
                    key.append_bit_bool(i != 0)?;
                    let child1 = Some(cursor_1.reference(i)?);
                    let child2 = Some(cursor_2.reference(i)?);
                    if !dict_scan_diff::<T, _>(child1, child2, key, bit_len_1, bit_len_1, func)? {
                        return Ok(false)
                    }
                }
                return Ok(true)
            }
        }
        match key1.compare_data(&key2)? {
            (Some(next_bit), None) => { // key1 includes key2
                bit_len_2 -= 1;
                let mut key = key2.clone();
                key.append_bit_bool(next_bit == 0)?;
                if !dict_scan_diff::<T, _>(None, Some(cursor_2.reference(1 - next_bit)?), key, 0, bit_len_2, func)? {
                    return Ok(false)
                }
                key2.append_bit_bool(next_bit == 1)?;
                cursor_2 = cursor_2.next_reader::<T>(next_bit, &mut 0)?;
                key2 = cursor_2.get_label_raw(&mut bit_len_2, key2)?;
            }
            (None, Some(next_bit)) => { // key2 includes key1
                bit_len_1 -= 1;
                let mut key = key1.clone();
                key.append_bit_bool(next_bit == 0)?;
                if !dict_scan_diff::<T, _>(Some(cursor_1.reference(1 - next_bit)?), None, key, bit_len_1, 0, func)? {
                    return Ok(false)
                }
                key1.append_bit_bool(next_bit == 1)?;
                cursor_1 = cursor_1.next_reader::<T>(next_bit, &mut 0)?;
                key1 = cursor_1.get_label_raw(&mut bit_len_1, key1)?;
            }
            (Some(_), Some(_)) => { // 1 and 2 are different - iterate both
                bit_len_1 -= 1;
                bit_len_2 -= 1;
                for i in 0..2 {
                    let mut key = key1.clone();
                    key.append_bit_bool(i == 1)?;
                    if !dict_scan_diff::<T, _>(Some(cursor_1.reference(i)?), None, key, bit_len_1, 0, func)? {
                        return Ok(false)
                    }
                    let mut key = key2.clone();
                    key.append_bit_bool(i == 1)?;
                    if !dict_scan_diff::<T, _>(None, Some(cursor_2.reference(i)?), key, 0, bit_len_2, func)? {
                        return Ok(false)
                    }
                }
                return Ok(true)
            }
            (None, None) => unreachable!("checked upper")
        }
    }
}

/// iterate all elements with callback function
fn iterate_internal<T, F>(
    mut cursor: LabelReader,
    mut key: BuilderData, 
    mut bit_len: usize, 
    found: &mut F
) -> Result<bool>
where
    F: FnMut(BuilderData, SliceData) -> Result<bool>,
    T: HashmapType + ?Sized
{
    if !cursor.already_read() {
        key = cursor.get_label_raw(&mut bit_len, key)?;
    }
    if bit_len == 0 {
        found(key, cursor.remainder()?)
    } else {
        bit_len -= 1;
        for i in 0..2 {
            let mut key = key.clone();
            key.append_bit_bool(i != 0)?;
            if !iterate_internal::<T, F>(cursor.next_reader::<T>(i, &mut 0)?, key, bit_len, found)? {
                return Ok(false)
            }
        }
        Ok(true)
    }
}

/// count all elements with callback function
fn count_internal<T: HashmapType + ?Sized>(
    mut cursor: LabelReader,
    mut bit_len: usize,
    len: &mut usize,
    max: usize,
) -> Result<bool> {
    if !cursor.already_read() {
        cursor.skip_label(&mut bit_len)?;
    }
    match bit_len.checked_sub(1) {
        Some(bit_len) => for i in 0..2 {
            if !count_internal::<T>(cursor.next_reader::<T>(i, &mut 0)?, bit_len, len, max)? {
                return Ok(false)
            }
        }
        None if *len == max => return Ok(false),
        None => *len += 1
    }
    Ok(true)
}

/// Puts element to required branch by first bit
fn put_to_fork_with_mode<T: HashmapType + ?Sized>(
    slice: &mut SliceData, // TODO: BuilderData
    bit_len: usize,
    mut key: SliceData,
    leaf: &BuilderData,
    gas_consumer: &mut dyn GasConsumer,
    mode: u8
) -> Leaf {
    debug_assert!(slice.remaining_bits() == 0);
    let result;
    let next_index = key.get_next_bit_int()?;
    // hmn_fork#_ {n:#} {X:Type} left:^(Hashmap n X) right:^(Hashmap n X) = HashmapNode (n+1) X;
    let mut builder = BuilderData::new();
    if slice.remaining_references() != 2 {
        fail!(ExceptionCode::CellUnderflow)
    } else {
        if next_index == 1 {
            builder.checked_append_reference(slice.checked_drain_reference()?)?;
        }
        let mut cell = slice.checked_drain_reference()?;
        let bit_len = bit_len.checked_sub(1).ok_or(ExceptionCode::CellUnderflow)?;
        result = put_to_node_with_mode::<T>(&mut cell, bit_len, key, leaf, gas_consumer, mode);
        builder.checked_append_reference(cell)?;
        if next_index == 0 {
            builder.checked_append_reference(slice.checked_drain_reference()?)?;
        }
    }
    *slice = builder.into_cell()?.into();
    result
}

/// Continues or finishes search of place
fn put_to_node_with_mode<T: HashmapType + ?Sized>(
    cell: &mut Cell,
    bit_len: usize,
    key: SliceData,
    leaf: &BuilderData,
    gas_consumer: &mut dyn GasConsumer,
    mode: u8
) -> Leaf {
    let mut result = Ok(None);
    let mut slice = gas_consumer.load_cell(cell.clone())?;
    let label = slice.get_label(bit_len)?;
    if label == key {
        // replace existing leaf
        if T::is_leaf(&mut slice) {
            result = Ok(Some(slice));
            if mode.bit(REPLACE) {
                *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_builder(key, bit_len, true, leaf)?)?;
            }
        } else {
            fail!(ExceptionCode::FatalError)
        }
    } else if label.is_empty() {
        // 1-bit edge
        let is_leaf = T::is_leaf(&mut slice);
        match put_to_fork_with_mode::<T>(&mut slice, bit_len, key, leaf, gas_consumer, mode)? {
            None => {
                if mode.bit(ADD) {
                    *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label, bit_len, is_leaf, &slice)?)?;
                }
            }
            Some(val) => {
                if mode.bit(REPLACE) {
                    *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label, bit_len, is_leaf, &slice)?)?;
                }
                result = Ok(Some(val));
            }
        }
    } else {
        match SliceData::common_prefix(&label, &key) {
            (_, _, None) => {// variable length: key shorter than edge
                if mode.bit(ADD) {
                    let is_leaf = T::is_leaf(&mut slice);
                    *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label, bit_len, is_leaf, &slice)?)?;
                }
            }
            (label_prefix, Some(label_remainder), Some(key_remainder)) => {
                if mode.bit(ADD) {
                    let b = slice_edge::<T>(
                        slice, bit_len,
                        label_prefix.unwrap_or_default(), label_remainder, key_remainder,
                        leaf, gas_consumer
                    )?;
                    *cell = gas_consumer.finalize_cell(b)?;
                }
            }
            (Some(prefix), None, Some(key_remainder)) => {
                // next iteration
                let is_leaf = T::is_leaf(&mut slice);
                result = put_to_fork_with_mode::<T>(
                    &mut slice,
                    bit_len.checked_sub(prefix.remaining_bits()).ok_or(ExceptionCode::CellUnderflow)?,
                    key_remainder, leaf, gas_consumer, mode
                );                                        
                let make_cell = match result {
                    Ok(None) => mode.bit(ADD),
                    Ok(Some(_)) => mode.bit(REPLACE),
                    _ => false                    
                };
                if make_cell {
                    *cell = gas_consumer.finalize_cell(
                        T::make_cell_with_label_and_data(label, bit_len, is_leaf, &slice)?
                    )?;
                }
            }
            error @ (_, _, _) => {
                log::error!(
                    target: "tvm",  
                    "If we hit this, there's certainly a bug. {:?}. \
                     Passed: label: {}, key: {} ", 
                    error, label, key
                );
                fail!(ExceptionCode::FatalError)
            }
        }
    };
    result
}

/// Slices the edge and put new leaf
fn slice_edge<T: HashmapType + ?Sized>(
    mut slice: SliceData,
    bit_len: usize,
    prefix: SliceData,
    mut label: SliceData,
    mut key: SliceData,
    leaf: &BuilderData,
    gas_consumer: &mut dyn GasConsumer
) -> Result<BuilderData> {
    key.shrink_data(1..);
    let label_bit = label.get_next_bit()?;
    let length = bit_len.checked_sub(prefix.remaining_bits() + 1).ok_or(ExceptionCode::CellUnderflow)?;
    let is_leaf = T::is_leaf(&mut slice);
    // Remainder of tree
    let existing_cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label, length, is_leaf, &slice)?)?;
    // Leaf for fork
    let another_cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_builder(key, length, true, leaf)?)?;
    let (builder, _remainder) = T::make_fork(&prefix, bit_len, existing_cell, another_cell, label_bit)?;
    Ok(builder)
}

// remove method
fn remove_node<T: HashmapType + ?Sized>(
    cell_opt: &mut Option<Cell>,
    bit_len: usize,
    key: SliceData,
    gas_consumer: &mut dyn GasConsumer
) -> Leaf {
    let mut cursor = match cell_opt {
        Some(cell) => gas_consumer.load_cell(cell.clone())?,
        _ => return Ok(None)
    };
    let label = cursor.get_label(bit_len)?;
    match SliceData::common_prefix(&label, &key) {
        (_, None, Some(mut reminder)) => {
            if let Some(next_bit_len) = bit_len.checked_sub(1 + label.remaining_bits()) {
                if T::is_fork(&mut cursor)? {
                    let next_index = reminder.get_next_bit_int()?;
                    let mut next_cell = Some(cursor.reference(next_index)?);
                    let result = remove_node::<T>(&mut next_cell, next_bit_len, reminder, gas_consumer)?;
                    if result.is_some() {
                        let other = cursor.reference(1 - next_index)?;
                        if let Some(next) = next_cell {
                            let (builder, _remainder) = T::make_fork(&label, bit_len, next, other, next_index == 1)?;
                            *cell_opt = Some(gas_consumer.finalize_cell(builder)?)
                        } else {
                            let builder = T::make_edge(&label, bit_len, next_index == 1, gas_consumer.load_cell(other)?)?;
                            *cell_opt = Some(gas_consumer.finalize_cell(builder)?)
                        }
                    }
                    return Ok(result)
                }
            }
            fail!(ExceptionCode::CellUnderflow)
        }
        (_, None, None) => {
            if T::is_leaf(&mut cursor) {
                *cell_opt = None;
                Ok(Some(cursor))
            } else {
                fail!(ExceptionCode::CellUnderflow)
            }
        }
        (_, Some(_), Some(_)) => Ok(None),
        (_, Some(_), _) => fail!(ExceptionCode::CellUnderflow)
    }
}

#[derive(Clone, Debug, Eq, PartialEq)]
pub enum HashmapFilterResult {
    Cancel, // cancel traverse and skip changes
    Stop,   // cancel traverse and accept changes
    Remove, // remove element and continue
    Accept, // accept element and continue
}

pub trait HashmapRemover: HashmapType {
    fn hashmap_remove(&mut self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        let bit_len = self.bit_len();
        Self::check_key_fail(bit_len, &key)?;
        remove_node::<Self>(self.data_mut(), bit_len, key, gas_consumer)
    }
    fn remove(&mut self, key: SliceData) -> Leaf {
        self.hashmap_remove(key, &mut 0)
    }
    fn hashmap_filter<F>(&mut self, mut func: F) -> Result<()>
    where F: FnMut(&BuilderData, SliceData) -> Result<HashmapFilterResult> {
        let bit_len = self.bit_len();
        let mut result = HashmapFilterResult::Accept;
        filter_next::<Self, _>(self.data_mut(), &mut BuilderData::default(), bit_len, &mut result, &mut func)?;
        Ok(())
    }
}

fn filter_next<T, F>(
    cell_opt: &mut Option<Cell>,
    key: &mut BuilderData,
    mut bit_len: usize,
    result: &mut HashmapFilterResult,
    func: &mut F,
) -> Result<(bool, Option<SliceData>)> // is_removed and remainder
where
    T: HashmapType + ?Sized,
    F: FnMut(&BuilderData, SliceData) -> Result<HashmapFilterResult>
{
    if *result == HashmapFilterResult::Cancel || *result == HashmapFilterResult::Stop {
        return Ok((false, None))
    }
    let mut cursor = match cell_opt {
        None => { // it only for root
            *result = HashmapFilterResult::Cancel;
            return Ok((false, None))
        }
        Some(cell) => SliceData::from(cell.clone()),
    };
    let key_length = key.length_in_bits();
    let this_bit_len = bit_len;
    *key = cursor.get_label_raw(&mut bit_len, std::mem::replace(key, BuilderData::default()))?;
    let remainder = cursor.clone();
    if bit_len == 0 {
        let removed = match func(key, cursor)? {
            HashmapFilterResult::Remove => {
                *cell_opt = None;
                true
            }
            HashmapFilterResult::Accept => false,
            new_result => {
                *result = new_result;
                false
            }
        };
        return Ok((removed, Some(remainder)))
    }
    let mut changed = false;
    bit_len -= 1;
    let mut next = vec![];
    for i in 0..2 {
        let mut key = key.clone();
        key.append_bit_bool(i == 1)?;
        let mut cell = Some(cursor.checked_drain_reference()?);
        let (removed, remainder) = filter_next::<T, F>(&mut cell, &mut key, bit_len, result, func)?;
        if *result == HashmapFilterResult::Cancel {
            return Ok((false, None))
        }
        changed |= removed;
        if let Some(cell) = cell {
            next.push((cell, key, remainder));
        }
    }
    if !changed {
        Ok((false, Some(remainder)))
    } else if let Some((right, new_key, next_remainder)) = next.pop() {
        if let Some((left, _, _)) = next.pop() { // prepare new fork
            let mut label = SliceData::from(key.clone().into_cell()?);
            label.move_by(key_length)?;
            let (builder, remainder) = T::make_fork(&label, this_bit_len, left, right, false)?;
            *cell_opt = Some(builder.into_cell()?);
            Ok((true, Some(remainder)))
        } else { // replace fork with edge
            *key = new_key;
            let mut label = SliceData::from(key.clone().into_cell()?);
            label.move_by(key_length)?;
            let mut builder = T::make_cell_with_label(label, this_bit_len)?;
            if let Some(ref remainder) = next_remainder {
                builder.checked_append_references_and_data(remainder)?;
            }
            *cell_opt = Some(builder.into_cell()?);
            Ok((true, next_remainder))
        }
    } else {
        *cell_opt = None;
        Ok((true, None))
    }
}

pub trait HashmapSubtree: HashmapType + Sized {
    /// transform to subtree with the common prefix
    // #[deprecated]
    #[allow(clippy::wrong_self_convention)]
    fn into_subtree_with_prefix(&mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<()> {
        self.subtree_with_prefix(prefix, gas_consumer)
    }
    /// transform to subtree with the common prefix
    fn subtree_with_prefix(&mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<()> {
        let prefix_len = prefix.remaining_bits();
        if prefix_len == 0 || self.bit_len() < prefix_len {
            return Ok(())
        }
        if let Some(root) = self.data() {
            let mut cursor = LabelReader::new(gas_consumer.load_cell(root.clone())?);
            let (key, rem_prefix) = down_by_tree::<Self>(prefix, &mut cursor, self.bit_len(), gas_consumer)?;
            if rem_prefix.is_none() {
                let label = SliceData::from(key.into_cell()?);
                let mut remainder = cursor.remainder()?;
                let is_leaf = Self::is_leaf(&mut remainder);
                if remainder.cell() != root {
                    let root = Self::make_cell_with_label_and_data(label, self.bit_len(), is_leaf, &remainder)?;
                    *self.data_mut() = Some(gas_consumer.finalize_cell(root)?)
                }
            } else {
                *self.data_mut() = None
            }
        }
        Ok(())
    }

    /// transform to subtree with the common prefix
    fn into_subtree_w_prefix(mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<Self> {
        self.subtree_with_prefix(prefix, gas_consumer)?;
        Ok(self)
    }

    /// transform to subtree without the common prefix (dec bit_len)
    // #[deprecated]
    #[allow(clippy::wrong_self_convention)]
    fn into_subtree_without_prefix(&mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer)-> Result<()> {
        self.subtree_without_prefix(prefix, gas_consumer)
    }
    /// transform to subtree without the common prefix (dec bit_len)
    fn subtree_without_prefix(&mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer)-> Result<()> {
        let prefix_len = prefix.remaining_bits();
        if prefix_len == 0 || self.bit_len() < prefix_len {
            return Ok(())
        }
        if let Some(root) = self.data() {
            let mut cursor = LabelReader::new(gas_consumer.load_cell(root.clone())?);
            let (key, rem_prefix) = down_by_tree::<Self>(prefix, &mut cursor, self.bit_len(), gas_consumer)?;
            if rem_prefix.is_none() {
                let mut label = SliceData::from(key.into_cell()?);
                label.shrink_data(prefix_len..);
                let mut remainder = cursor.remainder()?;
                let is_leaf = Self::is_leaf(&mut remainder);
                *self.bit_len_mut() -= prefix_len;
                let root = Self::make_cell_with_label_and_data(label, self.bit_len(), is_leaf, &remainder)?;
                *self.data_mut() = Some(gas_consumer.finalize_cell(root)?)
            } else {
                *self.data_mut() = None
            }
        }
        Ok(())
    }

    /// transform to subtree without the common prefix (dec bit_len)
    fn into_subtree_wo_prefix(mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer)-> Result<Self> {
        self.subtree_without_prefix(prefix, gas_consumer)?;
        Ok(self)
    }

    /// transform to subtree with the maximal common prefix
    fn into_subtree_with_prefix_not_exact(mut self, prefix: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<Self> {
        let bit_len = self.bit_len();
        if bit_len <= prefix.remaining_bits() {
            return Ok(self)
        }
        if let Some(root) = self.data() {
            let mut cursor = LabelReader::new(gas_consumer.load_cell(root.clone())?);
            let (key, rem_prefix) = down_by_tree::<Self>(prefix, &mut cursor, self.bit_len(), gas_consumer)?;
            if rem_prefix.as_ref() == Some(prefix) {
                *self.data_mut() = None;
                return Ok(self)
            }
            let mut remainder = cursor.remainder()?;
            let is_leaf = Self::is_leaf(&mut remainder);
            let root = Self::make_cell_with_label_and_data(key.into_cell()?.into(), self.bit_len(), is_leaf, &remainder)?;
            *self.data_mut() = Some(gas_consumer.finalize_cell(root)?);
        }
        Ok(self)
    }
}

fn down_by_tree<T>(prefix: &SliceData, cursor: &mut LabelReader, mut bit_len: usize, gas_consumer: &mut dyn GasConsumer)
-> Result<(BuilderData, Option<SliceData>)>
where T: HashmapType + ?Sized {
    let mut key = BuilderData::default();
    loop {
        key = cursor.get_label_raw(&mut bit_len, key)?;
        let label = SliceData::from(key.clone().into_cell()?);
        match SliceData::common_prefix(&label, prefix) {
            (_, None, Some(mut rem_prefix)) => { // continue down
                bit_len = bit_len.checked_sub(1).ok_or(ExceptionCode::CellUnderflow)?;
                let next_index = rem_prefix.get_next_bit_int()?;
                key.append_bit_bool(next_index == 1)?;
                *cursor = cursor.next_reader::<T>(next_index, gas_consumer)?;
            }
            (_, _, rem_prefix) => return Ok((key, rem_prefix))
        }
    }
}

#[derive(Debug, Eq, PartialEq)]
pub struct HashmapIterator<T: HashmapType + ?Sized> {
    pos: Vec<(LabelReader, usize, BuilderData)>,
    phantom: PhantomData<T>,
}

impl<T: HashmapType + ?Sized> HashmapIterator<T> {
    pub fn from_hashmap(tree: &T) -> Self {
        let mut pos = vec![];
        if let Some(root) = tree.data() {
            pos.push((LabelReader::with_cell(root), tree.bit_len(), BuilderData::default()));
        }
        Self { pos, phantom: PhantomData::<T> }
    }
    // is_leaf and is_fork are not used here
    pub fn next_item(&mut self) -> Result<Option<(BuilderData, SliceData)>> {
        while let Some((mut cursor, mut bit_len, key)) = self.pos.pop() {
            let key = cursor.get_label_raw(&mut bit_len, key)?;
            if bit_len == 0 {
                return Ok(Some((key, cursor.remainder()?)))
            }
            for index in 0..2 {
                let mut key = key.clone();
                key.append_bit_bool(index == 0)?;
                let cursor = cursor.next_reader::<T>(1 - index, &mut 0)?;
                self.pos.push((cursor, bit_len - 1, key));
            }
        }
        Ok(None)
    }
}

impl<T: HashmapType + ?Sized> Iterator for HashmapIterator<T> {
    type Item = Result<(BuilderData, SliceData)>;
    fn next(&mut self) -> Option<Self::Item> {
        self.next_item().transpose()
    }
}

