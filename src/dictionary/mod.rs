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

use crate::{error, fail};
use crate::cell::{BuilderData, Cell, IBitstring, SliceData};
use crate::GasConsumer;
use crate::Mask;
use crate::types::{ExceptionCode, Result};

pub use self::hashmap::HashmapE;
pub use self::pfxhashmap::PfxHashmapE;

mod hashmap;
mod pfxhashmap;

pub type Leaf = Result<Option<SliceData>>;

pub const ADD: u8 = 0x01;
pub const REPLACE: u8 = 0x02;
const EMPTY_LABEL_MARKER: u8 = 0b00_000000;
const SHORT_LABEL_PREFIX: u8 = 0b0_0000000; // hml_short constructor, binary 0
const LONG_LABEL_PREFIX: u8 = 0b10_000000; // hml_long, binary 10
const SAME_LABEL_PREFIX: u8 = 0b11_000000; // hml_same, binary 11

// hml_long$10 n:(#<= m) s:n*bit = HmLabel ~n m;
fn hml_long(key: &SliceData, len: usize) -> Result<BuilderData> {
    let mut label = BuilderData::with_raw(vec![LONG_LABEL_PREFIX], 2)?;
    label.append_bits(key.remaining_bits(), len)?;
    label.append_bytestring(key)?;
    Ok(label)
}

// hml_short$0 {n:#} len:(Unary ~n) s:n*bit = HmLabel ~n m;
fn hml_short(key: &SliceData) -> Result<BuilderData> {
    let mut label = BuilderData::with_raw(vec![SHORT_LABEL_PREFIX], 1)?;
    let length = key.remaining_bits();
    for _ in 0..length / 32 {
        label.append_bits(std::u32::MAX as usize, 32)?;
    }
    let remainder = length % 32;
    if remainder != 0 {
        label.append_bits(std::u32::MAX as usize, remainder)?;
    }
    label.append_bit_zero()?;
    label.append_bytestring(key)?;
    Ok(label)
}

// hml_same$11 v:bit n:(#<= m) = HmLabel ~n m;
fn hml_same(key: &SliceData, len: usize) -> Result<Option<BuilderData>> {
    let mut zero_bit_found = false;
    let mut one_bit_found = false;
    let bits = key.remaining_bits();
    for offset in 0..bits {
        match key.get_bits(offset, 1)? {
            0 if one_bit_found => return Ok(None),
            0 => zero_bit_found = true,
            1 if zero_bit_found => return Ok(None),
            1 => one_bit_found = true,
            _ => return Ok(None)
        }
    }

    let mut label = BuilderData::with_raw(vec![SAME_LABEL_PREFIX], 2)?;
    label.append_bit_bool(!zero_bit_found)?;
    label.append_bits(bits, len)?;
    Ok(Some(label))
}

pub fn hm_label(key: &SliceData, max: usize) -> Result<BuilderData> {
    debug_assert!(max > 0 || key.is_empty());
    if key.is_empty() || max == 0 {
        return BuilderData::with_raw(vec![EMPTY_LABEL_MARKER], 2)
    }
    let len = 16 - (max as u16).leading_zeros() as usize;
    let length_of_long = 2 + len + key.remaining_bits(); // len == key.remaining_bits() + 1
    let length_of_short = 1 + 2 * key.remaining_bits() + 1;
    let length_of_same = 2 + 1 + len;

    let long_label = hml_long(key, len)?;
    let short_label = hml_short(key)?;
    debug_assert_eq!(length_of_long, long_label.length_in_bits());
    debug_assert_eq!(length_of_short, short_label.length_in_bits());
    if let Some(same_label) = hml_same(key, len)? {
        debug_assert_eq!(length_of_same, same_label.length_in_bits());
        let length = cmp::min(long_label.length_in_bits(), short_label.length_in_bits());
        if same_label.length_in_bits() < length {
            return Ok(same_label)
        }
    }
    if short_label.length_in_bits() <= long_label.length_in_bits() {
        Ok(short_label)
    } else {
        Ok(long_label)
    }
}

// reading hmLabel from SliceData
impl SliceData {
    pub fn get_label(&mut self, max: usize) -> Result<SliceData> {
        if self.is_empty() {
            Ok(SliceData::default())
        } else if !self.get_next_bit()? {
            // short label
            let mut len = 0;
            while self.get_next_bit()? {
                len += 1;
            }
            let mut label = self.clone();
            self.shrink_data(len..);
            label.shrink_references(..0);
            label.shrink_data(..len);
            Ok(label)
        } else if !self.get_next_bit()? {
            // long label
            let len = self.get_next_size(max)? as usize;
            let mut label = self.clone();
            self.shrink_data(len..);
            label.shrink_references(..0);
            label.shrink_data(..len);
            Ok(label)
        } else {
            // same bit
            let value = if self.get_next_bit()? { 0xFF } else { 0 };
            let len = self.get_next_size(max)? as usize;
            Ok(BuilderData::with_raw(vec![value; len / 8 + 1], len)?.into())
        }
    }
}

// methods working with root
impl SliceData {
    pub fn is_empty_root(&self) -> bool {
        self.is_empty() || 
        match self.get_bits(0, 1) {
            Ok(0) => true,
            _ => false
        }
    }
    pub fn get_dictionary(&mut self) -> Result<SliceData> {
        let mut root = self.clone();
        if !self.get_next_bit()? {
            root.shrink_references(..0);
        } else {
            self.checked_drain_reference()?;
            root.shrink_references(..1);
        }
        root.shrink_data(..1);
        Ok(root)
    }
}

fn find_leaf<T: HashmapType>(
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
            let key_bit = remainder.get_bits(0, 1)? as usize;
            let next = match signed_int && path.is_empty() && prefix_opt.is_none() {
                false => next_index,
                true => 1 - next_index,
            };
            dbg!(key_bit, next_index, path.length_in_bits());
            if key_bit != next {
                Ok(None)
            } else {
                return get_min_max::<T>(data, path, bit_len, next_index, next, gas_consumer)
            }
        }
        (_, None, None) => if eq {
            path.append_bytestring(&label)?;
            return Ok(Some(cursor))
        } else {
            return Ok(None)
        }
        (_, Some(remainder), None) => { // label fully in key
            if !T::is_fork(&mut cursor)? {
                fail!(ExceptionCode::DictionaryError)
            }
            let next = match signed_int & path.is_empty() {
                false => next_index,
                true => 1 - next_index,
            };
            path.append_bytestring(&label)?;
            key = remainder;
            let key_bit = key.get_next_bit_int()?;
            bit_len -= label.remaining_bits() + 1;
            let length_in_bits = path.length_in_bits();
            path.append_bit_bool(key_bit == 1)?;
            let res = find_leaf::<T>(cursor.reference(key_bit)?, path, bit_len, key, next_index, eq, false, gas_consumer)?;
            if res.is_some() || key_bit != next {
                dbg!(res.is_some(), key_bit, next, length_in_bits, path.length_in_bits());
                return Ok(res)
            }
            path.trunc(length_in_bits)?;
            path.append_bit_bool(key_bit == 0)?;
            data = cursor.reference(1 - key_bit)?;
            return get_min_max::<T>(data, path, bit_len, next_index, next_index, gas_consumer)
        }
    }
}

/// recursevily searchs min or max element from current subtree. Append path and returns element if found
pub fn get_min_max<T: HashmapType>(
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
        if T::is_fork(&mut cursor)? && bit_len > label_length {
            bit_len -= label_length + 1;
            path.append_bytestring(&label)?;
            path.append_bit_bool(index == 1)?;
            data = cursor.reference(index)?;
        } else if bit_len == label_length {
            path.append_bytestring(&label)?;
            return Ok(Some(cursor))
        } else {
            fail!(ExceptionCode::DictionaryError)
        }
        index = next_index;
    }
}

// difference for different hashmap types
pub trait HashmapType: Sized {
    fn write_hashmap_data(&self, cell: &mut BuilderData) -> Result<()> {
        if let Some(root) = self.data() {
            cell.append_bit_one()?;
            cell.append_reference_cell(root.clone());
        } else {
            cell.append_bit_zero()?;
        }
        Ok(())
    }
    fn read_hashmap_data(&mut self, slice: &mut SliceData) -> Result<()> {
        let data = slice.get_dictionary()?;
        *self.data_mut() = data.reference(0).ok();
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
    fn make_cell_with_label(key: SliceData, max: usize) -> Result<BuilderData>;
    fn make_cell_with_label_and_data(key: SliceData, max: usize, is_leaf: bool, data: &SliceData) -> Result<BuilderData>;
    fn is_fork(slice: &mut SliceData) -> Result<bool>;
    fn is_leaf(slice: &mut SliceData) -> bool;
    fn data(&self) -> Option<&Cell>;
    fn data_mut(&mut self) -> &mut Option<Cell>;
    fn bit_len(&self) -> usize;
    fn bit_len_mut(&mut self) -> &mut usize;
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
            bit_len -= label.remaining_bits() + 1;
            label = cursor.get_label(bit_len)?;
        }
        if key.is_empty() && Self::is_leaf(&mut cursor) {
            Ok(Some(cursor))
        } else {
            Ok(None)
        }
    }

    fn hashmap_set_with_mode<T: HashmapType>(
        &mut self,
        key: SliceData,
        leaf: &SliceData,
        gas_consumer: &mut dyn GasConsumer,
        mode: u8
    ) -> Leaf {
        let bit_len = self.bit_len();
        T::check_key_fail(bit_len, &key)?;
        if let Some(root) = self.data() {
            let mut root = root.clone();
            let result = put_to_node_with_mode::<T>(&mut root, bit_len, key, leaf, gas_consumer, mode);
            *self.data_mut() = Some(root);
            result
        } else if mode.bit(ADD) {
            let cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(key, bit_len, true, leaf)?)?;
            *self.data_mut() = Some(cell);
            Ok(None)
        } else {
            Ok(None)
        }
    }

    fn hashmap_setref_with_mode<T: HashmapType>(
        &mut self,
        key: SliceData,
        value: &Cell,
        gas_consumer: &mut dyn GasConsumer,
        mode: u8
    ) -> Leaf {
        let mut builder = BuilderData::default();
        builder.append_reference_cell(value.clone());
        self.hashmap_set_with_mode::<T>(key, &builder.into(), gas_consumer, mode)
    }

    /// iterate all elements with callback function
    /// to be removed
    fn iterate<F> (&self, p: &mut F) -> Result<bool>
    where F: FnMut(SliceData, SliceData) -> Result<bool> {
        if let Some(root) = self.data() {
            iterate_internal(
                &mut SliceData::from(root),
                BuilderData::default(),
                self.bit_len(),
                p)
        } else {
            Ok(true)
        }
    }

    /// iterate all elements with callback function
    fn iterate_slices<F> (&self, mut p: F) -> Result<bool>
    where F: FnMut(SliceData, SliceData) -> Result<bool> {
        if let Some(root) = self.data() {
            iterate_internal(
                &mut SliceData::from(root),
                BuilderData::default(),
                self.bit_len(),
                &mut p)
        } else {
            Ok(true)
        }
    }

    /// returns count of objects in tree - don't use it - try is_empty()
    fn len(&self) -> Result<usize> {
        let mut count = 0;
        self.iterate_slices(|_, _| {
            count += 1;
            Ok(true)
        })?;
        Ok(count)
    }
    /// counts elements to max counter - can be used as validate
    fn count(&self, max: usize) -> Result<usize> {
        let mut count = 0;
        self.iterate_slices(|_, _| {
            count += 1;
            Ok(count < max)
        })?;
        Ok(count)
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
                bit_len -= label.remaining_bits() + 1;
                (cursor.reference(0)?, cursor.reference(1)?)
            }
            // normal case with empty branch
            (_prefix, Some(mut label_remainder), None) => match label_remainder.get_next_bit()? {
                false => return Ok((Some(data.clone()), None)),
                true  => return Ok((None, Some(data.clone()))),
            }
            // wrong hashmap tree
            _ => fail!("split fail: root label: x{} and key: x{}", label.to_hex_string(), key.to_hex_string()),
        };
        cursor = SliceData::from(left);
        let label = cursor.get_label(bit_len)?;
        let mut builder = BuilderData::from_slice(&key);
        builder.append_bit_zero()?;
        builder.append_bytestring(&label)?;
        let left = Self::make_cell_with_label_and_data(builder.into(), self.bit_len(), false, &cursor)?;

        cursor = SliceData::from(right);
        let label = cursor.get_label(bit_len)?;
        let mut builder = BuilderData::from_slice(&key);
        builder.append_bit_one()?;
        builder.append_bytestring(&label)?;
        let right = Self::make_cell_with_label_and_data(builder.into(), self.bit_len(), false, &cursor)?;

        Ok((Some(left.into()), Some(right.into())))
    }
    // merge
    fn hashmap_merge(&mut self, other: &Self, key: &SliceData) -> Result<()> {
        let mut bit_len = self.bit_len();
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
                let left_bit = left.get_next_bit()?;
                let right_bit = right.get_next_bit()?;
                if left_bit && !right_bit {
                    std::mem::swap(&mut left, &mut right);
                    std::mem::swap(&mut cursor, &mut other);
                } else if left_bit == right_bit {
                    fail!("bug in common_prefix is impossible")
                }
                let is_leaf1 = Self::is_leaf(&mut cursor);
                let is_leaf2 = Self::is_leaf(&mut other);
                let prefix = prefix.unwrap_or_default();
                let mut root = Self::make_cell_with_label(prefix, bit_len)?;
                bit_len -= root.length_in_bits() + 1;
                root.append_reference(Self::make_cell_with_label_and_data(left, bit_len, is_leaf1, &cursor)?);
                root.append_reference(Self::make_cell_with_label_and_data(right, bit_len, is_leaf2, &other)?);
                *self.data_mut() = Some(root.into());
            }
            _ => fail!("Cannot merge")
        }
        Ok(())
    }
    fn scan_diff<F>(&self, other: &Self, mut op: F) -> Result<bool> 
    where F: FnMut(SliceData, Option<SliceData>, Option<SliceData>) -> Result<bool> {
        if !self.iterate_slices(|key, value| {
            let value2 = other.hashmap_get(key.clone(), &mut 0)?;
            if Some(&value) != value2.as_ref() {
                return op(key, Some(value), value2)
            }
            Ok(true)
        })? { return Ok(false); }
        other.iterate_slices(|key, value| match self.hashmap_get(key.clone(), &mut 0)? {
            None => op(key, None, Some(value)),
            Some(_) => Ok(true) // already checked in the first loop
        })
    }
}

/// iterate all elements with callback function
fn iterate_internal<F: FnMut(SliceData, SliceData) -> Result<bool>>(
    cursor: &mut SliceData, 
    mut key: BuilderData, 
    mut bit_len: usize, 
    found: &mut F
) -> Result<bool> {
    let label = cursor.get_label(bit_len)?;
    let label_length = label.remaining_bits();
    debug_assert!(label_length <= bit_len, "label_length: {}, bit_len: {}", label_length, bit_len);
    if label_length < bit_len {
        bit_len -= label_length + 1;
        let n = cmp::min(2, cursor.remaining_references());
        for i in 0..n {
            let mut key = key.clone();
            key.append_bytestring(&label)?;
            key.append_bit_bool(i != 0)?;
            let ref mut child = SliceData::from(cursor.reference(i)?);
            if !iterate_internal(child, key, bit_len, found)? {
                return Ok(false)
            }
        }
    } else if label_length == bit_len {
        key.append_bytestring(&label)?;
        return found(key.into(), cursor.clone());
    }
    Ok(true)
}

/// Puts element to required branch by first bit
fn put_to_fork_with_mode<T: HashmapType>(
    slice: &mut SliceData, // TODO: BuilderData
    bit_len: usize,
    mut key: SliceData,
    leaf: &SliceData,
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
            builder.append_reference_cell(slice.checked_drain_reference()?.clone())
        }
        let mut cell = slice.checked_drain_reference()?.clone();
        result = put_to_node_with_mode::<T>(&mut cell, bit_len - 1, key, leaf, gas_consumer, mode);
        builder.append_reference_cell(cell);
        if next_index == 0 {
            builder.append_reference_cell(slice.checked_drain_reference()?.clone())
        }
    }
    *slice = builder.into();
    result
}

/// Continues or finishes search of place
fn put_to_node_with_mode<T: HashmapType>(
    cell: &mut Cell,
    bit_len: usize,
    key: SliceData,
    leaf: &SliceData,
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
                *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(key, bit_len, true, leaf)?)?;
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
                    &mut slice, bit_len - prefix.remaining_bits(), key_remainder, leaf, gas_consumer, mode
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
fn slice_edge<T: HashmapType>(
    mut slice: SliceData,
    bit_len: usize,
    prefix: SliceData,
    mut label: SliceData,
    mut key: SliceData,
    leaf: &SliceData,
    gas_consumer: &mut dyn GasConsumer
) -> Result<BuilderData> {
    key.shrink_data(1..);
    let label_bit = label.get_next_bit()?;
    let length = bit_len - 1 - prefix.remaining_bits();
    let is_leaf = T::is_leaf(&mut slice);
    // Common prefix
    let mut builder = T::make_cell_with_label(prefix, bit_len)?;
    // Remainder of tree
    let existing_cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label, length, is_leaf, &slice)?)?;
    // Leaf for fork
    let another_cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(key, length, true, leaf)?)?;
    if !label_bit {
        builder.append_reference_cell(existing_cell);
        builder.append_reference_cell(another_cell);
    } else {
        builder.append_reference_cell(another_cell);
        builder.append_reference_cell(existing_cell);
    };
    Ok(builder)
}

// remove method
fn remove_node<T: HashmapType>(
    cell: &mut Cell,
    bit_len: usize,
    prefix: SliceData,
    mut key: SliceData,
    gas_consumer: &mut dyn GasConsumer
) -> Leaf {
    if cell.references_count() != 2 {
        debug_assert!(false);
        return Ok(None)
    }
    let length = bit_len - 1 - prefix.remaining_bits();
    let next_index = key.get_next_bit_int()?;
    let mut leaf = gas_consumer.load_cell(cell.reference(next_index)?)?;
    let label = leaf.get_label(length)?;
    if label == key && T::is_leaf(&mut leaf) {
        let result = Some(leaf);
        let ref mut fork = gas_consumer.load_cell(cell.reference(1 - next_index)?)?;
        let mut label = BuilderData::from_slice(&prefix);
        label.append_bit_bool(next_index == 0)?;
        label.append_bytestring(&fork.get_label(length)?)?; // with fork bit
        let is_leaf = T::is_leaf(fork);
        *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(
            label.into(), bit_len, is_leaf, fork
        )?)?;
        return Ok(result);
    }
    let mut references = vec![cell.reference(0)?.clone(), cell.reference(1)?.clone()];
    let result = remove_fork::<T>(&mut references[next_index], length, label, key, gas_consumer);

    let mut builder = BuilderData::new();
    builder.append_raw(cell.data(), cell.bit_length())?;
    for r in references {
        builder.append_reference_cell(r);
    }
    *cell = gas_consumer.finalize_cell(builder)?;

    result
}
// label is empty or fully in key
fn remove_fork<T: HashmapType>(
    cell: &mut Cell,
    bit_len: usize,
    label: SliceData,
    key: SliceData,
    gas_consumer: &mut dyn GasConsumer
) -> Leaf {
    if let (prefix, None, Some(remainder)) = SliceData::common_prefix(&label, &key) {
        remove_node::<T>(cell, bit_len, prefix.unwrap_or_default(), remainder, gas_consumer)
    } else {
        Ok(None)
    }
}

pub trait HashmapRemover: HashmapType {
    fn hashmap_remove<T: HashmapType>(&mut self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        let bit_len = self.bit_len();
        T::check_key_fail(bit_len, &key)?;
        let mut root = match self.data().cloned() {
            Some(root) => root,
            _ => return Ok(None)
        };
        let mut leaf = gas_consumer.load_cell(root.clone())?;
        let label = leaf.get_label(bit_len)?;
        let result;
        *self.data_mut() = if label == key && T::is_leaf(&mut leaf) {
            // last node
            result = Ok(Some(leaf));
            None
        } else {
            result = remove_fork::<T>(&mut root, bit_len, label, key, gas_consumer);
            Some(root)
        };
        result
    }
}

fn remove_except_prefix<T: HashmapType>(cell: &mut Cell, bit_len: usize, prev_common: SliceData, mut prefix: SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<bool> {
    debug_assert!(!prefix.is_empty());

    let next_index = prefix.get_next_bit_int()?;
    let mut next = match cell.references_count() >= next_index {
        true => gas_consumer.load_cell(cell.reference(next_index)?)?,
        false => return Ok(false)
    };
    let length = bit_len - prev_common.remaining_bits() - 1;
    let label = next.get_label(length)?;

    let (common, rem_label, rem_prefix) = SliceData::common_prefix(&label, &prefix);
    if !prefix.is_empty() && !label.is_empty() && (common.is_none() || (rem_label.is_some() && rem_prefix.is_some())) {
        return Ok(false)
    } else {
        let mut label = BuilderData::from_slice(&prev_common);
        label.append_bit_bool(next_index == 1)?;
        common.map(|ref string| label.append_bytestring(string)).transpose()?;
        rem_label.map(|ref string| label.append_bytestring(string)).transpose()?;
        let label: SliceData = label.into();
        let is_leaf = T::is_leaf(&mut next);
        *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label.clone(), bit_len, is_leaf, &next)?)?;
        if let Some(rem_prefix) = rem_prefix {
            return remove_except_prefix::<T>(cell, bit_len, label, rem_prefix, gas_consumer);
        }
        return Ok(true)
    }
}

fn remove_with_prefix<T: HashmapType>(cell: &mut Cell, bit_len: usize, prev_common: SliceData, mut prefix: SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<bool> {
    let next_index = prefix.get_next_bit_int()?;
    let mut next = match cell.references_count() >= next_index {
        true => gas_consumer.load_cell(cell.reference(next_index)?)?,
        false => return Ok(false)
    };
    let length = bit_len - prev_common.remaining_bits() - 1;
    let label = next.get_label(length)?;
    let (common, rem_label, rem_prefix) = SliceData::common_prefix(&label, &prefix);
    if !prefix.is_empty() && !label.is_empty() && (common.is_none() || (rem_label.is_some() && rem_prefix.is_some())) {
        Ok(false)
    } else {
        let label = rem_label.unwrap_or_default();
        let is_leaf = T::is_leaf(&mut next);
        *cell = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(label.clone(), length, is_leaf, &next)?)?;
        if let Some(rem_prefix) = rem_prefix {
            return remove_with_prefix::<T>(cell, length, label, rem_prefix, gas_consumer);
        }
        Ok(true)
    }
}

fn hashmap_into_subtree_with_prefix<T: HashmapType>(tree: &mut T, prefix: SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<()> {
    let bit_len = tree.bit_len();
    debug_assert!(bit_len >= prefix.remaining_bits());
    if !prefix.is_empty() && !tree.is_empty() && bit_len >= prefix.remaining_bits() {
        if let Some(mut root) = tree.data().cloned() {
            let mut slice = gas_consumer.load_cell(root.clone())?;
            let label = slice.get_label(bit_len)?;
            let (common, rem_label, rem_prefix) = SliceData::common_prefix(&label, &prefix);
            *tree.data_mut() = if !label.is_empty() && (common.is_none() || (rem_label.is_some() && rem_prefix.is_some())) {
                None
            } else if let Some(rem_prefix) = rem_prefix {
                if remove_except_prefix::<T>(&mut root, bit_len, common.unwrap_or_default(), rem_prefix, gas_consumer)? {
                    Some(root)
                } else {
                    None
                }
            } else {
                return Ok(())
            };
        }
    }
    Ok(())
}

fn hashmap_into_subtree_without_prefix<T: HashmapType>(tree: &mut T, prefix: SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<()> {
    let bit_len = tree.bit_len();
    debug_assert!(bit_len >= prefix.remaining_bits());
    if !prefix.is_empty() && !tree.is_empty() && bit_len >= prefix.remaining_bits() {
        if let Some(mut root) = tree.data().cloned() {
            let mut slice = gas_consumer.load_cell(root.clone())?;
            let label = slice.get_label(bit_len)?;
            let (common, rem_label, rem_prefix) = SliceData::common_prefix(&label, &prefix);
            *tree.data_mut() = if !label.is_empty() && (common.is_none() || (rem_label.is_some() && rem_prefix.is_some())) {
                None
            } else if let Some(rem_prefix) = rem_prefix {
                if remove_with_prefix::<T>(&mut root, bit_len, common.unwrap_or_default(), rem_prefix, gas_consumer)? {
                    *tree.bit_len_mut() = bit_len - prefix.remaining_bits();
                    Some(root)
                } else {
                    None
                }
            } else {
                let is_leaf = T::is_leaf(&mut slice);
                let root = gas_consumer.finalize_cell(T::make_cell_with_label_and_data(
                    rem_label.unwrap_or_default(),
                    bit_len - prefix.remaining_bits(),
                    is_leaf, &slice
                )?)?;
                *tree.bit_len_mut() = bit_len - prefix.remaining_bits();
                Some(root)
            }
        }
    }
    Ok(())
}

