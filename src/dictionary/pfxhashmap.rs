/*
* Copyright 2018-2020 TON DEV SOLUTIONS LTD.
*
* Licensed under the SOFTWARE EVALUATION License (the "License"); you may not use
* this file except in compliance with the License.  You may obtain a copy of the
* License at: https://ton.dev/licenses
*
* Unless required by applicable law or agreed to in writing, software
* distributed under the License is distributed on an "AS IS" BASIS,
* WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
* See the License for the specific TON DEV software governing permissions and
* limitations under the License.
*/

use std::fmt;

use crate::GasConsumer;
use crate::types::Result;

use super::{ADD, HashmapRemover, HashmapType, hm_label, Leaf, REPLACE};
use super::{BuilderData, Cell, IBitstring, SliceData};

#[derive(Clone, Debug)]
pub struct PfxHashmapE {
    bit_len: usize,
    data: Option<Cell>,
}

#[cfg_attr(rustfmt, rustfmt_skip)]
impl fmt::Display for PfxHashmapE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.data() {
            Some(cell) => write!(f, "PfxHashmap: {}", cell),
            None => write!(f, "Empty PfxHashmap"),
        }
    }
}

impl PfxHashmapE {
    /// constructs with bit_len
    pub fn with_bit_len(bit_len: usize) -> Self {
        Self::with_hashmap(bit_len, None)
    }
    /// construct with bit_len and data representing dictionary
    pub fn with_data(bit_len: usize, data: SliceData) -> Self {
        Self::with_hashmap(bit_len, data.reference(0).ok())
    }
    /// construct with bit_len and root representing Hashmap
    pub fn with_hashmap(bit_len: usize, data: Option<Cell>) -> Self {
        Self {
            bit_len,
            data: data
        }
    }
    /// gets value from hahsmap
    pub fn get(&self, key: SliceData) -> Leaf {
        self.hashmap_get(key, &mut 0)
    }
    pub fn get_with_gas(&self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_get(key, gas_consumer)
    }
    /// sets value as SliceData
    pub fn set(&mut self, key: SliceData, value: &SliceData) -> Leaf {
        self.hashmap_set_with_mode::<Self>(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn set_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode::<Self>(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replace_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode::<Self>(key, value, gas_consumer, REPLACE)
    }
    /// sets value as reference in empty SliceData
    pub fn setref(&mut self, key: SliceData, value: &Cell) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn setref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replaceref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, gas_consumer, REPLACE)
    }
    /// removes item
    pub fn remove(&mut self, key: SliceData) -> Leaf {
        self.hashmap_remove::<Self>(key, &mut 0)
    }
    pub fn remove_with_gas(&mut self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_remove::<Self>(key, gas_consumer)
    }
    /// true if key is prefix of any item in PfxHashmap
    pub fn is_prefix(&self, mut key: SliceData) -> bool {
        if key.is_empty() || self.is_empty() {
            return false;
        }
        let mut bit_len = self.bit_len;
        let mut cursor = SliceData::from(self.data().unwrap());
        let mut label = cursor.get_label(bit_len);
        loop {
            match SliceData::common_prefix(&label, &key) {
                (_, None, None) => (), // label == key
                (_, None, Some(remainder)) => key = remainder, // usual case
                (_, _, None) => return true, // key is prefix
                (_, Some(_), Some(_)) => return false
            }
            if Self::is_leaf(&mut cursor) {
                return false;
            }
            let next_index = key.get_next_bit_int().unwrap();
            if next_index >= cursor.remaining_references()
                || bit_len < label.remaining_bits() + 1 {
                debug_assert!(false);
                return false; // problem
            }
            cursor = SliceData::from(cursor.reference(next_index).unwrap());
            bit_len -= label.remaining_bits() + 1;
            label = cursor.get_label(bit_len);
        }
    }
    /// finds item in PfxHashmap which key is prefix of key and returns value with path and suffix
    pub fn get_prefix_leaf_with_gas(&self, mut key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Result<(SliceData, Option<SliceData>, SliceData)> {
        if key.is_empty() || self.is_empty() {
            return Ok((SliceData::default(), None, key))
        }
        let mut bit_len = self.bit_len;
        let mut path =  BuilderData::default();
        let mut cursor = SliceData::from_cell_ref(self.data().unwrap(), gas_consumer);
        let mut label = cursor.get_label(bit_len);
        loop {
            path.checked_append_references_and_data(&label)?;
            match SliceData::common_prefix(&label, &key) {
                (_, None, None) => { // label == key
                    key.shrink_data(..0);
                }
                (_, None, Some(remainder)) => key = remainder, // usual case
                (_, _, None) => return Ok((path.into(), None, SliceData::default())), // key is prefix
                (_, Some(_), Some(remainder)) => return Ok((path.into(), None, remainder))
            }
            if Self::is_leaf(&mut cursor) {
                return Ok((path.into(), Some(cursor), key))
            } else if key.is_empty() {
                return Ok((path.into(), None, key))
            }
            let next_index = key.get_next_bit_int()?;
            if next_index >= cursor.remaining_references()
                || bit_len < label.remaining_bits() + 1 {
                debug_assert!(false);
                return Ok((path.into(), None, key)) // problem
            }
            path.append_bit_bool(next_index == 1)?;
            cursor = SliceData::from_cell(cursor.reference(next_index)?, gas_consumer);
            bit_len -= label.remaining_bits() + 1;
            label = cursor.get_label(bit_len);
        }
    }
    #[allow(dead_code)]
    pub fn get_leaf_by_prefix(&self, mut key: SliceData) -> Result<(SliceData, Option<SliceData>, SliceData)> {
        if key.is_empty() || self.is_empty() {
            return Ok((SliceData::default(), None, key))
        }
        let mut bit_len = self.bit_len;
        let mut path = BuilderData::default();
        let mut cursor = SliceData::from(self.data().unwrap());
        let mut label = cursor.get_label(bit_len);
        loop {
            path.checked_append_references_and_data(&label)?;
            match SliceData::common_prefix(&label, &key) {
                (_, None, None) => { // label == key
                    key.shrink_data(..0);
                }
                (_, None, Some(remainder)) => key = remainder, // usual case
                (_, _, None) => break, // key is prefix
                (_, Some(_), Some(remainder)) => return Ok((path.into(), None, remainder))
            }
            if Self::is_leaf(&mut cursor) {
                return Ok((path.into(), Some(cursor), key))
            }
            let next_index = key.get_next_bit_int()?;
            if next_index >= cursor.remaining_references()
                || bit_len < label.remaining_bits() + 1 {
                debug_assert!(false);
                return Ok((path.into(), None, key)) // problem
            }
            path.append_bit_bool(next_index == 1)?;
            cursor = SliceData::from(cursor.reference(next_index)?);
            bit_len -= label.remaining_bits() + 1;
            label = cursor.get_label(bit_len);
        }
        key = SliceData::default();
        loop {
            if Self::is_leaf(&mut cursor) {
                return Ok((path.into(), Some(cursor), key))
            }
            let next_index = 0;
            if next_index >= cursor.remaining_references() {
                return Ok((path.into(), None, key)) // problem
            }
            path.append_bit_bool(next_index == 1)?;
            cursor = SliceData::from(cursor.reference(next_index)?);
            if bit_len < label.remaining_bits() + 1 {
                return Ok((path.into(), None, key)) // problem
            }
            bit_len -= label.remaining_bits() + 1;
            label = cursor.get_label(bit_len);
            path.checked_append_references_and_data(&label)?;
        }
    }
}

// phm_edge#_ {n:#} {X:Type} {l:#} {m:#} label:(HmLabel ~l n)
// {n = (~m) + l} node:(PfxHashmapNode m X) = PfxHashmap n X;
// phmn_leaf$0 {n:#} {X:Type} value:X = PfxHashmapNode n X;
// phmn_fork$1 {n:#} {X:Type} left:^(PfxHashmap n X)
// right:^(PfxHashmap n X) = PfxHashmapNode (n+1) X;
impl HashmapType for PfxHashmapE {
    fn check_key(bit_len: usize, key: &SliceData) -> bool {
        bit_len >= key.remaining_bits()
    }
    fn make_cell_with_label(key: SliceData, max: usize) -> Result<BuilderData> {
        let mut builder = hm_label(&key, max)?;
        builder.append_bit_one()?;
        Ok(builder)
    }
    fn make_cell_with_label_and_data(key: SliceData, max: usize, is_leaf: bool, data: &SliceData)
    -> Result<BuilderData> {
        let mut builder = hm_label(&key, max)?;
        builder.append_bit_bool(!is_leaf)?;
        // automatically adds reference with data if space is not enought
        if builder.checked_append_references_and_data(data).is_err() {
            let reference = BuilderData::from_slice(data);
            builder.append_reference(reference);
        }
        Ok(builder)
    }
    fn is_fork(slice: &mut SliceData) -> Result<bool> {
        Ok(slice.get_next_bit()? && slice.remaining_references() > 1)
    }
    fn is_leaf(slice: &mut SliceData) -> bool {
        !slice.is_empty() && !slice.get_next_bit().unwrap()
    }
    fn data(&self) -> Option<&Cell> {
        self.data.as_ref()
    }
    fn data_mut(&mut self) -> &mut Option<Cell> {
        &mut self.data
    }
    fn bit_len(&self) -> usize {
        self.bit_len
    }
    fn bit_len_mut(&mut self) -> &mut usize {
        &mut self.bit_len
    }
}

impl HashmapRemover for PfxHashmapE {}

