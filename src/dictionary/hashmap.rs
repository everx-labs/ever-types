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

use std::fmt;

use crate::{
    error, fail, Result, GasConsumer,
    types::ExceptionCode,
    cell::{BuilderData, Cell, SliceData},

};
use super::*;

///////////////////////////////////////////////
/// Length of key should not exceed bit_len
/// If key length is less than bit_len it should be filled by zeros on the left <- TODO:
///
#[derive(Clone, Debug, Default, PartialEq, Eq)]
pub struct HashmapE {
    bit_len: usize,
    data: Option<Cell>,
}

#[rustfmt::skip]
impl fmt::Display for HashmapE {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self.data() {
            Some(cell) => write!(f, "Hashmap: {}", cell),
            None => write!(f, "Empty Hashmap"),
        }
    }
}

impl HashmapE {
    /// constructs with bit_len
    pub const fn with_bit_len(bit_len: usize) -> Self {
        Self::with_hashmap(bit_len, None)
    }
    /// construct with bit_len and root representing Hashmap
    pub const fn with_hashmap(bit_len: usize, data: Option<Cell>) -> Self {
        Self { bit_len, data }
    }
    /// serialize not empty root in current cell
    pub fn write_hashmap_root(&self, cell: &mut BuilderData) -> Result<()> {
        match self.data() {
            Some(root) => {
                cell.checked_append_references_and_data(&SliceData::load_cell_ref(root)?)?;
                Ok(())
            }
            None => fail!(ExceptionCode::CellUnderflow)
        }
    }
    /// deserialize not empty root
    pub fn read_hashmap_root(&mut self, slice: &mut SliceData) -> Result<()> {
        let mut root = slice.clone();
        let label = LabelReader::read_label(slice, self.bit_len)?;
        if label.remaining_bits() != self.bit_len {
            slice.shrink_references(2..);
            root.shrink_by_remainder(slice);
        } else { // all remainded slice as single item
            slice.shrink_data(..0);
            slice.shrink_references(..0);
        }

        self.data = Some(root.into_cell());
        Ok(())
    }
    /// checks if dictionary is empty
    pub fn is_empty(&self) -> bool {
        self.data.is_none()
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
        self.hashmap_set_with_mode(key, &value.as_builder(), &mut 0, ADD | REPLACE)
    }
    pub fn set_builder(&mut self, key: SliceData, value: &BuilderData) -> Leaf {
        self.hashmap_set_with_mode(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn set_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode(key, &value.as_builder(), gas_consumer, ADD | REPLACE)
    }
    pub fn set_builder_with_gas(&mut self, key: SliceData, value: &BuilderData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replace_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode(key, &value.as_builder(), gas_consumer, REPLACE)
    }
    pub fn replace_builder_with_gas(&mut self, key: SliceData, value: &BuilderData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode(key, value, gas_consumer, REPLACE)
    }
    pub fn add_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode(key, &value.as_builder(), gas_consumer, ADD)
    }
    pub fn add_builder_with_gas(&mut self, key: SliceData, value: &BuilderData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode(key, value, gas_consumer, ADD)
    }
    /// sets value as reference
    pub fn setref(&mut self, key: SliceData, value: &Cell) -> Leaf {
        self.hashmap_setref_with_mode(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn setref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replaceref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode(key, value, gas_consumer, REPLACE)
    }
    pub fn addref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode(key, value, gas_consumer, ADD)
    }
    /// gets next/this or previous leaf
    pub fn find_leaf(
        &self,
        key: SliceData,
        next: bool,
        eq: bool,
        signed_int: bool,
        gas_consumer: &mut dyn GasConsumer
    ) -> Result<Option<(BuilderData, SliceData)>> {
        Self::check_key_fail(self.bit_len, &key)?;
        match self.data() {
            Some(root) => {
                let mut path = BuilderData::new();
                let next_index = match next {
                    true => 0,
                    false => 1,
                };
                let result = find_leaf::<Self>(root.clone(), &mut path, self.bit_len, key, next_index, eq, signed_int, gas_consumer)?;
                Ok(result.map(|value| (path, value)))
            }
            None => Ok(None)
        }
    }
    /// removes item
    pub fn remove(&mut self, key: SliceData) -> Leaf {
        self.hashmap_remove(key, &mut 0)
    }
    /// removes item spending gas
    pub fn remove_with_gas(&mut self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_remove(key, gas_consumer)
    }
    /// gets item with minimal key
    pub fn get_min(&self, signed: bool, gas_consumer: &mut dyn GasConsumer) -> Result<Option<(BuilderData, SliceData)>> {
        self.get_min_max(true, signed, gas_consumer)
    }
    /// gets item with maxiaml key
    pub fn get_max(&self, signed: bool, gas_consumer: &mut dyn GasConsumer) -> Result<Option<(BuilderData, SliceData)>> {
        self.get_min_max(false, signed, gas_consumer)
    }
    /// gets item with minimal or maxiaml key
    pub fn get_min_max(&self, min: bool, signed: bool, gas_consumer: &mut dyn GasConsumer) -> Result<Option<(BuilderData, SliceData)>> {
        match self.data() {
            Some(root) => {
                let mut path = BuilderData::new();
                let (next_index, index) = match (min, signed) {
                    (true, true) => (0, 1),
                    (true, false) => (0, 0),
                    (false, true) => (1, 0),
                    (false, false) => (1, 1),
                };
                let result = get_min_max::<Self>(root.clone(), &mut path, self.bit_len, next_index, index, gas_consumer)?;
                Ok(result.map(|value| (path, value)))
            }
            None => Ok(None)
        }
    }
    /// split to subtrees by key
    pub fn split(&self, key: &SliceData) -> Result<(Self, Self)> {
        self.hashmap_split(key).map(|(left, right)| (Self::with_hashmap(self.bit_len, left), Self::with_hashmap(self.bit_len, right)))
    }
    /// Merge other tree to current roots should be at least merge key
    pub fn merge(&mut self, other: &Self, key: &SliceData) -> Result<()> {
        self.hashmap_merge(other, key)
    }
}

// hm_edge#_ {n:#} {X:Type} {l:#} {m:#} label:(HmLabel ~l n)
// {n = (~m) + l} node:(HashmapNode m X) = Hashmap n X;
// hmn_leaf#_ {X:Type} value:X = HashmapNode 0 X;
// hmn_fork#_ {n:#} {X:Type} left:^(Hashmap n X)
// right:^(Hashmap n X) = HashmapNode (n+1) X;
impl HashmapType for HashmapE {
    fn check_key(bit_len: usize, key: &SliceData) -> bool {
        bit_len == key.remaining_bits()
    }
    fn make_cell_with_label_and_data(key: SliceData, max: usize, _is_leaf: bool, data: &SliceData)
    -> Result<BuilderData> {
        let mut builder = hm_label(&key, max)?;
        builder.checked_append_references_and_data(data)?;
        Ok(builder)
    }
    fn is_fork(slice: &mut SliceData) -> Result<bool> {
        Ok(slice.remaining_references() > 1)
    }
    fn is_leaf(_slice: &mut SliceData) -> bool {
        true
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

impl HashmapRemover for HashmapE {}
impl HashmapSubtree for HashmapE {}

impl IntoIterator for &HashmapE {
    type Item = <HashmapIterator<HashmapE> as std::iter::Iterator>::Item;
    type IntoIter = HashmapIterator<HashmapE>;

    fn into_iter(self) -> Self::IntoIter {
        self.iter()
    }
}

#[cfg(test)]
#[path = "tests/test_hashmap.rs"]
mod tests;
