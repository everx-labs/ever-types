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

use crate::types::ExceptionCode;

use super::{HashmapRemover, HashmapType, hm_label, KeyLeaf, Leaf};
use super::{BuilderData, SliceData};
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

#[cfg_attr(rustfmt, rustfmt_skip)]
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
    /// serialize not empty root in current cell
    pub fn write_hashmap_root(&self, cell: &mut BuilderData) -> Result<()> {
        match self.data() {
            Some(root) => {
                cell.checked_append_references_and_data(&SliceData::from(root))?;
                Ok(())
            }
            None => Err(ExceptionCode::CellUnderflow)
        }
    }
    /// serialize hashmapE to cell
    pub fn write_to_cell(&self, cell: &mut BuilderData) -> Result<()> {
        match self.data() {
            Some(root) => {
                cell.append_bit_one()?;
                cell.append_reference_cell(root.clone());
            }
            None => {
                cell.append_bit_zero()?;
            }
        }
        Ok(())
    }
    /// deserialize not empty root
    pub fn read_hashmap_root(&mut self, slice: &mut SliceData) -> Result<()> {
        let mut root = slice.clone();
        let label = slice.get_label(self.bit_len);
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
        self.hashmap_set_with_mode::<Self>(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn set_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode::<Self>(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replace_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode::<Self>(key, value, gas_consumer, REPLACE)
    }
    pub fn add_with_gas(&mut self, key: SliceData, value: &SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_set_with_mode::<Self>(key, value, gas_consumer, ADD)
    }
    /// sets value as reference
    pub fn setref(&mut self, key: SliceData, value: &Cell) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, &mut 0, ADD | REPLACE)
    }
    pub fn setref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, gas_consumer, ADD | REPLACE)
    }
    pub fn replaceref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, gas_consumer, REPLACE)
    }
    pub fn addref_with_gas(&mut self, key: SliceData, value: &Cell, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_setref_with_mode::<Self>(key, value, gas_consumer, ADD)
    }
    /// gets next/this or previous leaf
    pub fn find_leaf(&self, key: SliceData, next: bool, eq: bool, signed_int: bool, gas_consumer: &mut dyn GasConsumer) -> KeyLeaf {
        find_leaf::<Self>(self.data().cloned(), self.bit_len, key, next, eq, signed_int, gas_consumer)
    }
    /// removes item
    pub fn remove(&mut self, key: SliceData) -> Leaf {
        self.hashmap_remove::<Self>(key, &mut 0)
    }
    pub fn remove_with_gas(&mut self, key: SliceData, gas_consumer: &mut dyn GasConsumer) -> Leaf {
        self.hashmap_remove::<Self>(key, gas_consumer)
    }
    /// gets item with minimal key
    pub fn get_min(&self, signed: bool, gas_consumer: &mut dyn GasConsumer) -> KeyLeaf {
        get_min::<Self>(self.data.as_ref().cloned(), self.bit_len, self.bit_len, signed, gas_consumer)
    }
    /// gets item with maximal key
    pub fn get_max(&self, signed: bool, gas_consumer: &mut dyn GasConsumer) -> KeyLeaf {
        get_max::<Self>(self.data.as_ref().cloned(), self.bit_len, self.bit_len, signed, gas_consumer)
    }
    /// transform to subtree with the common prefix
    pub fn into_subtree_with_prefix(&mut self, prefix: SliceData, gas_consumer: &mut dyn GasConsumer) {
        hashmap_into_subtree_with_prefix::<Self>(self, prefix, gas_consumer);
    }
    /// transform to subtree without the common prefix
    pub fn into_subtree_without_prefix(&mut self, prefix: SliceData, gas_consumer: &mut dyn GasConsumer) {
        hashmap_into_subtree_without_prefix::<Self>(self, prefix, gas_consumer);
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
    fn make_cell_with_label(key: SliceData, max: usize) -> Result<BuilderData> {
        hm_label(&key, max)
    }
    fn make_cell_with_label_and_data(key: SliceData, max: usize, _is_leaf: bool, data: &SliceData)
    -> Result<BuilderData> {
        let mut builder = hm_label(&key, max)?;
        // automatically adds reference with data if space is not enought
        if builder.checked_append_references_and_data(data).is_err() {
            let reference = BuilderData::from_slice(data);
            builder.append_reference(reference);
        }
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

