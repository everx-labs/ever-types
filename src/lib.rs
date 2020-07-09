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

pub mod types;
pub use self::types::*;

pub mod cell;
pub use self::cell::*;

pub mod dictionary;
pub use self::dictionary::*;

pub mod cells_serialization;
pub use cells_serialization::*;

pub trait Mask {
    fn bit(&self, bits: Self) -> bool;
    fn mask(&self, mask: Self) -> Self;
    fn any(&self, bits: Self) -> bool;
    fn non(&self, bits: Self) -> bool;
}

impl Mask for u8 {
    fn bit(&self, bits: Self) -> bool {
        (self & bits) == bits
    }
    fn mask(&self, mask: Self) -> u8 {
        self & mask
    }
    fn any(&self, bits: Self) -> bool {
        (self & bits) != 0
    }
    fn non(&self, bits: Self) -> bool {
        (self & bits) == 0
    }
}


pub trait GasConsumer {
    fn finalize_cell(&mut self, builder: BuilderData) -> Result<Cell>;
    fn load_cell(&mut self, cell: Cell) -> Result<SliceData>;
    fn finalize_cell_and_load(&mut self, builder: BuilderData) -> Result<SliceData>;
}

impl GasConsumer for u64 {
    fn finalize_cell(&mut self, builder: BuilderData) -> Result<Cell> {
        builder.into_cell()
    }
    fn load_cell(&mut self, cell: Cell) -> Result<SliceData> {
        Ok(cell.into())
    }
    fn finalize_cell_and_load(&mut self, builder: BuilderData) -> Result<SliceData> {
        Ok(builder.into())
    }
}

pub fn parse_slice_base(slice: &str, mut bits: usize, base: u32) -> Option<Vec<u8>> {
    debug_assert!(bits < 8, "it is offset to get slice parsed");
    let mut acc = 0u8;
    let mut data = vec![];
    let mut completion_tag = false;
    for ch in slice.chars() {
        if completion_tag {
            return None
        }
        match ch.to_digit(base) {
            Some(x) => if bits < 4 {
                acc |= (x << (4 - bits)) as u8;
                bits += 4;
            } else {
                data.push(acc | (x as u8 >> (bits - 4)));
                acc = (x << (12 - bits)) as u8;
                bits -= 4;
            }
            None => match ch {
                '_' => completion_tag = true,
                _ => return None
            }
        }
    }
    if bits != 0 {
        if !completion_tag {
            acc |= 1 << (7 - bits);
        }
        if acc != 0 || data.is_empty() {
            data.push(acc);
        }
    } else if !completion_tag {
        data.push(0x80);
    }
    Some(data)
}
