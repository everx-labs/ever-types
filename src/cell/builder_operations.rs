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

use crate::{BuilderData, Cell, find_tag, MAX_DATA_BITS, MAX_REFERENCES_COUNT, SliceData};
use crate::types::{ExceptionCode, Result};

impl BuilderData {
    /// maximum number of references
    pub fn references_capacity() -> usize {
        MAX_REFERENCES_COUNT
    }
    /// used number of references
    pub fn references_used(&self) -> usize {
        self.references().len()
    }
    /// free number of references
    pub fn references_free(&self) -> usize {
        MAX_REFERENCES_COUNT - self.references().len()
    }
    /// maximum number of bits
    pub fn bits_capacity() -> usize {
        MAX_DATA_BITS
    }
    /// used number of bits
    pub fn bits_used(&self) -> usize {
        self.length_in_bits()
    }
    /// free number of bits
    pub fn bits_free(&self) -> usize {
        MAX_DATA_BITS - self.bits_used()
    }

    pub fn check_enough_refs(&self, count: usize) -> bool {
        self.references().len() + count <= MAX_REFERENCES_COUNT
    }

    // TODO: check here cyclic appending
    pub fn checked_append_reference(&mut self, cell: Cell) -> Result<&mut Self> {
        if self.references().len() >= MAX_REFERENCES_COUNT {
            failure::bail!(ExceptionCode::CellOverflow)
        } else {
            self.append_reference_cell(cell);
            Ok(self)
        }  
    }

    pub fn check_enough_space(&self, size: usize) -> bool {
        self.length_in_bits() + size <= MAX_DATA_BITS 
    }

    pub fn checked_append_references_and_data(&mut self, other: &SliceData) -> Result<&mut Self> {
        if self.bits_free() < other.remaining_bits() || self.references_free() < other.remaining_references() {
            failure::bail!(ExceptionCode::CellOverflow)
        }
        self.append_raw(other.get_bytestring(0).as_slice(), other.remaining_bits())?;
        for i in 0..other.remaining_references() {
            self.append_reference_cell(other.reference(i)?);
        }
        Ok(self)
    }
}

pub trait IBitstring {
    fn prepend_builder(&mut self, data: &BuilderData) -> Result<&mut Self>;
    fn prepend_bitstring(&mut self, data: &[u8]) -> Result<&mut Self>;
    fn append_builder(&mut self, data: &BuilderData) -> Result<&mut Self>;
    fn append_bitstring(&mut self, data: &[u8]) -> Result<&mut Self>;
    fn append_bytestring(&mut self, data: &SliceData) -> Result<&mut Self>;
    fn append_bit_zero(&mut self) -> Result<&mut Self>;
    fn append_bit_one(&mut self) -> Result<&mut Self>;
    fn append_bit_bool(&mut self, bit: bool) -> Result<&mut Self>;
    fn append_bits(&mut self, value: usize, bits: usize) -> Result<&mut Self>;
    fn append_u8(&mut self, value: u8) -> Result<&mut Self>;
    fn append_u16(&mut self, value: u16) -> Result<&mut Self>;
    fn append_u32(&mut self, value: u32) -> Result<&mut Self>;
    fn append_u64(&mut self, value: u64) -> Result<&mut Self>;
    fn append_u128(&mut self, value: u128) -> Result<&mut Self>;
    fn append_i8(&mut self, value: i8) -> Result<&mut Self>;
    fn append_i16(&mut self, value: i16) -> Result<&mut Self>;
    fn append_i32(&mut self, value: i32) -> Result<&mut Self>;
    fn append_i64(&mut self, value: i64) -> Result<&mut Self>;
    fn append_i128(&mut self, value: i128) -> Result<&mut Self>;
}

impl IBitstring for BuilderData {
    fn prepend_builder(&mut self, data: &BuilderData) -> Result<&mut Self> {
        self.prepend_raw(data.data(), data.length_in_bits())
    }
    fn prepend_bitstring(&mut self, data: &[u8]) -> Result<&mut Self> {
        let length_in_bits = find_tag(data);
        self.prepend_raw(data, length_in_bits)
    }
    fn append_builder(&mut self, data: &BuilderData) -> Result<&mut Self> {
        if self.can_append(data) {
            self.append_raw(data.data(), data.length_in_bits())?;
            for i in 0..data.references().len() {
                self.append_reference(BuilderData::from(&data.references()[i]));
            }
            Ok(self)
        } else {
            failure::bail!(ExceptionCode::CellOverflow)
        }
    }
    fn append_bitstring(&mut self, data: &[u8]) -> Result<&mut Self> {
        let length_in_bits = find_tag(data);
        self.append_raw(data, length_in_bits)
    }
    fn append_bytestring(&mut self, data: &SliceData) -> Result<&mut Self> {
        self.append_raw(&data.get_bytestring(0), data.remaining_bits())
    }
    fn append_bit_zero(&mut self) -> Result<&mut Self> {
        self.append_raw(&[0x00], 1)
    }
    fn append_bit_one(&mut self) -> Result<&mut Self> {
        self.append_raw(&[0xFF], 1)
    }
    fn append_bit_bool(&mut self, bit: bool) -> Result<&mut Self> {
        if bit {
            self.append_raw(&[0xFF], 1)
        } else {
            self.append_raw(&[0x00], 1)
        }
    }
    fn append_bits(&mut self, value: usize, bits: usize) -> Result<&mut Self> {
        match bits {
            0 => Ok(self),
            1..=7 => self.append_raw(&((value as u8) << (8 - bits)).to_be_bytes(), bits),
            8..=15 => self.append_raw(&((value as u16) << (16 - bits)).to_be_bytes(), bits),
            16..=31 => self.append_raw(&((value as u32) << (32 - bits)).to_be_bytes(), bits),
            32..=63 => self.append_raw(&((value as u64) << (64 - bits)).to_be_bytes(), bits),
            bits @ _ => unimplemented!("bits: {}", bits)
        }
    }
    fn append_u8(&mut self, value: u8) -> Result<&mut Self> {
        self.append_raw(&[value], 8)
    }
    fn append_u16(&mut self, value: u16) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 16)
    }
    fn append_u32(&mut self, value: u32) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 32)
    }
    fn append_u64(&mut self, value: u64) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 64)
    }
    fn append_u128(&mut self, value: u128) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 128)
    }    
    fn append_i8(&mut self, value: i8) -> Result<&mut Self> {
        self.append_raw(&[value as u8], 8)
    }
    fn append_i16(&mut self, value: i16) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 16)
    }
    fn append_i32(&mut self, value: i32) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 32)
    }
    fn append_i64(&mut self, value: i64) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 64)
    }
    fn append_i128(&mut self, value: i128) -> Result<&mut Self> {
        self.append_raw(&value.to_be_bytes(), 128)
    }
}

