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

use std::sync::{Arc, Mutex};
use std::collections::HashSet;
use std::fmt;
use std::ops::{BitOr, BitOrAssign};
use types::{ExceptionCode, Result, UInt256};
use cells_serialization::{SHA256_SIZE, BagOfCells};
use sha2::{Sha256, Digest};
use std::cmp::{max, min};
use std::ops::Deref;

pub const MAX_REFERENCES_COUNT: usize = 4;
pub const MAX_DATA_BITS: usize = 1023;
pub const MAX_LEVEL: u8 = 3;
pub const MAX_DEPTH: u16 = 1024;


#[derive(Debug, Eq, PartialEq, Clone, Copy, Hash)]
pub enum CellType {
    Unknown,
    Ordinary,
    PrunedBranch,
    LibraryReference,
    MerkleProof,
    MerkleUpdate
}

#[derive(Debug, Default, Eq, PartialEq, Clone, Copy, Hash)]
pub struct LevelMask(u8);

impl LevelMask {
    pub fn with_level(level: u8) -> Self {
        LevelMask(match level {
            0 => 0,
            1 => 1,
            2 => 3,
            3 => 7,
            _ => {
                error!(target: "tvm", "{} {}", file!(), line!());
                0
            }
        })
    }

    pub fn with_mask(mask: u8) -> Self {
        if mask <= 7 {
            LevelMask(mask)
        } else {
            error!(target: "tvm", "{} {}", file!(), line!());
            LevelMask(0)
        }
    }

    pub fn for_merkle_cell(children_mask: LevelMask) -> Self {
        LevelMask(children_mask.0 >> 1)
    }

    pub fn level(&self) -> u8 {
        if self.0 > 7 {
            error!(target: "tvm", "{} {}", file!(), line!());
            255
        } else {
            // count of set bits (low three)
            (self.0 & 1) + ((self.0 >> 1) & 1) + ((self.0 >> 2) & 1)
        }
    }

    pub fn mask(&self) -> u8 {
        self.0
    }

    // if cell contains requared hash() - it will be returned,
    // else = max avaliable, but less then index
    //
    // rows - cell mask
    //       0(0)  1(1)  2(3)  3(7)  columns - index(mask)
    // 0     0     0     0     0     cells - index(AND result)
    // 1     0     1(1)  1(1)  1(1)
    // 2     0     0(0)  1(2)  1(2)
    // 3     0     1(1)  2(3)  2(3)
    // 4     0     0(0)  0(0)  1(4)
    // 5     0     1(1)  0(0)  2(5)
    // 6     0     0(0)  1(2)  2(6)
    // 7     0     1(1)  2(3)  3(7)
    pub fn calc_hash_index(&self, mut index: usize) -> usize {
        index = min(index, 3);
        LevelMask::with_mask(self.0 & LevelMask::with_level(index as u8).0).level() as usize
    }

    pub fn calc_virtual_hash_index(&self, index: usize, virt_offset: u8) -> usize {
        LevelMask::with_mask(self.0 >> virt_offset)
            .calc_hash_index(index)
    }

    pub fn virtualize(&self, virt_offset: u8) -> Self {
        LevelMask::with_mask(self.0 >> virt_offset)
    }
}

impl BitOr for LevelMask {
    type Output = Self;

    // rhs is the "right-hand side" of the expression `a | b`
    fn bitor(self, rhs: Self) -> Self {
        LevelMask::with_mask(self.0 | rhs.0)
    }
}

impl BitOrAssign for LevelMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

impl From<u8> for CellType {
    fn from(num: u8) -> CellType {
        match num {
            1 => CellType::PrunedBranch,
            2 => CellType::LibraryReference,
            3 => CellType::MerkleProof,
            4 => CellType::MerkleUpdate,
            0xff => CellType::Ordinary,
            _ => CellType::Unknown,
        }
    }
} 

impl From<CellType> for u8 {
    fn from(ct: CellType) -> u8 {
        match ct {
            CellType::Unknown => 0,
            CellType::Ordinary => 0xff,
            CellType::PrunedBranch => 1,
            CellType::LibraryReference => 2,
            CellType::MerkleProof => 3,
            CellType::MerkleUpdate => 4,
        }
    }
}

#[cfg_attr(rustfmt, rustfmt_skip)]
impl fmt::Display for CellType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let msg = match *self {
            CellType::Ordinary => "Ordinary",
            CellType::PrunedBranch => "Pruned branch",
            CellType::LibraryReference => "Library reference",
            CellType::MerkleProof => "Merkle proof",
            CellType::MerkleUpdate => "Merkle update",
            CellType::Unknown => "Unknown",
        };
        f.write_str(msg)
    }
}

#[derive(Clone)]
pub struct Cell(Arc<dyn CellImpl>);

pub trait CellImpl: Sync + Send {
    fn data(&self) -> &[u8];
    fn bit_length(&self) -> usize;
    fn references_count(&self) -> usize;
    fn reference(&self, index: usize) -> Result<Cell>;
    fn cell_type(&self) -> CellType;
    fn level_mask(&self) -> LevelMask;
    fn hash(&self, index: usize) -> UInt256;
    fn depth(&self, index: usize) -> u16;
    fn store_hashes(&self) -> bool;

    fn level(&self) -> u8 {
        self.level_mask().level()
    }

    fn is_merkle(&self) -> bool {
        self.cell_type() == CellType::MerkleProof || self.cell_type() == CellType::MerkleUpdate
    }

    fn is_pruned(&self) -> bool {
        self.cell_type() == CellType::PrunedBranch
    }
}

impl Cell {

    pub fn virtualize(self, offset: u8) -> Self {
        if self.level_mask().mask() == 0 {
            self
        } else {
            Cell::with_cell_impl(
                VirtualCell::with_cell_and_offset(self, offset)
            )
        }
    }

    pub fn with_cell_impl<T: 'static + CellImpl>(cell_impl: T) -> Self {
       Cell(Arc::new(cell_impl))
    }

    pub fn with_cell_impl_arc(cell_impl: Arc<dyn CellImpl>) -> Self {
        Cell(cell_impl)
    }

    pub fn reference(&self, index: usize) -> Result<Cell> {
        self.0.reference(index)
    }

    pub fn clone_references(&self) -> Vec<Cell> {
        let count = self.0.references_count();
        let mut refs = Vec::with_capacity(count);
        for i in 0..count {
            refs.push(self.0.reference(i).unwrap())
        }
        refs
    }

    pub fn data(&self) -> &[u8] {
        self.0.data()
    }

    pub fn bit_length(&self) -> usize {
        self.0.bit_length()
    }

    pub fn cell_type(&self) -> CellType {
        self.0.cell_type()
    }

    pub fn level(&self) -> u8 {
        self.0.level()
    }

    pub fn hashes_count(&self) -> usize {
        self.0.level() as usize + 1
    }

    pub fn level_mask(&self) -> LevelMask {
        self.0.level_mask()
    }

    pub fn references_count(&self) -> usize {
        self.0.references_count()
    }

    /// Returns cell's higher hash for given index (last one - representation hash)
    pub fn hash(&self, index: usize) -> UInt256 {
        self.0.hash(index)
    }

    /// Returns cell's depth for given index
    pub fn depth(&self, index: usize) -> u16 {
        self.0.depth(index)
    }

    /// Returns cell's hashes (representation and highers)
    pub fn hashes(&self) -> Vec<UInt256> {
        let mut hashes = Vec::new();
        for i in 0..self.level() + 1 {
            hashes.push(self.hash(i as usize))
        }
        hashes
    }

    /// Returns cell's depth (for current state and each level)
    pub fn depths(&self) -> Vec<u16> {
        let mut depths = Vec::new();
        for i in 0..self.level() + 1 {
            depths.push(self.depth(i as usize))
        }
        depths
    }

    pub fn repr_hash(&self) -> UInt256 {
        self.0.hash(MAX_LEVEL as usize)
    }

    pub fn repr_depth(&self) -> u16 {
        self.0.depth(MAX_LEVEL as usize)
    }

    pub fn store_hashes(&self) -> bool {
        self.0.store_hashes()
    }

    #[allow(dead_code)]
    pub fn is_merkle(&self) -> bool {
        self.0.is_merkle()
    }

    #[allow(dead_code)]
    pub fn is_pruned(&self) -> bool {
        self.0.is_pruned()
    }

    pub fn to_hex_string(&self, lower: bool) -> String {
        let len = self.bit_length();
        if len == 0 {
            return String::new()
        }
        let mut result = if lower {
            hex::encode(&self.data())
        } else {
            hex::encode_upper(&self.data())
        };
        match len % 8 {
            0 => {
                result.pop();
                result.pop();
            }
            1..=3 => {
                result.pop();
                result.push('_')
            }
            4 => {
                result.pop();
            }
            _ => result.push('_')
        }
        result
    }

    fn print_indent(f: &mut fmt::Formatter, indent: &str, last_child: bool, first_line: bool) -> fmt::Result {
        write!(f, "{}{}", indent, if first_line {
                if last_child {" └─"} else {" ├─"} 
            } else { 
                if last_child {"   "} else {" │ "}
            })?;

        Ok(())
    }

    pub fn format_without_refs(&self, f: &mut fmt::Formatter, indent: &str, last_child: bool, 
        full: bool, root: bool) -> fmt::Result {

        if !root { Self::print_indent(f, indent, last_child, true)?; }

        if full {
            write!(f, "{}   l: {:03b}   ", self.cell_type(), self.level_mask().mask())?;
        }

        write!(f, "bits: {}", self.bit_length())?;
        write!(f, "   refs: {}", self.references_count())?;

        if self.data().len() > 100 {
            write!(f, "\n")?;
            if !root { Self::print_indent(f, indent, last_child, false)?; }
        } else {
            write!(f, "   ")?;
        }

        write!(f, "data: {}", self.to_hex_string(true))?;

        if full {
            write!(f, "\n")?;
            if !root { Self::print_indent(f, indent, last_child, false)?; }
            write!(f, "hashes:")?;
            for h in self.hashes().iter() {
                write!(f, " {:x}", h)?;
            }
            write!(f, "\n")?;
            if !root { Self::print_indent(f, indent, last_child, false)?; }
            write!(f, "depths:")?;
            for d in self.depths().iter() {
                write!(f, " {}", d)?;
            }
        }
        Ok(())
    }

    pub fn format_with_refs_tree(
        &self,
        f: &mut fmt::Formatter,
        mut indent: String,
        last_child: bool,
        full: bool,
        root: bool,
        remaining_depth: u16) -> std::result::Result<String, fmt::Error> {

        self.format_without_refs(f, &indent, last_child, full, root)?;
        if remaining_depth > 0 {
            if !root {
                indent.push(' ');
                indent.push(if last_child {' '} else {'│'});
            }
            for i in 0..self.references_count() {
                let child = self.reference(i).unwrap();
                write!(f, "\n")?;
                indent = child.format_with_refs_tree(
                    f, indent, i == self.references_count() - 1, full, false, remaining_depth - 1)?;
            }
            if !root {
                indent.pop();
                indent.pop();
            }
        }
        Ok(indent)
    }
}

impl Default for Cell {
    fn default() -> Self{
        Cell(Arc::new(DataCell::new()))
    }
}

impl PartialEq for Cell {
    fn eq(&self, other: &Cell) -> bool {
        self.repr_hash() == other.repr_hash()
    }
}

impl Eq for Cell { }

impl fmt::Debug for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.repr_hash())
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with_refs_tree(f, "".to_string(), true, f.alternate(), true, 
            min(f.precision().unwrap_or(0), MAX_DEPTH as usize) as u16)?;
        Ok(())
    }
}

impl fmt::LowerHex for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}",  self.to_hex_string(true))
    }
}

impl fmt::UpperHex for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}",  self.to_hex_string(false))
    }
}

impl fmt::Binary for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.data().iter()
            .map(|x| format!("{:08b}", *x))
            .collect::<Vec<_>>().join("")
            .trim_end_matches('0')
        )
    }
}

/// Calculates data's lengt in bits with respect to completion tag
pub fn find_tag(bitsting: &[u8]) -> usize {
    let mut length = bitsting.len() * 8;
    for x in bitsting.iter().rev() {
        if *x == 0 {
            length -= 8;
        } else {
            let mut skip = 1;
            let mut mask = 1;
            while (*x & mask) == 0 {
                skip += 1;
                mask <<= 1
            }
            length -= skip;
            break;
        }
    }
    length
}

pub fn append_tag(data: &mut Vec<u8>, bits: usize) {
    let shift = bits % 8;
    if shift == 0 || data.is_empty() {
        data.truncate(bits / 8);
        data.push(0x80);
    } else {
        data.truncate(1 + bits / 8);
        let mut last_byte = data.pop().unwrap();
        if shift != 7 {
            last_byte >>= 7 - shift;
        }
        last_byte |= 1;
        if shift != 7 {
            last_byte <<= 7 - shift;
        }
        data.push(last_byte);
    }
}

#[derive(Clone)]
pub struct DataCell {
    references: Vec<Cell>,
    data: Vec<u8>,
    cell_type: CellType,
    level_mask: LevelMask,
    store_hashes: bool,
    hashes: Option<Vec<UInt256>>,
    depths: Option<Vec<u16>>,
}

impl DataCell {

    pub fn new() -> DataCell {
        Self::with_params(vec!(), vec!(), CellType::Ordinary, 0, None, None).unwrap()
    }

    pub fn with_params<TRefs>(refs: TRefs, data: Vec<u8>, cell_type: CellType, level_mask: u8, 
        hashes: Option<Vec<UInt256>>, depths: Option<Vec<u16>>) -> Result<DataCell>  
    where
        TRefs: IntoIterator<Item = Cell>
    {
        assert_eq!(hashes.is_some(), depths.is_some());

        let refs = refs.into_iter();
        let mut references: Vec<Cell> = vec![];
        references.extend(refs);
        let mut cell = DataCell {
            data,
            references,
            cell_type,
            level_mask: LevelMask::with_mask(level_mask),
            store_hashes: hashes.is_some(),
            hashes,
            depths };
        cell.finalize_ex(false)?;
        Ok(cell)
    }

    pub fn finalize_ex(&mut self, force: bool) -> Result<()> {

        if !force && self.hashes.is_some() && self.depths.is_some() {
            return Ok(());
        }

        // Check data size and references count

        let bit_len = find_tag(&self.data);

        match self.cell_type {
            CellType::PrunedBranch => {
                // type + level_mask + level * (hashes + depths)
                if bit_len != 8 * (1 + 1 + (self.level() as usize) * (SHA256_SIZE + 2)) ||
                    self.references.len() > 0
                {
                    return Err(ExceptionCode::RangeCheckError)
                }
                if self.data[0] != u8::from(CellType::PrunedBranch) ||
                   self.data[1] != self.level_mask.mask() {
                    return Err(ExceptionCode::FatalError)
                }
            },
            CellType::MerkleProof => {
                // type + hash + depth
                if bit_len != 8 * (1 + SHA256_SIZE + 2) ||
                    self.references.len() != 1
                {
                    return Err(ExceptionCode::RangeCheckError)
                }
                // TODO check hashes and depths
            },
            CellType::MerkleUpdate => {
                // type + 2 * (hash + depth)
                if bit_len != 8 * (1 + 2 * (SHA256_SIZE + 2)) ||
                    self.references.len() != 2
                {
                    return Err(ExceptionCode::RangeCheckError)
                }
                // TODO check hashes and depths
            },
            CellType::Ordinary => {
                if bit_len > MAX_DATA_BITS || self.references.len() > MAX_REFERENCES_COUNT {
                    return Err(ExceptionCode::CellOverflow)
                }
            },
            CellType::LibraryReference => { },
            CellType::Unknown => return Err(ExceptionCode::RangeCheckError)
        }

        // Check level

        let mut children_mask = LevelMask::with_mask(0);
        for child in self.references.iter() {
            children_mask |= child.level_mask();
        }
        let level_mask = match self.cell_type {
            CellType::Ordinary => children_mask,
            CellType::PrunedBranch => self.level_mask(),
            CellType::LibraryReference => LevelMask::with_mask(0), // TODO ???
            CellType::MerkleProof => LevelMask::for_merkle_cell(children_mask),
            CellType::MerkleUpdate => LevelMask::for_merkle_cell(children_mask),
            CellType::Unknown => return Err(ExceptionCode::RangeCheckError)
        };
        if self.level_mask != level_mask {
            return Err(ExceptionCode::RangeCheckError)
        }

        // calculate hashes and depths

        let is_merkle_cell = self.is_merkle();
        let is_pruned_cell = self.is_pruned();

        // pruned cell stores all hashes except representetion in data
        let hashes_count = if is_pruned_cell { 1 } else { self.level() as usize + 1 };
        
        let mut depths = vec![0_u16; hashes_count];
        let mut hashes = Vec::with_capacity(hashes_count);
        for i in 0..hashes_count {
            let mut hasher = Sha256::new();

            // data
            let level_mask = if is_pruned_cell {
                self.level_mask()
            } else {
                LevelMask::with_level(i as u8)
            };

            let (d1, d2) = BagOfCells::calculate_descriptor_bytes(
                bit_len,
                self.references.len() as u8,
                level_mask.mask(),
                self.cell_type() != CellType::Ordinary,
                false);
            hasher.input(&[d1, d2]);

            if i == 0 {
                let data_size = (bit_len / 8) + if bit_len % 8 != 0 { 1 } else { 0 };
                hasher.input(&self.data[..data_size]);
            } else {
                hasher.input(hashes.last().unwrap());
            }

            // depth
            for child in self.references.iter() {
                let child_depth = child.depth(if is_merkle_cell { i + 1 } else { i });
                depths[i] = max(depths[i], child_depth + 1);
                hasher.input(&child_depth.to_be_bytes());
            }

            // hashes
            for child in self.references.iter() {
                let child_hash = child.hash(if is_merkle_cell { i + 1 } else { i });
                hasher.input(child_hash.as_slice());
            }

            hashes.push(UInt256::from(hasher.result().to_vec()));
        }

        if self.store_hashes {
            if &depths != self.depths.as_ref().expect("cell have to store depths") {
                return Err(ExceptionCode::FatalError)
            }
           if &hashes != self.hashes.as_ref().expect("cell have to store hashes") {
               return Err(ExceptionCode::FatalError)
           }
        } else {
            self.hashes = Some(hashes);
            self.depths = Some(depths);
        }
        Ok(())
    }
}

impl CellImpl for DataCell {
    fn data(&self) -> &[u8] {
        &self.data
    }

    fn bit_length(&self) -> usize {
        find_tag(&self.data)
    }

    fn references_count(&self) -> usize {
        self.references.len()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        self.references.get(index).cloned().ok_or(ExceptionCode::CellUnderflow)
    }

    fn cell_type(&self) -> CellType {
        self.cell_type
    }

    fn level_mask(&self) -> LevelMask {
        self.level_mask
    }

    fn hash(&self, mut index: usize) -> UInt256 {
        index = self.level_mask.calc_hash_index(index);
        if self.cell_type == CellType::PrunedBranch {
            // pruned cell stores all hashes (except representetion) in data
            if index != self.level() as usize {
                let offset = 1 + 1 + index * SHA256_SIZE;
                self.data[offset..offset + SHA256_SIZE].into()
            } else if let Some(hashes) = self.hashes.as_ref() {
                hashes.get(0).map(|h| h.clone()).expect("cell is not finalized")
            } else {
                panic!("cell is not finalized")
            }
        }
        else if let Some(hashes) = self.hashes.as_ref() {
            hashes.get(index as usize).map(|h| h.clone()).expect("cell is not finalized")
        } else {
            panic!("cell is not finalized")
        }
    }

    fn depth(&self, mut index: usize) -> u16 {
        index = self.level_mask.calc_hash_index(index);
        if self.cell_type == CellType::PrunedBranch {
            // pruned cell stores all depth except "representetion" in data
            if index != self.level() as usize {
                let offset = 1 + 1 + (self.level() as usize) * SHA256_SIZE + index * 2;
                if offset + 2 <= self.data.len() {
                    let mut depth = [0; 2];
                    depth.copy_from_slice(&self.data[offset..offset + 2]);
                    return u16::from_be_bytes(depth)
                }
            } else if let Some(ref depths) = self.depths {
                if let Some(d) = depths.get(0) {
                    return *d
                }
            }
        } else if let Some(ref depths) = self.depths {
            if let Some(d) = depths.get(index as usize) {
                return *d
            }
        }
        error!(target: "tvm", "cell is not finalized");
        0
    }

    fn store_hashes(&self) -> bool {
        self.store_hashes
    }
}

#[derive(Clone)]
pub struct UsageCell {
    cell: Cell,
    visited: Arc<Mutex<HashSet<UInt256>>>
}

impl UsageCell {
    pub fn with_cell(cell: Cell) -> Self {
        UsageCell {
            cell,
            visited: Arc::new(Mutex::new(HashSet::new())),
        }
    }
    pub fn visited<'a>(&'a self) -> impl 'a + Deref<Target = HashSet<UInt256>> {
        self.visited.lock().unwrap()
    }
}

impl CellImpl for UsageCell {
    fn data(&self) -> &[u8] {
        self.visited.lock().unwrap().insert(self.cell.repr_hash());
        self.cell.data()
    }

    fn bit_length(&self) -> usize {
        self.cell.bit_length()
    }

    fn references_count(&self) -> usize {
        self.cell.references_count()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        self.visited.lock().unwrap().insert(self.cell.repr_hash());
        Ok(
            Cell::with_cell_impl(
                UsageCell {
                    cell: self.cell.reference(index)?,
                    visited: self.visited.clone(),
                }
            )
        )
    }

    fn cell_type(&self) -> CellType {
        self.cell.cell_type()
    }

    fn level_mask(&self) -> LevelMask {
        self.cell.level_mask()
    }

    fn hash(&self, index: usize) -> UInt256 {
        self.cell.hash(index)
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell.depth(index)
    }

    fn store_hashes(&self) -> bool {
        self.cell.store_hashes()
    }
}

#[derive(Clone)]
pub struct VirtualCell {
    offset: u8,
    cell: Cell,
}

impl VirtualCell {
    pub fn with_cell_and_offset(cell: Cell, offset: u8) -> Self {
        VirtualCell {
            offset,
            cell,
        }
    }
}

impl CellImpl for VirtualCell {
    fn data(&self) -> &[u8] {
        self.cell.data()
    }

    fn bit_length(&self) -> usize {
        self.cell.bit_length()
    }

    fn references_count(&self) -> usize {
        self.cell.references_count()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        Ok(self.cell.reference(index)?.virtualize(self.offset))
    }

    fn cell_type(&self) -> CellType {
        self.cell.cell_type()
    }

    fn level_mask(&self) -> LevelMask {
        self.cell.level_mask().virtualize(self.offset)
    }

    fn hash(&self, index: usize) -> UInt256 {
        self.cell.hash(self.level_mask().calc_virtual_hash_index(index, self.offset))
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell.depth(self.level_mask().calc_virtual_hash_index(index, self.offset))
    }

    fn store_hashes(&self) -> bool {
        self.cell.store_hashes()
    }
}

pub struct UsageTree {
    root: Arc<UsageCell>
}

impl UsageTree {
    pub fn with_root(root: Cell) -> Self {
        Self {
            root: Arc::new(UsageCell::with_cell(root)) 
        }
    }

    pub fn root_slice(&self) -> SliceData {
        SliceData::from(Cell::with_cell_impl_arc(self.root.clone()))
    }

    pub fn root_cell(&self) -> Cell {
        Cell::with_cell_impl_arc(self.root.clone())
    }

    pub fn visited<'a>(&'a self) -> impl 'a + Deref<Target = HashSet<UInt256>> {
        self.root.visited()
    }
}

mod slice;
pub use self::slice::*;

pub mod builder;
pub use self::builder::*;
mod builder_operations;
pub use self::builder_operations::*;
