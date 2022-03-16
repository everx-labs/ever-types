/*
* Copyright (C) 2019-2021 TON Labs. All Rights Reserved.
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

use crate::cells_serialization::{BagOfCells, SHA256_SIZE};
use crate::types::{ByteOrderRead, ExceptionCode, Result, UInt256};
use crate::{error, fail};
use num::{FromPrimitive, ToPrimitive};
use sha2::{Digest, Sha256};
use std::cmp::{max, min};
use std::fmt;
use std::ops::{BitOr, BitOrAssign, Deref};
use std::sync::{
    atomic::{AtomicU64, Ordering},
    Arc, Weak,
};

pub const MAX_REFERENCES_COUNT: usize = 4;
pub const MAX_DATA_BITS: usize = 1023;
pub const MAX_LEVEL: usize = 3;
pub const MAX_DEPTH: u16 = u16::MAX - 1;

/// Type of a cell.
///
/// There are three main kinds of cell types:
///
/// - [`Unknown`][Self::Unknown]: nothing is known about the cell type;
/// - [`Ordinary`][Self::Ordinary]: an ordinary cell, which do not require any special processing;
/// - *exotic*: exotic cells may be *loaded*, meaning they can automatically be replaced by other
///   cells when an attempt to deserialize them (*i.e.* to convert them into [`SliceData`] by a
///   `CTOS` instruction) is made. They may also exhibit a non-trivial behavior when their hashes
///   are computed.
///
///   Exotic cell types include [`PrunedBranch`][Self::PrunedBranch],
///   [`LibraryReference`][Self::LibraryReference], [`MerkleProof`][Self::MerkleProof], and
///   [`MerkleUpdate`][Self::MerkleUpdate].
#[derive(
    Debug, Clone, Copy, Eq, PartialEq, Hash, num_derive::FromPrimitive, num_derive::ToPrimitive,
)]
pub enum CellType {
    /// Unknown cell type.
    Unknown,
    /// Ordinary cell type, no special processing required.
    Ordinary,
    PrunedBranch,
    LibraryReference,
    MerkleProof,
    MerkleUpdate,
}
impl CellType {
    /// True if `self` is an ordinary cell type.
    ///
    /// ```rust
    /// # use ton_types::cell::CellType;
    /// assert!(CellType::Ordinary.is_ordinary());
    /// assert!(!CellType::Unknown.is_ordinary());
    /// ```
    #[inline]
    pub fn is_ordinary(self) -> bool {
        self == Self::Ordinary
    }

    /// [`u8`] representation of [`Self::Ordinary`].
    const ORDINARY_CODE: u8 = 0xff;
    /// [`u8`] representation of [`Self::Unknown`].
    const UNKNOWN_CODE: u8 = 0;
    /// [`u8`] representation of [`Self::PrunedBranch`].
    const PRUNED_BRANCH_CODE: u8 = 1;
    /// [`u8`] representation of [`Self::LibraryReference`].
    const LIBRARY_REFERENCE_CODE: u8 = 2;
    /// [`u8`] representation of [`Self::MerkleProof`].
    const MERKLE_PROOF_CODE: u8 = 3;
    /// [`u8`] representation of [`Self::MerkleUpdate`].
    const MERKLE_UPDATE_CODE: u8 = 4;

    /// Static string description of a cell type.
    ///
    /// ```rust
    /// # use ton_types::cell::CellType;
    /// assert_eq!(CellType::Ordinary.desc(), "Ordinary");
    /// assert_eq!(CellType::MerkleUpdate.desc(), "Merkle update");
    /// ```
    pub fn desc(self) -> &'static str {
        match self {
            Self::Ordinary => "Ordinary",
            Self::PrunedBranch => "Pruned branch",
            Self::LibraryReference => "Library reference",
            Self::MerkleProof => "Merkle proof",
            Self::MerkleUpdate => "Merkle update",
            Self::Unknown => "Unknown",
        }
    }
}

impl From<u8> for CellType {
    fn from(num: u8) -> CellType {
        if num == Self::PRUNED_BRANCH_CODE {
            Self::PrunedBranch
        } else if num == Self::LIBRARY_REFERENCE_CODE {
            Self::LibraryReference
        } else if num == Self::MERKLE_PROOF_CODE {
            Self::MerkleProof
        } else if num == Self::MERKLE_UPDATE_CODE {
            Self::MerkleUpdate
        } else {
            Self::Unknown
        }
    }
}
impl From<CellType> for u8 {
    fn from(ct: CellType) -> u8 {
        match ct {
            CellType::Unknown => CellType::UNKNOWN_CODE,
            CellType::Ordinary => CellType::ORDINARY_CODE,
            CellType::PrunedBranch => CellType::PRUNED_BRANCH_CODE,
            CellType::LibraryReference => CellType::LIBRARY_REFERENCE_CODE,
            CellType::MerkleProof => CellType::MERKLE_PROOF_CODE,
            CellType::MerkleUpdate => CellType::MERKLE_UPDATE_CODE,
        }
    }
}
impl fmt::Display for CellType {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.desc().fmt(f)
    }
}

/// De Brujn level of a cell, usually just called *level* of a cell.
///
/// # TODO
///
/// Would probably be much better to change the architecture so that no illegal value can be
/// constructed (while preserving performance).
#[derive(Debug, Clone, Copy, Default, Eq, PartialEq, Hash)]
pub struct LevelMask(
    /// De Brujn level.
    u8,
);

impl LevelMask {
    /// Constructor from a de Brujn level.
    ///
    /// If `level > 3`, an error is issued and the actual level created will be `0`.
    ///
    /// # Examples
    ///
    /// If `level` is not `0` or `1`, the actual level stored is different from `level`.
    ///
    /// ```rust
    /// # use ton_types::cell::LevelMask;
    /// fn check(level: u8, expected: u8) {
    /// #     println!("level: {}, expecting {}", level, expected);
    ///     let level = LevelMask::with_level(level);
    /// #     println!("=> {:?}", level);
    ///     assert_eq!(level.mask(), expected);
    /// }
    /// check(0, 0);
    /// check(1, 1);
    /// check(2, 3);
    /// check(3, 7);
    /// check(4, 0);
    /// check(5, 0);
    /// check(17, 0);
    /// ```
    pub fn with_level(level: u8) -> Self {
        LevelMask(match level {
            0 => 0,
            1 => 1,
            2 => 3,
            3 => 7,
            _ => {
                log::error!(target: "tvm", "{} {}", file!(), line!());
                0
            }
        })
    }

    /// Constructor from a mask.
    ///
    /// If `mask > 7`, an error is issued and the actual mask created will be `0`.
    ///
    /// # Examples
    ///
    /// ```rust
    /// # use ton_types::cell::LevelMask;
    /// fn check(level: u8, expected: u8) {
    /// #     println!("level: {}, expecting {}", level, expected);
    ///     let level = LevelMask::with_mask(level);
    /// #     println!("=> {:?}", level);
    ///     assert_eq!(level.mask(), expected);
    /// }
    /// check(0, 0);
    /// check(1, 1);
    /// check(2, 2);
    /// check(3, 3);
    /// check(4, 4);
    /// check(5, 5);
    /// check(6, 6);
    /// check(7, 7);
    /// check(8, 0);
    /// check(10, 0);
    /// check(17, 0);
    /// ```
    pub fn with_mask(mask: u8) -> Self {
        if mask <= 7 {
            LevelMask(mask)
        } else {
            log::error!(target: "tvm", "{} {}", file!(), line!());
            LevelMask(0)
        }
    }

    /// Level mask for a Merkle proof cell, from its child cell's mask.
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ton_types::cell::LevelMask;
    /// let mask = LevelMask::for_merkle_cell(LevelMask::with_level(2));
    /// assert_eq!(mask.mask(), 1);
    /// ```
    pub fn for_merkle_cell(children_mask: LevelMask) -> Self {
        LevelMask(children_mask.0 >> 1)
    }

    /// De Brujn level accessor.
    ///
    /// # TODO
    ///
    /// Functions over [`Copy`] types should (almost) never take `&self`, especially when they
    /// actually have a size equal to or smaller than pointers (which is the case here). Taking
    /// `&self` instead of `self` just introduces a useless indirection that needs to be resolved in
    /// the function. Note that this is not a breaking change, unless the function is called using
    /// [universal function call syntax]. Also note that the gain in performance would be very
    /// minimal.
    ///
    /// [universal function call syntax]:
    /// http://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/first-edition/ufcs.html
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ton_types::cell::LevelMask;
    /// fn check(level: u8, expected: u8) {
    /// #     println!("level: {}, expecting {}", level, expected);
    ///     let level = LevelMask::with_level(level);
    /// #     println!("=> {:?}", level);
    ///     assert_eq!(level.level(), expected);
    /// }
    /// check(0, 0);
    /// check(1, 1);
    /// check(2, 2);
    /// check(3, 3);
    /// check(4, 0);
    /// check(7, 0);
    /// check(8, 0);
    /// check(10, 0);
    /// check(17, 0);
    /// ```
    pub fn level(&self) -> u8 {
        if self.0 > 7 {
            log::error!(target: "tvm", "{} {}", file!(), line!());
            255
        } else {
            // count of set bits (low three)
            (self.0 & 1) + ((self.0 >> 1) & 1) + ((self.0 >> 2) & 1)
        }
    }

    /// Level mask accessor.
    ///
    /// # TODO
    ///
    /// Functions over [`Copy`] types should (almost) never take `&self`, especially when they
    /// actually have a size equal to or smaller than pointers (which is the case here). Taking
    /// `&self` instead of `self` just introduces a useless indirection that needs to be resolved in
    /// the function. Note that this is not a breaking change, unless the function is called using
    /// [universal function call syntax]. Also note that the gain in performance would be very
    /// minimal.
    ///
    /// [universal function call syntax]:
    /// http://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/first-edition/ufcs.html
    ///
    /// # Examples
    ///
    /// ```rust
    /// use ton_types::cell::LevelMask;
    /// fn check(level: u8, expected: u8) {
    /// #     println!("level: {}, expecting {}", level, expected);
    ///     let level = LevelMask::with_mask(level);
    /// #     println!("=> {:?}", level);
    ///     assert_eq!(level.mask(), expected);
    /// }
    /// check(0, 0);
    /// check(1, 1);
    /// check(2, 2);
    /// check(3, 3);
    /// check(4, 4);
    /// check(5, 5);
    /// check(6, 6);
    /// check(7, 7);
    /// check(8, 0);
    /// check(10, 0);
    /// check(17, 0);
    /// ```
    pub fn mask(&self) -> u8 {
        self.0
    }

    /// Hash of a level mask from an index.
    ///
    /// # TODO
    ///
    /// Functions over [`Copy`] types should (almost) never take `&self`, especially when they
    /// actually have a size equal to or smaller than pointers (which is the case here). Taking
    /// `&self` instead of `self` just introduces a useless indirection that needs to be resolved in
    /// the function. Note that this is not a breaking change, unless the function is called using
    /// [universal function call syntax]. Also note that the gain in performance would be very
    /// minimal.
    ///
    /// [universal function call syntax]:
    /// http://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/first-edition/ufcs.html
    ///
    /// Not sure why this function starts with `calc`. Is it to indicate that it performs
    /// computations? Because [`Self::level`] computes stuff too, but has no `calc_`. Would probably
    /// be more idiomatic to just call this function `hash_index`.
    pub fn calc_hash_index(&self, mut index: usize) -> usize {
        // if cell contains requared hash() - it will be returned, else = max avaliable, but less
        // then index
        //
        // rows - cell mask 0(0)  1(1)  2(3)  3(7)  columns - index(mask) 0     0     0     0     0
        //       cells - index(AND result) 1     0     1(1)  1(1)  1(1) 2     0     0(0)  1(2)  1(2)
        //       3     0     1(1)  2(3)  2(3) 4     0     0(0)  0(0)  1(4) 5     0     1(1)  0(0)
        //       2(5) 6     0     0(0)  1(2)  2(6) 7     0     1(1)  2(3)  3(7)
        index = min(index, 3);
        LevelMask::with_mask(self.0 & LevelMask::with_level(index as u8).0).level() as usize
    }

    /// Virtual hash of a level max from an index and a virtual offset.
    ///
    /// # TODO
    ///
    /// Functions over [`Copy`] types should (almost) never take `&self`, especially when they
    /// actually have a size equal to or smaller than pointers (which is the case here). Taking
    /// `&self` instead of `self` just introduces a useless indirection that needs to be resolved in
    /// the function. Note that this is not a breaking change, unless the function is called using
    /// [universal function call syntax]. Also note that the gain in performance would be very
    /// minimal.
    ///
    /// [universal function call syntax]:
    /// http://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/first-edition/ufcs.html
    ///
    /// Not sure why this function starts with `calc`. Is it to indicate that it performs
    /// computations? Because [`Self::level`] computes stuff too, but has no `calc_`. Would probably
    /// be more idiomatic to just call this function `virtual_hash_index`.
    pub fn calc_virtual_hash_index(&self, index: usize, virt_offset: u8) -> usize {
        LevelMask::with_mask(self.0 >> virt_offset).calc_hash_index(index)
    }

    /// Creates a virtual version of a level mask from an offset.
    ///
    /// # TODO
    ///
    /// Functions over [`Copy`] types should (almost) never take `&self`, especially when they
    /// actually have a size equal to or smaller than pointers (which is the case here). Taking
    /// `&self` instead of `self` just introduces a useless indirection that needs to be resolved in
    /// the function. Note that this is not a breaking change, unless the function is called using
    /// [universal function call syntax]. Also note that the gain in performance would be very
    /// minimal.
    ///
    /// [universal function call syntax]:
    /// http://web.mit.edu/rust-lang_v1.25/arch/amd64_ubuntu1404/share/doc/rust/html/book/first-edition/ufcs.html
    pub fn virtualize(&self, virt_offset: u8) -> Self {
        LevelMask::with_mask(self.0 >> virt_offset)
    }
}

impl BitOr for LevelMask {
    type Output = Self;
    fn bitor(self, rhs: Self) -> Self {
        // rhs is the "right-hand side" of the expression `a | b`
        LevelMask::with_mask(self.0 | rhs.0)
    }
}
impl BitOrAssign for LevelMask {
    fn bitor_assign(&mut self, rhs: Self) {
        self.0 |= rhs.0;
    }
}

pub trait CellImpl: Sync + Send {
    fn data(&self) -> &[u8];
    fn cell_data(&self) -> &CellData;
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

    fn tree_bits_count(&self) -> u64 {
        0
    }

    fn tree_cell_count(&self) -> u64 {
        0
    }
}

//#[derive(Clone)]
pub struct Cell(Arc<dyn CellImpl>);

lazy_static::lazy_static! {
    static ref CELL_COUNT: Arc<AtomicU64> = Arc::new(AtomicU64::new(0));
}

impl Clone for Cell {
    fn clone(&self) -> Self {
        Cell::with_cell_impl_arc(self.0.clone())
    }
}

impl Drop for Cell {
    fn drop(&mut self) {
        CELL_COUNT.fetch_sub(1, Ordering::Relaxed);
    }
}

impl Cell {
    pub fn virtualize(self, offset: u8) -> Self {
        if self.level_mask().mask() == 0 {
            self
        } else {
            Cell::with_cell_impl(VirtualCell::with_cell_and_offset(self, offset))
        }
    }

    pub fn with_cell_impl<T: 'static + CellImpl>(cell_impl: T) -> Self {
        let ret = Cell(Arc::new(cell_impl));
        CELL_COUNT.fetch_add(1, Ordering::Relaxed);
        ret
    }

    pub fn with_cell_impl_arc(cell_impl: Arc<dyn CellImpl>) -> Self {
        let ret = Cell(cell_impl);
        CELL_COUNT.fetch_add(1, Ordering::Relaxed);
        ret
    }

    pub fn cell_count() -> u64 {
        CELL_COUNT.load(Ordering::Relaxed)
    }

    pub fn reference(&self, index: usize) -> Result<Cell> {
        self.0.reference(index)
    }

    // TODO: make as simple clone
    pub fn clone_references(&self) -> SmallVec<[Cell; 4]> {
        let count = self.0.references_count();
        let mut refs = SmallVec::with_capacity(count);
        for i in 0..count {
            refs.push(self.0.reference(i).unwrap())
        }
        refs
    }

    pub fn data(&self) -> &[u8] {
        self.0.data()
    }

    pub fn cell_data(&self) -> &CellData {
        self.0.cell_data()
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

    pub fn count_cells(&self, max: usize) -> Result<usize> {
        let mut count = 0;
        let mut queue = vec![self.clone()];
        while let Some(cell) = queue.pop() {
            if count >= max {
                fail!("count exceeds max {}", max)
            }
            count += 1;
            let count = cell.references_count();
            for i in 0..count {
                queue.push(cell.reference(i)?);
            }
        }
        Ok(count)
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
        self.0.hash(MAX_LEVEL)
    }

    pub fn repr_depth(&self) -> u16 {
        self.0.depth(MAX_LEVEL)
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
        to_hex_string(self.data(), self.bit_length(), lower)
    }

    fn print_indent(
        f: &mut fmt::Formatter,
        indent: &str,
        last_child: bool,
        first_line: bool,
    ) -> fmt::Result {
        let build = match (first_line, last_child) {
            (true, true) => " └─",
            (true, false) => " ├─",
            (false, true) => "   ",
            (false, false) => " │ ",
        };
        write!(f, "{}{}", indent, build)
    }

    pub fn format_without_refs(
        &self,
        f: &mut fmt::Formatter,
        indent: &str,
        last_child: bool,
        full: bool,
        root: bool,
    ) -> fmt::Result {
        if !root {
            Self::print_indent(f, indent, last_child, true)?;
        }

        if full {
            write!(
                f,
                "{}   l: {:03b}   ",
                self.cell_type(),
                self.level_mask().mask()
            )?;
        }

        write!(f, "bits: {}", self.bit_length())?;
        write!(f, "   refs: {}", self.references_count())?;

        if self.data().len() > 100 {
            writeln!(f)?;
            if !root {
                Self::print_indent(f, indent, last_child, false)?;
            }
        } else {
            write!(f, "   ")?;
        }

        write!(f, "data: {}", self.to_hex_string(true))?;

        if full {
            writeln!(f)?;
            if !root {
                Self::print_indent(f, indent, last_child, false)?;
            }
            write!(f, "hashes:")?;
            for h in self.hashes().iter() {
                write!(f, " {:x}", h)?;
            }
            writeln!(f)?;
            if !root {
                Self::print_indent(f, indent, last_child, false)?;
            }
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
        remaining_depth: u16,
    ) -> std::result::Result<String, fmt::Error> {
        self.format_without_refs(f, &indent, last_child, full, root)?;
        if remaining_depth > 0 {
            if !root {
                indent.push(' ');
                indent.push(if last_child { ' ' } else { '│' });
            }
            for i in 0..self.references_count() {
                let child = self.reference(i).unwrap();
                writeln!(f)?;
                indent = child.format_with_refs_tree(
                    f,
                    indent,
                    i == self.references_count() - 1,
                    full,
                    false,
                    remaining_depth - 1,
                )?;
            }
            if !root {
                indent.pop();
                indent.pop();
            }
        }
        Ok(indent)
    }
    fn tree_bits_count(&self) -> u64 {
        self.0.tree_bits_count()
    }

    fn tree_cell_count(&self) -> u64 {
        self.0.tree_cell_count()
    }
}

impl Deref for Cell {
    type Target = dyn CellImpl;
    fn deref(&self) -> &Self::Target {
        self.0.deref()
    }
}

impl Cell {
    pub fn read_from_file(file_name: &str) -> Self {
        let bytes = std::fs::read(file_name).unwrap();
        crate::cells_serialization::deserialize_tree_of_cells(&mut std::io::Cursor::new(bytes))
            .unwrap()
    }
    pub fn write_to_file(&self, file_name: &str) {
        let bytes = crate::cells_serialization::serialize_toc(self).unwrap();
        std::fs::write(file_name, bytes).unwrap();
    }
}

impl Default for Cell {
    fn default() -> Self {
        Cell::with_cell_impl_arc(Arc::new(DataCell::new()))
    }
}

impl PartialEq for Cell {
    fn eq(&self, other: &Cell) -> bool {
        self.repr_hash() == other.repr_hash()
    }
}

impl PartialEq<UInt256> for Cell {
    fn eq(&self, other_hash: &UInt256) -> bool {
        &self.repr_hash() == other_hash
    }
}

impl Eq for Cell {}

impl fmt::Debug for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:x}", self.repr_hash())
    }
}

impl fmt::Display for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        self.format_with_refs_tree(
            f,
            "".to_string(),
            true,
            f.alternate(),
            true,
            min(f.precision().unwrap_or(0), MAX_DEPTH as usize) as u16,
        )?;
        Ok(())
    }
}

impl fmt::LowerHex for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex_string(true))
    }
}

impl fmt::UpperHex for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.to_hex_string(false))
    }
}

impl fmt::Binary for Cell {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            self.data()
                .iter()
                .map(|x| format!("{:08b}", *x))
                .collect::<Vec<_>>()
                .join("")
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

pub fn append_tag(data: &mut SmallVec<[u8; 128]>, bits: usize) {
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

#[derive(Clone, Debug, PartialEq)]
pub struct CellData {
    cell_type: CellType,
    data: SmallVec<[u8; 128]>,
    bit_length: u16,
    level_mask: LevelMask,
    store_hashes: bool,
    hashes: Option<[UInt256; 4]>,
    depths: Option<[u16; 4]>,
}

impl Default for CellData {
    fn default() -> Self {
        Self::new()
    }
}

impl CellData {
    pub fn new() -> Self {
        Self {
            cell_type: CellType::Ordinary,
            data: SmallVec::new(),
            bit_length: 0,
            level_mask: LevelMask(0),
            store_hashes: false,
            hashes: Some([
                UInt256::DEFAULT_CELL_HASH,
                UInt256::MIN,
                UInt256::MIN,
                UInt256::MIN,
            ]),
            depths: Some([0; 4]),
        }
    }
    pub fn with_params(
        cell_type: CellType,
        data: impl Into<SmallVec<[u8; 128]>>,
        level_mask: u8,
        store_hashes: bool,
        hashes: Option<[UInt256; 4]>,
        depths: Option<[u16; 4]>,
    ) -> Self {
        let data = data.into();
        let bit_length = find_tag(data.as_ref());
        assert!(bit_length <= MAX_DATA_BITS);
        Self {
            cell_type,
            data,
            bit_length: bit_length as u16,
            level_mask: LevelMask::with_mask(level_mask),
            store_hashes,
            hashes,
            depths,
        }
    }

    pub fn cell_type(&self) -> CellType {
        self.cell_type
    }

    pub fn data(&self) -> &[u8] {
        &self.data
    }

    pub fn bit_length(&self) -> u16 {
        self.bit_length
    }

    pub fn level(&self) -> u8 {
        self.level_mask.level()
    }

    pub fn level_mask(&self) -> LevelMask {
        self.level_mask
    }

    pub fn store_hashes(&self) -> bool {
        self.store_hashes
    }

    pub fn hashes(&self) -> Option<&[UInt256; 4]> {
        self.hashes.as_ref()
    }

    fn set_hashes(&mut self, hashes: Option<[UInt256; 4]>) {
        self.hashes = hashes
    }

    pub fn depths(&self) -> Option<&[u16; 4]> {
        self.depths.as_ref()
    }

    fn set_depths(&mut self, depths: Option<[u16; 4]>) {
        self.depths = depths
    }

    pub fn hash(&self, mut index: usize) -> UInt256 {
        index = self.level_mask.calc_hash_index(index);
        if self.cell_type() == CellType::PrunedBranch {
            // pruned cell stores all hashes (except representation) in data
            if index != self.level() as usize {
                let offset = 1 + 1 + index * SHA256_SIZE;
                UInt256::from_slice(&self.data()[offset..offset + SHA256_SIZE])
            } else if let Some(hashes) = self.hashes.as_ref() {
                hashes[0].clone()
            } else {
                unreachable!("cell is not finalized")
            }
        } else if let Some(hashes) = self.hashes().as_ref() {
            hashes
                .get(index as usize)
                .cloned()
                .expect("cell is not finalized")
        } else {
            unreachable!("cell is not finalized")
        }
    }

    pub fn depth(&self, mut index: usize) -> u16 {
        index = self.level_mask.calc_hash_index(index);
        if self.cell_type() == CellType::PrunedBranch {
            // pruned cell stores all depth except "representetion" in data
            if index != self.level() as usize {
                let offset = 1 + 1 + (self.level() as usize) * SHA256_SIZE + index * 2;
                if offset + 2 <= self.data().len() {
                    let mut depth = [0; 2];
                    depth.copy_from_slice(&self.data()[offset..offset + 2]);
                    return u16::from_be_bytes(depth);
                }
            } else if let Some(depths) = self.depths() {
                if let Some(d) = depths.get(0) {
                    return *d;
                }
            }
        } else if let Some(depths) = self.depths() {
            if let Some(d) = depths.get(index as usize) {
                return *d;
            }
        }
        log::error!(target: "tvm", "cell is not finalized");
        0
    }

    /// Binary serialization of cell data
    pub fn serialize<T: Write>(&self, writer: &mut T) -> Result<()> {
        writer.write_all(&[self.cell_type.to_u8().unwrap()])?;
        writer.write_all(&self.bit_length.to_le_bytes())?;
        writer.write_all(&self.data[0..(self.bit_length as usize + 8) / 8])?;
        writer.write_all(&[self.level_mask.0])?;
        writer.write_all(&[if self.store_hashes { 1 } else { 0 }])?;
        if let Some(ref hashes) = self.hashes {
            let mut len = hashes.len();
            if let Some(pos) = hashes.iter().position(|hash| hash == &UInt256::MIN) {
                len = std::cmp::min(len, pos);
            }
            writer.write_all(&[1])?;
            writer.write_all(&[len as u8])?;
            for hash in hashes.iter().take(len) {
                writer.write_all(hash.as_slice())?;
            }
        } else {
            writer.write_all(&[0])?;
        }
        if let Some(ref depths) = self.depths {
            let mut len = depths.len();
            if let Some(pos) = depths.iter().position(|depth| depth == &0) {
                len = std::cmp::min(len, pos);
            }
            writer.write_all(&[1])?;
            writer.write_all(&[len as u8])?;
            for depth in depths.iter().take(len) {
                writer.write_all(&depth.to_le_bytes())?;
            }
        } else {
            writer.write_all(&[0])?;
        }
        Ok(())
    }

    /// Binary deserialization of cell data
    pub fn deserialize<T: Read>(reader: &mut T) -> Result<Self> {
        let cell_type: CellType = FromPrimitive::from_u8(reader.read_byte()?)
            .ok_or_else(|| std::io::Error::from(ErrorKind::InvalidData))?;
        let bit_length = reader.read_le_u16()?;
        let data_len = ((bit_length + 8) / 8) as usize;
        let mut data = vec![0; data_len]; //todo optimize
        reader.read_exact(&mut data)?;
        let level_mask = reader.read_byte()?;
        let store_hashes = Self::read_bool(reader)?;
        let hashes =
            Self::read_short_array_opt(reader, |reader| Ok(UInt256::from(reader.read_u256()?)))?;
        let depths = Self::read_short_array_opt(reader, |reader| Ok(reader.read_le_u16()?))?;

        Ok(Self::with_params(
            cell_type,
            data,
            level_mask,
            store_hashes,
            hashes,
            depths,
        ))
    }

    fn read_short_array_opt<R, T, F>(reader: &mut R, read_func: F) -> Result<Option<[T; 4]>>
    where
        R: Read,
        T: Default,
        F: Fn(&mut R) -> Result<T>,
    {
        if Self::read_bool(reader)? {
            Ok(Some(Self::read_short_array(reader, read_func)?))
        } else {
            Ok(None)
        }
    }

    fn read_short_array<R, T, F>(reader: &mut R, read_func: F) -> Result<[T; 4]>
    where
        R: Read,
        T: Default,
        F: Fn(&mut R) -> Result<T>,
    {
        let count = reader.read_byte()?;
        if count > 4 {
            fail!("count too big {}", count)
        }
        let mut result = [T::default(), T::default(), T::default(), T::default()];
        for i in 0..count {
            result[i as usize] = read_func(reader)?;
        }
        Ok(result)
    }

    fn read_bool<R: Read>(reader: &mut R) -> Result<bool> {
        match reader.read_byte()? {
            1 => Ok(true),
            0 => Ok(false),
            _ => fail!(std::io::Error::from(ErrorKind::InvalidData)),
        }
    }
}

#[derive(Clone, Debug)]
pub struct DataCell {
    cell_data: CellData,
    references: SmallVec<[Cell; 4]>,
    tree_bits_count: u64,
    tree_cell_count: u64,
}

impl Default for DataCell {
    fn default() -> Self {
        Self::new()
    }
}

impl DataCell {
    pub fn new() -> Self {
        Self {
            cell_data: CellData::new(),
            references: SmallVec::new(),
            tree_bits_count: 0,
            tree_cell_count: 1,
        }
    }

    pub fn with_max_depth(
        references: impl Into<SmallVec<[Cell; 4]>>,
        data: impl Into<SmallVec<[u8; 128]>>,
        cell_type: CellType,
        level_mask: u8,
        max_depth: u16,
    ) -> Result<DataCell> {
        let cell_data = CellData::with_params(cell_type, data, level_mask, false, None, None);
        let mut tree_bits_count = cell_data.bit_length as u64;
        let mut tree_cell_count = 1;
        let references = references.into();
        for reference in &references {
            tree_bits_count += reference.tree_bits_count();
            tree_cell_count += reference.tree_cell_count();
        }
        let mut cell = DataCell {
            cell_data,
            references,
            tree_bits_count,
            tree_cell_count,
        };
        cell.finalize(true, max_depth)?;
        Ok(cell)
    }

    pub fn with_params<TRefs>(
        refs: TRefs,
        data: impl Into<SmallVec<[u8; 128]>>,
        cell_type: CellType,
        level_mask: u8,
        hashes: Option<[UInt256; 4]>,
        depths: Option<[u16; 4]>,
    ) -> Result<DataCell>
    where
        TRefs: IntoIterator<Item = Cell>,
    {
        assert_eq!(hashes.is_some(), depths.is_some());

        let store_hashes = hashes.is_some();
        let cell_data =
            CellData::with_params(cell_type, data, level_mask, store_hashes, hashes, depths);
        let mut references = SmallVec::new();
        let mut tree_bits_count = cell_data.bit_length as u64;
        let mut tree_cell_count = 1;
        for reference in refs.into_iter() {
            tree_bits_count += reference.tree_bits_count();
            tree_cell_count += reference.tree_cell_count();
            references.push(reference);
        }
        let mut cell = DataCell {
            cell_data,
            references,
            tree_bits_count,
            tree_cell_count,
        };
        cell.finalize(true, 0)?;
        Ok(cell)
    }

    fn finalize(&mut self, force: bool, max_depth: u16) -> Result<()> {
        if !force && self.hashes().is_some() && self.depths().is_some() {
            return Ok(());
        }

        // Check data size and references count

        let bit_len = self.bit_length();

        match self.cell_type() {
            CellType::PrunedBranch => {
                // type + level_mask + level * (hashes + depths)
                if bit_len != 8 * (1 + 1 + (self.level() as usize) * (SHA256_SIZE + 2)) {
                    fail!(
                        "fail creating pruned branch cell: {} != {}",
                        bit_len,
                        8 * (1 + 1 + (self.level() as usize) * (SHA256_SIZE + 2))
                    )
                }
                if !self.references.is_empty() {
                    fail!(
                        "fail creating pruned branch cell: references {} != 0",
                        self.references.len()
                    )
                }
                if self.data()[0] != u8::from(CellType::PrunedBranch) {
                    fail!(
                        "fail creating pruned branch cell: data[0] {} != {}",
                        self.data()[0],
                        u8::from(CellType::PrunedBranch)
                    )
                }
                if self.data()[1] != self.cell_data.level_mask.0 {
                    fail!(
                        "fail creating pruned branch cell: data[1] {} != {}",
                        self.data()[1],
                        self.cell_data.level_mask.0
                    )
                }
            }
            CellType::MerkleProof => {
                // type + hash + depth
                if bit_len != 8 * (1 + SHA256_SIZE + 2) {
                    fail!(
                        "fail creating merkle proof cell: bit_len {} != {}",
                        bit_len,
                        8 * (1 + SHA256_SIZE + 2)
                    )
                }
                if self.references.len() != 1 {
                    fail!(
                        "fail creating merkle proof cell: references {} != 1",
                        self.references.len()
                    )
                }
                // TODO check hashes and depths
            }
            CellType::MerkleUpdate => {
                // type + 2 * (hash + depth)
                if bit_len != 8 * (1 + 2 * (SHA256_SIZE + 2)) {
                    fail!(
                        "fail creating merkle unpdate cell: bit_len {} != {}",
                        bit_len,
                        8 * (1 + 2 * (SHA256_SIZE + 2))
                    )
                }
                if self.references.len() != 2 {
                    fail!(
                        "fail creating merkle unpdate cell: references {} != 2",
                        self.references.len()
                    )
                }
                // TODO check hashes and depths
            }
            CellType::Ordinary => {
                if bit_len > MAX_DATA_BITS {
                    fail!(
                        "fail creating ordinary cell: bit_len {} > {}",
                        bit_len,
                        MAX_DATA_BITS
                    )
                }
                if self.references.len() > MAX_REFERENCES_COUNT {
                    fail!(
                        "fail creating ordinary cell: references {} > {}",
                        self.references.len(),
                        MAX_REFERENCES_COUNT
                    )
                }
            }
            CellType::LibraryReference => {
                if bit_len != 8 * (1 + SHA256_SIZE) {
                    fail!(
                        "fail creating libray reference cell: bit_len {} != {}",
                        bit_len,
                        8 * (1 + SHA256_SIZE)
                    )
                }
                if !self.references.is_empty() {
                    fail!(
                        "fail creating libray reference cell: references {} != 0",
                        self.references.len()
                    )
                }
            }
            CellType::Unknown => {
                fail!("fail creating unknown cell")
            }
        }

        // Check level

        let mut children_mask = LevelMask::with_mask(0);
        for child in self.references.iter() {
            children_mask |= child.level_mask();
        }
        let level_mask = match self.cell_type() {
            CellType::Ordinary => children_mask,
            CellType::PrunedBranch => self.level_mask(),
            CellType::LibraryReference => LevelMask::with_mask(0),
            CellType::MerkleProof => LevelMask::for_merkle_cell(children_mask),
            CellType::MerkleUpdate => LevelMask::for_merkle_cell(children_mask),
            CellType::Unknown => fail!(ExceptionCode::RangeCheckError),
        };
        if self.cell_data.level_mask != level_mask {
            fail!(ExceptionCode::RangeCheckError)
        }

        // calculate hashes and depths

        let is_merkle_cell = self.is_merkle();
        let is_pruned_cell = self.is_pruned();

        // pruned cell stores all hashes except representetion in data
        let hashes_count = if is_pruned_cell {
            1
        } else {
            self.level() as usize + 1
        };

        let mut depths = [0_u16; 4];
        let mut hashes = [UInt256::MIN; 4];
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
                false,
            );
            hasher.update(&[d1, d2]);

            if i == 0 {
                let data_size = (bit_len / 8) + if bit_len % 8 != 0 { 1 } else { 0 };
                hasher.update(&self.data()[..data_size]);
            } else {
                hasher.update(hashes[i - 1].as_slice());
            }

            // depth
            for child in self.references.iter() {
                let child_depth = child.depth(if is_merkle_cell { i + 1 } else { i });
                depths[i] = max(depths[i], child_depth + 1);
                if ((max_depth != 0) && (depths[i] > max_depth)) || (depths[i] > MAX_DEPTH) {
                    fail!(
                        "fail creating cell: depth {} > {}",
                        depths[i],
                        std::cmp::max(max_depth, MAX_DEPTH)
                    )
                }
                hasher.update(&child_depth.to_be_bytes());
            }

            // hashes
            for child in self.references.iter() {
                let child_hash = child.hash(if is_merkle_cell { i + 1 } else { i });
                hasher.update(child_hash.as_slice());
            }

            hashes[i] = From::<[u8; 32]>::from(hasher.finalize().into());
            // debug_assert_ne!(hashes[i], UInt256::DEFAULT_CELL_HASH);
        }

        if self.store_hashes() {
            if Some(&depths) != self.depths() {
                fail!("store_hashes set and depths do not equal to self.depths")
            }
            if Some(&hashes) != self.hashes() {
                fail!("store_hashes set and hashes do not equal to self.hashes")
            }
        } else {
            self.set_hashes(Some(hashes));
            self.set_depths(Some(depths));
        }
        Ok(())
    }

    pub fn cell_data(&self) -> &CellData {
        &self.cell_data
    }

    fn hashes(&self) -> Option<&[UInt256; 4]> {
        self.cell_data.hashes()
    }

    fn set_hashes(&mut self, hashes: Option<[UInt256; 4]>) {
        self.cell_data.set_hashes(hashes)
    }

    fn depths(&self) -> Option<&[u16; 4]> {
        self.cell_data.depths()
    }

    fn set_depths(&mut self, depths: Option<[u16; 4]>) {
        self.cell_data.set_depths(depths)
    }
}

impl CellImpl for DataCell {
    fn data(&self) -> &[u8] {
        self.cell_data.data()
    }

    fn cell_data(&self) -> &CellData {
        self.cell_data()
    }

    fn bit_length(&self) -> usize {
        self.cell_data.bit_length() as usize
    }

    fn references_count(&self) -> usize {
        self.references.len()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        self.references
            .get(index)
            .cloned()
            .ok_or_else(|| error!(ExceptionCode::CellUnderflow))
    }

    fn cell_type(&self) -> CellType {
        self.cell_data.cell_type()
    }

    fn level_mask(&self) -> LevelMask {
        self.cell_data.level_mask()
    }

    fn hash(&self, index: usize) -> UInt256 {
        self.cell_data().hash(index)
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell_data().depth(index)
    }

    fn store_hashes(&self) -> bool {
        self.cell_data().store_hashes()
    }

    fn tree_bits_count(&self) -> u64 {
        self.tree_bits_count
    }

    fn tree_cell_count(&self) -> u64 {
        self.tree_cell_count
    }
}

#[derive(Clone)]
struct UsageCell {
    cell: Cell,
    visit_on_load: bool,
    visited: Weak<lockfree::set::Set<UInt256>>,
}

impl UsageCell {
    fn new(inner: Cell, visit_on_load: bool, visited: Weak<lockfree::set::Set<UInt256>>) -> Self {
        let cell = Self {
            cell: inner,
            visit_on_load,
            visited,
        };
        if visit_on_load {
            cell.visit();
        }
        cell
    }
    fn visit(&self) -> bool {
        if let Some(visited) = self.visited.upgrade() {
            visited.insert(self.cell.repr_hash()).ok();
            return true;
        }
        false
    }
}

impl CellImpl for UsageCell {
    fn data(&self) -> &[u8] {
        if !self.visit_on_load {
            self.visit();
        }
        self.cell.data()
    }

    fn cell_data(&self) -> &CellData {
        if !self.visit_on_load {
            self.visit();
        }
        self.cell.cell_data()
    }

    fn bit_length(&self) -> usize {
        self.cell.bit_length()
    }

    fn references_count(&self) -> usize {
        self.cell.references_count()
    }

    fn reference(&self, index: usize) -> Result<Cell> {
        if self.visit_on_load && self.visited.upgrade().is_some() || self.visit() {
            let cell = UsageCell::new(
                self.cell.reference(index)?,
                self.visit_on_load,
                self.visited.clone(),
            );
            Ok(Cell::with_cell_impl(cell))
        } else {
            self.cell.reference(index)
        }
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

    fn tree_bits_count(&self) -> u64 {
        self.cell.tree_bits_count()
    }

    fn tree_cell_count(&self) -> u64 {
        self.cell.tree_cell_count()
    }
}

#[derive(Clone)]
pub struct VirtualCell {
    offset: u8,
    cell: Cell,
}

impl VirtualCell {
    pub fn with_cell_and_offset(cell: Cell, offset: u8) -> Self {
        VirtualCell { offset, cell }
    }
}

impl CellImpl for VirtualCell {
    fn data(&self) -> &[u8] {
        self.cell.data()
    }

    fn cell_data(&self) -> &CellData {
        self.cell.cell_data()
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
        self.cell.hash(
            self.level_mask()
                .calc_virtual_hash_index(index, self.offset),
        )
    }

    fn depth(&self, index: usize) -> u16 {
        self.cell.depth(
            self.level_mask()
                .calc_virtual_hash_index(index, self.offset),
        )
    }

    fn store_hashes(&self) -> bool {
        self.cell.store_hashes()
    }

    fn tree_bits_count(&self) -> u64 {
        self.cell.tree_bits_count()
    }

    fn tree_cell_count(&self) -> u64 {
        self.cell.tree_cell_count()
    }
}

#[derive(Default)]
pub struct UsageTree {
    root: Cell,
    visited: Arc<lockfree::set::Set<UInt256>>,
}

impl UsageTree {
    pub fn with_root(root: Cell) -> Self {
        let visited = Arc::new(lockfree::set::Set::new());
        let usage_cell = UsageCell::new(root, false, Arc::downgrade(&visited));
        let root = Cell::with_cell_impl_arc(Arc::new(usage_cell));
        Self { root, visited }
    }

    pub fn with_params(root: Cell, visit_on_load: bool) -> Self {
        let visited = Arc::new(lockfree::set::Set::new());
        let root = Cell::with_cell_impl_arc(Arc::new(UsageCell::new(
            root,
            visit_on_load,
            Arc::downgrade(&visited),
        )));
        Self { root, visited }
    }

    pub fn use_cell(&self, cell: Cell, visit_on_load: bool) -> Cell {
        let usage_cell = UsageCell::new(cell, visit_on_load, Arc::downgrade(&self.visited));
        usage_cell.visit();
        Cell::with_cell_impl(usage_cell)
    }

    pub fn use_cell_opt(&self, cell_opt: &mut Option<Cell>, visit_on_load: bool) {
        if let Some(cell) = cell_opt.as_mut() {
            *cell = self.use_cell(cell.clone(), visit_on_load);
        }
    }

    pub fn root_slice(&self) -> SliceData {
        SliceData::from(self.root.clone())
    }

    pub fn root_cell(&self) -> Cell {
        self.root.clone()
    }

    /// destroy usage tree and free all cells
    pub fn visited(self) -> lockfree::set::Set<UInt256> {
        // safe because Arc is used to share weak pointers, nobody must clone this Arc
        Arc::try_unwrap(self.visited).unwrap()
    }

    pub fn contains(&self, hash: &UInt256) -> bool {
        self.visited.contains(hash)
    }
}

mod slice;

pub use self::slice::*;

pub mod builder;

pub use self::builder::*;

mod builder_operations;

pub use self::builder_operations::*;
use smallvec::SmallVec;
use std::io::{ErrorKind, Read, Write};

pub(crate) fn to_hex_string(data: &[u8], len: usize, lower: bool) -> String {
    if len == 0 {
        return String::new();
    }
    let mut result = if lower {
        hex::encode(data)
    } else {
        hex::encode_upper(data)
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
        _ => result.push('_'),
    }
    result
}
