/*
* Copyright (C) 2019-2023 EverX. All Rights Reserved.
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


use std::{
    collections::{HashMap, HashSet},
    io::{Read, Write, Seek, SeekFrom, Cursor},
    sync::Arc, ops::Deref,
};

use crc::{Crc, CRC_32_ISCSI, Digest};
const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

use crate::{
    cell::{self, Cell, DataCell, SHA256_SIZE, DEPTH_SIZE, MAX_DATA_BYTES, MAX_SAFE_DEPTH},
    ByteOrderRead, UInt256, Result, Status, fail, error, MAX_REFERENCES_COUNT, full_len, CellType, MAX_BIG_DATA_BYTES, CellImpl,
};
use smallvec::SmallVec;

const BOC_INDEXED_TAG: u32 = 0x68ff65f3; // deprecated, is used only for read
const BOC_INDEXED_CRC32_TAG: u32 = 0xacc3a728; // deprecated, is used only for read
const BOC_GENERIC_TAG: u32 = 0xb5ee9c72;
const BOC_GENERIC_V2_TAG: u32 = 0xb6ff9a73; // with big cells

const MAX_ROOTS_COUNT: usize = 1024;

pub trait OrderedCellsStorage {
    fn get_cell_by_index(&self, index: u32) -> Result<Cell>;
    fn get_rev_index_by_hash(&self, hash: &UInt256) -> Result<u32>;
    fn store_cell(&mut self, cell: Cell) -> Result<()>;
    fn push_cell(&mut self, hash: &UInt256) -> Result<()>;
    fn contains_hash(&self, hash: &UInt256) -> Result<bool>;
    fn cleanup(&mut self) -> Result<()>;
}

#[derive(Default)]
pub struct SimpleOrderedCellsStorage {
    cells: HashMap<UInt256, (Cell, u32)>, // cell, reversed index (from end)
    sorted_rev: Vec<UInt256>,
}

impl OrderedCellsStorage for SimpleOrderedCellsStorage {
    fn store_cell(&mut self, cell: Cell) -> Result<()> {
        self.cells.insert(cell.repr_hash(), (cell, 0));
        Ok(())
    }

    fn push_cell(&mut self, hash: &UInt256) -> Result<()> {
        self.cells
            .get_mut(hash)
            .ok_or_else(|| error!("Can't find cell with hash {:x}", hash))?
            .1 = self.sorted_rev.len() as u32;
        self.sorted_rev.push(hash.clone());
        Ok(())
    }

    fn get_cell_by_index(&self, index: u32) -> Result<Cell> {
        if let Some(hash) = self.sorted_rev.get(index as usize) {
            if let Some((cell, _)) = self.cells.get(hash) {
                Ok(cell.clone())
            } else {
                fail!("Can't find cell with hash {:x}", hash)
            }
        } else {
            fail!("Can't find cell with index {}", index)
        }
    }

    fn get_rev_index_by_hash(&self, hash: &UInt256) -> Result<u32> {
        if let Some((_, index)) = self.cells.get(hash) {
            Ok(*index)
        } else {
            fail!("Can't find cell index with hash {:x}", hash)
        }
    }
    fn contains_hash(&self, hash: &UInt256) -> Result<bool> {
        Ok(self.cells.contains_key(hash))
    }

    fn cleanup(&mut self) -> Result<()> { Ok(()) }
}

#[derive(Clone)]
pub struct BocWriter<'a, S: OrderedCellsStorage> {
    roots_indexes_rev: Vec<usize>,
    cells: S,
    data_size: usize,
    references: usize,
    cells_count: usize,
    big_cells_count: usize,
    big_cells_size: usize,
    abort: &'a dyn Fn() -> bool,
}

pub fn write_boc(root_cell: &Cell) -> Result<Vec<u8>> {
    let mut buf = Vec::new();
    BocWriter::with_root(root_cell)?.write(&mut buf)?;
    Ok(buf)
}

impl<'a> BocWriter<'a, SimpleOrderedCellsStorage> {
    pub fn with_root(root_cell: &'a Cell) -> Result<Self> {
        Self::with_roots([root_cell.clone()])
    }
    pub fn with_owned_root(root_cell: Cell) -> Result<Self> {
        Self::with_roots([root_cell])
    }
    pub fn with_roots(root_cells: impl IntoIterator<Item = Cell>) -> Result<Self> {
        fn default_abort() -> bool { false }
        BocWriter::<SimpleOrderedCellsStorage>::with_params(
            root_cells,
            MAX_SAFE_DEPTH,
            SimpleOrderedCellsStorage::default(),
            &default_abort
        )
    }
}

impl<'a, S: OrderedCellsStorage> BocWriter<'a, S> {

    pub fn with_params(
        root_cells: impl IntoIterator<Item = Cell>,
        max_depth: u16,
        cells_storage: S,
        abort: &'a dyn Fn() -> bool,
    ) -> Result<Self> {

        let mut boc = BocWriter {
            roots_indexes_rev: Vec::new(),
            cells: cells_storage,
            data_size: 0,
            references: 0,
            cells_count: 0,
            big_cells_count: 0,
            big_cells_size: 0,
            abort,
        };
        let mut roots_set = HashSet::new();
        for root_cell in root_cells {
            if root_cell.virtualization() != 0 {
                fail!("Virtual cells serialisation is prohibited");
            }
            if !roots_set.insert(root_cell.repr_hash()) {
                fail!("roots must be all unique")
            }
            let depth = root_cell.repr_depth();
            if depth > max_depth {
                fail!("Cell {:x} is too deep: {} > {}", root_cell.repr_hash(), depth, max_depth);
            }

            if let Ok(rev_index) = boc.cells.get_rev_index_by_hash(&root_cell.repr_hash()) {
                boc.roots_indexes_rev.push(rev_index as usize);
            } else {
                boc.traverse(root_cell)?;
                boc.roots_indexes_rev.push(boc.cells_count - 1); // root must be added into `sorted_rev` back
            }
        }

        // roots must be firtst
        // TODO: due to real ton sorces it is not necceary to write roots first
        Ok(boc)
    }

    pub fn roots_count(&self) -> usize {
        self.roots_indexes_rev.len()
    }

    pub fn data_size(&self) -> usize {
        self.data_size
    }

    pub fn references_count(&self) -> usize {
        self.references
    }

    pub fn cells_count(&self) -> usize {
        self.cells_count
    }

    pub fn big_cells_count(&self) -> usize {
        self.big_cells_count
    }

    pub fn big_cells_size(&self) -> usize {
        self.big_cells_size
    }

    pub fn write<T: Write>(self, dest: &mut T) -> Result<()> {
        self.write_ex(dest, false, false, None, None)
    }

    pub fn write_ex<T: Write>(
        self,
        dest: &mut T,
        include_index: bool,
        include_crc: bool,
        custom_ref_size: Option<usize>,
        custom_offset_size: Option<usize>,
    ) -> Result<()> {
        if include_crc {
            let mut dest_wrapped = IoCrcFilter::new_writer(dest);
            self.write_ex_impl(&mut dest_wrapped, include_index, include_crc, custom_ref_size, custom_offset_size)?;
            dest_wrapped.finalize()
        } else {
            self.write_ex_impl(dest, include_index, include_crc, custom_ref_size, custom_offset_size)
        }
    }

    fn write_ex_impl<T: Write>(
        mut self,
        dest: &mut T,
        include_index: bool,
        include_crc: bool,
        custom_ref_size: Option<usize>,
        custom_offset_size: Option<usize>,
    ) -> Result<()> {
        let bytes_total_cells = Self::number_of_bytes_to_fit(self.cells_count);
        let ref_size = custom_ref_size.map_or(bytes_total_cells, |crs| {
            debug_assert!(crs >= bytes_total_cells);
            std::cmp::max(crs, bytes_total_cells)
        });
        let total_cells_size = self.data_size + self.references * ref_size;
        let bytes_total_size = Self::number_of_bytes_to_fit(total_cells_size);
        let offset_size = custom_offset_size.map_or(bytes_total_size, |cos| {
            debug_assert!(cos >= bytes_total_size);
            std::cmp::max(cos, bytes_total_size)
        });

        debug_assert!(ref_size <= 4);
        debug_assert!(offset_size <= 8);

        // Header

        let magic = if self.big_cells_count > 0 {
            BOC_GENERIC_V2_TAG
        } else {
            BOC_GENERIC_TAG
        };
        dest.write_all(&magic.to_be_bytes())?;

        // has index | has CRC | has cache bits | flags   | ref_size
        // 7         | 6       | 5              | 4 3     | 2 1 0
        dest.write_all(&[(include_index as u8) << 7 | (include_crc as u8) << 6 | ref_size as u8])?;

        dest.write_all(&[offset_size as u8])?; // off_bytes:(## 8) { off_bytes <= 8 }
        dest.write_all(&(self.cells_count as u64).to_be_bytes()[(8-ref_size)..8])?;
        dest.write_all(&(self.roots_count() as u64).to_be_bytes()[(8-ref_size)..8])?;
        dest.write_all(&0_u64.to_be_bytes()[(8-ref_size)..8])?;
        dest.write_all(&(total_cells_size as u64).to_be_bytes()[(8-offset_size)..8])?;
        if self.big_cells_count > 0 {
            dest.write_all(&(self.big_cells_count as u64).to_be_bytes()[(8-ref_size)..8])?;
            dest.write_all(&(self.big_cells_size as u64).to_be_bytes()[(8-offset_size)..8])?;
        }

        // Root's indexes 
        for index in self.roots_indexes_rev.iter() {
            check_abort(self.abort)?;
            dest.write_all(&((self.cells_count - *index - 1) as u64).to_be_bytes()[(8-ref_size)..8])?;
        }

        // Index
        if include_index { 
            let mut total_size = 0;
            for cell_index in (0..self.cells_count).rev() {
                check_abort(self.abort)?;
                let cell = &self.cells.get_cell_by_index(cell_index as u32)?;
                total_size += full_len(cell.raw_data()?) + ref_size * cell.references_count();
                dest.write_all(&(total_size as u64).to_be_bytes()[(8-offset_size)..8])?;
            }
        }

        // Cells
        for cell_rev_index in (0..self.cells_count).rev() {
            check_abort(self.abort)?;
            let cell = &self.cells.get_cell_by_index(cell_rev_index as u32)?;
            dest.write_all(cell.raw_data()?)?;
            let cell_index = self.cells_count - 1 - cell_rev_index;
            for i in 0..cell.references_count() {
                let child_hash = cell.reference_repr_hash(i).unwrap();
                let child_index = self.cells_count - 1 - 
                    self.cells.get_rev_index_by_hash(&child_hash)? as usize;
                debug_assert!(child_index > cell_index);
                dest.write_all(&(child_index as u64).to_be_bytes()[(8-ref_size)..8])?;
            }
        }

        self.cells.cleanup()
    }

    fn traverse(&mut self, root: Cell) -> Status {
        enum Phase {
            Pre(Cell),
            Post(Cell)
        }
        let mut stack = vec!(Phase::Pre(root));
        while let Some(phase) = stack.pop() {
            check_abort(self.abort)?;
            match phase {
                Phase::Pre(cell) => {
                    if cell.virtualization() != 0 {
                        fail!("Virtual cells serialization is prohibited");
                    }
                    // self.cells may change at some point between pushing pre-phase
                    // and popping it off the stack, so repeat the check
                    if self.cells.contains_hash(&cell.repr_hash())? {
                        continue;
                    }
                    stack.push(Phase::Post(cell.clone()));
                    self.update_counters(&cell)?;
                    let mut children: SmallVec<[Cell; MAX_REFERENCES_COUNT]> = SmallVec::new();
                    let mut children_hashes: SmallVec<[UInt256; MAX_REFERENCES_COUNT]> = SmallVec::new();
                    for i in 0..cell.references_count() {
                        let child_hash = cell.reference_repr_hash(i)?;
                        if !children_hashes.contains(&child_hash) && !self.cells.contains_hash(&child_hash)? {
                            children.push(cell.reference(i)?);
                            children_hashes.push(child_hash);
                        }
                    }
                    self.cells.store_cell(cell)?;
                    for (i, child) in children.into_iter().enumerate().rev() {
                        if !self.cells.contains_hash(&children_hashes[i])? {
                            stack.push(Phase::Pre(child));
                        }
                    }
                }
                Phase::Post(cell) => {
                    self.cells.push_cell(&cell.repr_hash())?;
                }
            }
        }
        Ok(())
    }

    fn update_counters(&mut self, cell: &Cell) -> Result<()> {
        self.cells_count += 1;
        let cell_size = cell.raw_data()?.len();
        self.data_size += cell_size;
        self.references += cell.references_count();
        if cell.cell_type() == CellType::Big {
            self.big_cells_count += 1;
            self.big_cells_size += cell_size;
        }
        Ok(())
    }

    fn number_of_bytes_to_fit(l: usize) -> usize {
        let mut n = 0;
        let mut l1 = l;
        
        while l1 != 0 {
            l1 >>= 8;
            n += 1;
        }

        n
    }
}

fn check_abort(abort: &dyn Fn() -> bool) -> Result<()> {
    if abort() {
        fail!("Operation was aborted");
    }
    Ok(())
}

#[derive(Clone)]
pub struct RawCell {
    pub data: Vec<u8>,
    pub refs: [u32; 4],
}

#[derive(Debug)]
pub struct BocHeader {
    pub magic: u32,
    pub roots_count: usize,
    pub ref_size: usize,
    pub index_included: bool,
    pub cells_count: usize,
    pub offset_size: usize,
    pub has_crc: bool,
    pub has_cache_bits: bool,
    pub roots_indexes: Vec<u32>,
    pub tot_cells_size: usize,
    pub big_cells_count: usize,
    pub big_cells_size: usize,
}

pub struct BocReaderResult {
    pub roots: Vec<Cell>,
    pub header: BocHeader,
}

impl BocReaderResult {
    pub fn withdraw_single_root(mut self) -> Result<Cell> {
        match self.roots.len() {
            0 => fail!("Error parsing cells tree: empty root"),
            1 => Ok(self.roots.remove(0)),
            r => fail!("Error parsing cells tree: too many roots {}", r)
        }
    }
}

pub trait IndexedCellsStorage {
    fn insert(&mut self, index: u32, cell: RawCell) -> Result<()>;
    fn remove(&mut self, index: u32) -> Result<RawCell>;
    fn cleanup(&mut self) -> Result<()>;
}

pub trait DoneCellsStorage {
    fn insert(&mut self, index: u32, cell: Cell) -> Result<()>;
    fn get(&self, index: u32) -> Result<Cell>;
    fn cleanup(&mut self) -> Result<()>;
}

impl IndexedCellsStorage for HashMap<u32, RawCell> {
    fn insert(&mut self, index: u32, cell: RawCell) -> Result<()> {
        self.insert(index, cell);
        Ok(())
    }
    fn remove(&mut self, index: u32) -> Result<RawCell> {
        self.remove(&index).ok_or_else(|| error!("Cell #{} was not found", index))
    }
    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

impl DoneCellsStorage for HashMap<u32, Cell> {
    fn insert(&mut self, index: u32, cell: Cell) -> Result<()> {
        self.insert(index, cell);
        Ok(())
    }
    fn get(&self, index: u32) -> Result<Cell> {
        Ok(self.get(&index).ok_or_else(|| error!("Cell #{} was not found", index))?.clone())
    }
    fn cleanup(&mut self) -> Result<()> {
        Ok(())
    }
}

pub struct BocReader<'a> {
    abort: &'a dyn Fn() -> bool,
    indexed_cells: Box<dyn IndexedCellsStorage>,
    done_cells: Box<dyn DoneCellsStorage>,
    max_depth: u16,
}

impl<'a> Default for BocReader<'a> {
    fn default() -> Self {
        Self {
            abort: &|| false,
            indexed_cells: Box::<HashMap::<u32, RawCell>>::default(),
            done_cells: Box::<HashMap::<u32, Cell>>::default(),
            max_depth: MAX_SAFE_DEPTH,
        }
    }
}

pub fn read_boc(data: impl AsRef<[u8]>) -> Result<BocReaderResult> {
    let mut cursor = Cursor::new(data);
    BocReader::new().read(&mut cursor)
}

pub fn read_single_root_boc(data: impl AsRef<[u8]>) -> Result<Cell> {
    read_boc(data)?.withdraw_single_root()
}

impl<'a> BocReader<'a> {
    pub fn new() -> Self { Self::default() }

    pub fn set_indexed_cells_storage(mut self, ics: Box<dyn IndexedCellsStorage>) -> Self {
        self.indexed_cells = ics;
        self
    }

    pub fn set_done_cells_storage(mut self, dcs: Box<dyn DoneCellsStorage>) -> Self {
        self.done_cells = dcs;
        self
    }

    pub fn set_abort(mut self, abort: &'a dyn Fn() -> bool) -> Self {
        self.abort = abort;
        self
    }

    pub fn set_max_cell_depth(mut self, max_depth: u16) -> Self {
        self.max_depth = max_depth;
        self
    }

    pub fn read<T: Read + Seek>(mut self, src: &mut T) -> Result<BocReaderResult> {
        #[cfg(not(target_family = "wasm"))]
        let now = std::time::Instant::now();

        let position = src.stream_position()?;
        let src_full_len = src.seek(SeekFrom::End(0))? - position;
        src.seek(SeekFrom::Start(position))?;

        // TODO do not compute crc if header says crc isn't included
        let mut src = IoCrcFilter::new_reader(src);

        let header = Self::read_header(&mut src)?;
        let header_len = src.stream_position()? - position;

        check_abort(self.abort)?;

        Self::precheck_cells_tree_len(&header, header_len, src_full_len, true)?;

        // Skip index
        if header.index_included {
            let mut raw_index = vec![0; header.cells_count * header.offset_size];
            src.read_exact(&mut raw_index)?;
        }

        // Read cells
        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        let mut actual_data_size = src.stream_position()?;
        let mut remaining_big_cells = header.big_cells_count;
        for cell_index in 0..header.cells_count {
            check_abort(self.abort)?;
            let raw_cell = Self::read_raw_cell(
                &mut src, header.ref_size, cell_index, header.cells_count, &mut remaining_big_cells)?;
            self.indexed_cells.insert(cell_index as u32, raw_cell)?;
        }
        actual_data_size = src.stream_position()? - actual_data_size;
        if actual_data_size as usize != header.tot_cells_size {
            fail!("actual data size disagrees with the size from header")
        }
        #[cfg(not(target_family = "wasm"))]
        let read_time = now1.elapsed().as_millis();

        // Resolving references & constructing cells from leaves to roots
        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        for cell_index in (0..header.cells_count).rev() {
            check_abort(self.abort)?;
            let raw_cell = self.indexed_cells.remove(cell_index as u32)?;
            let mut refs = vec!();
            for i in 0..cell::refs_count(&raw_cell.data) {
                refs.push(self.done_cells.get(raw_cell.refs[i])?)
            }
            let cell = DataCell::with_raw_data(refs, raw_cell.data, Some(self.max_depth))?;
            self.done_cells.insert(cell_index as u32, Cell::with_cell_impl(cell))?;
        }
        #[cfg(not(target_family = "wasm"))]
        let constructing_time = now1.elapsed().as_millis();

        let roots_indexes = if header.magic == BOC_GENERIC_TAG {
            &header.roots_indexes[..] 
        } else {
            &[0]
        };
        let mut roots = Vec::with_capacity(roots_indexes.len());
        for i in roots_indexes {
            check_abort(self.abort)?;
            roots.push(self.done_cells.get(*i)?);
        }

        if header.has_crc {
            src.check_crc()?;
        }

        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        self.done_cells.cleanup()?;
        #[cfg(not(target_family = "wasm"))]
        let drop_time_dc = now1.elapsed().as_millis();
    
        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        self.indexed_cells.cleanup()?;
        #[cfg(not(target_family = "wasm"))]
        let drop_time_ic = now1.elapsed().as_millis();

        #[cfg(not(target_family = "wasm"))] {
            let total_time = now.elapsed().as_millis();
            log::trace!(
                "TIME read_cells_tree_ex: {}ms (read: {}, creating cells: {}, \
                    indexed cells cleanup: {}, done cells cleanup: {})",
                total_time, read_time, constructing_time, drop_time_ic, drop_time_dc
            );
        }

        Ok(BocReaderResult { roots, header })
    }

    pub fn read_inmem(mut self, data: Arc<Vec<u8>>) -> Result<BocReaderResult> {
        #[cfg(not(target_family = "wasm"))]
        let now = std::time::Instant::now();
        let mut src = Cursor::new(data.deref());
    
        let header = Self::read_header(&mut src)?;
    
        Self::precheck_cells_tree_len(&header, src.position(), data.len() as u64, false)?;
    
        // Index processing - read existing index or traverse all vector to create own index2
        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        let mut index2 = vec!();
        let index = &data[src.position() as usize..];
        if !header.index_included {
            index2 = Vec::with_capacity(header.cells_count);
            for _ in 0_usize..header.cells_count {
                check_abort(self.abort)?;
                index2.push(src.position());
                Self::skip_cell(&mut src, header.ref_size)?;
            }
        } else if index.len() < header.cells_count * header.offset_size {
            fail!("Invalid data: too small to fit index");
        }
        #[cfg(not(target_family = "wasm"))]
        let index_time = now1.elapsed().as_millis();
    
        // Resolving references & constructing cells from leaves to roots
        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        let cells_start = src.position() as usize + header.cells_count * header.offset_size;
        let mut remaining_big_cells = header.big_cells_count;
        for cell_index in (0..header.cells_count).rev() {
            check_abort(self.abort)?;

            let offset = if header.index_included {
                let mut offset = cells_start;
                if cell_index > 0 {
                    let o = (cell_index - 1) * header.offset_size;
                    let mut o2 = Cursor::new(&index[o..o + header.offset_size])
                        .read_be_uint(header.offset_size)? as usize;
                    if header.has_cache_bits {
                        o2 >>= 1;
                    } 
                    offset += o2;
                }
                offset
            } else {
                index2[cell_index] as usize
            };
    
            if data.len() <= offset {
                fail!("Invalid data: data too short or index is invalid");
            }
            let mut src = Cursor::new(&data[offset..]);
            let refs_indexes = Self::read_refs_indexes(&mut src, header.ref_size, cell_index, header.cells_count)?;
            let mut refs = Vec::with_capacity(refs_indexes.len());
            for ref_cell_index in refs_indexes {
                let child = self.done_cells.get(ref_cell_index)?;
                refs.push(child.clone());
            }
    
            let cell = DataCell::with_external_data(refs, &data, offset, Some(self.max_depth))?;
            if cell.cell_type() == CellType::Big {
                if remaining_big_cells == 0 {
                    fail!("Big cell is not allowed");
                }
                remaining_big_cells -= 1;
            }
            self.done_cells.insert(cell_index as u32, Cell::with_cell_impl(cell))?;
        }
        #[cfg(not(target_family = "wasm"))]
        let constructing_time = now1.elapsed().as_millis();
    
        let mut roots = Vec::with_capacity(header.roots_count);
        if header.magic == BOC_GENERIC_TAG {
            for i in &header.roots_indexes {
                check_abort(self.abort)?;
                roots.push(self.done_cells.get(*i)?.clone());
            }
        } else {
            roots.push(self.done_cells.get(0)?);
        }
    
        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        if header.has_crc {
            let mut hasher = CASTAGNOLI.digest();
            hasher.update(&data[..data.len() - 4]);
            let crc = hasher.finalize();
            src.set_position(data.len() as u64 - 4);
            let read_crc = src.read_le_u32()?;
            if read_crc != crc {
                fail!("crc not the same, values: {}, {}", read_crc, crc)
            }
        }
        #[cfg(not(target_family = "wasm"))]
        let crc_time = now1.elapsed().as_millis();

        #[cfg(not(target_family = "wasm"))]
        let now1 = std::time::Instant::now();
        self.done_cells.cleanup()?;
        #[cfg(not(target_family = "wasm"))]
        let cleanup_time = now1.elapsed().as_millis();
        #[cfg(not(target_family = "wasm"))] {
            let total_time = now.elapsed().as_millis();
            log::trace!(
                "TIME read_inmem: {}ms (index: {}, creating cells: {}, crc: {}, cleanup: {})",
                total_time, index_time, constructing_time, crc_time, cleanup_time
            );
        }
    
        Ok(BocReaderResult { 
            roots, 
            header, 
        })
    }

    fn read_header<T>(src: &mut T) -> Result<BocHeader> where T: Read {
        let magic = src.read_be_u32()?;
        let first_byte = src.read_byte()?;
        let index_included;
        let mut has_crc = false;
        let ref_size;
        let mut has_big_cells = false;
        let mut has_cache_bits = false;

        match magic {
            BOC_INDEXED_TAG => {
                ref_size = first_byte as usize;
                index_included = true;
            },
            BOC_INDEXED_CRC32_TAG => {
                ref_size = first_byte as usize;
                index_included = true;
                has_crc = true;
            },
            BOC_GENERIC_TAG | BOC_GENERIC_V2_TAG => {
                index_included = first_byte & 0b1000_0000 != 0;
                has_crc = first_byte & 0b0100_0000 != 0;
                has_cache_bits = first_byte & 0b0010_0000 != 0;
                let flags = (first_byte & 0b0001_1000) >> 3;
                if flags != 0 {
                    fail!("non-zero flags field is not supported")
                }
                ref_size = (first_byte & 0b0000_0111) as usize;
                has_big_cells = magic == BOC_GENERIC_V2_TAG;
            },
            _ => fail!("unknown BOC_TAG: {}", magic)
        };

        if has_cache_bits && !index_included {
            fail!("invalid header")
        }

        if ref_size == 0 || ref_size > 4 {
            fail!("ref size has to be more than 0 and less or equal 4, actual value: {}", ref_size)
        }

        let offset_size = src.read_byte()? as usize;
        if offset_size == 0 || offset_size > 8 {
            fail!("offset size has to be less or equal 8, actual value: {}", offset_size)
        }

        let cells_count = src.read_be_uint(ref_size)? as usize; // cells:(##(size * 8))
        let roots_count = src.read_be_uint(ref_size)? as usize; // roots:(##(size * 8))
        let absent_count = src.read_be_uint(ref_size)? as usize; // absent:(##(size * 8)) { roots + absent <= cells }

        if cells_count == 0 {
            fail!("cell count is zero")
        }
        if roots_count == 0 {
            fail!("root cell count is zero")
        }
        if roots_count > MAX_ROOTS_COUNT {
            fail!("too many roots")
        }
        if (magic == BOC_INDEXED_TAG || magic == BOC_INDEXED_CRC32_TAG) && roots_count > 1 {
            fail!("roots count has to be less or equal 1 for TAG: {}, value: {}", magic, offset_size)
        }
        if roots_count + absent_count > cells_count {
            fail!("roots count + absent count has to be less or equal than cells count, roots: {}, \
                absent: {}, cells: {}", roots_count, absent_count, cells_count);
        }
        if absent_count != 0 {
            fail!("absent cells are not supported")
        }

        let tot_cells_size = src.read_be_uint(offset_size)? as usize; // tot_cells_size:(##(off_bytes * 8))
        
        let (big_cells_count, big_cells_size) = if has_big_cells {
            let big_cells_count = src.read_be_uint(ref_size)? as usize;
            let big_cells_size = src.read_be_uint(offset_size)? as usize;

            if big_cells_count > cells_count {
                fail!("big_cells_count ({}) is too big with respect to cells_count ({})", 
                    big_cells_count, cells_count);
            }
            if big_cells_size > tot_cells_size {
                fail!("big_cells_size ({}) is too big with respect to tot_cells_size ({})", 
                    big_cells_size, tot_cells_size);
            }
            let max_big_cell_size = MAX_BIG_DATA_BYTES + 4; // d1 and 3 bytes length
            if big_cells_size > big_cells_count * max_big_cell_size {
                fail!("big_cells_size ({}) is too big with respect to big_cells_count ({})", 
                    big_cells_size, big_cells_count);
            }
            let min_big_cell_size = 4; // d1 and 3 bytes length only
            if big_cells_size < big_cells_count * min_big_cell_size {
                fail!("big_cells_size ({}) is too small with respect to big_cells_count ({})", 
                    big_cells_size, big_cells_count);
            }
            (big_cells_count, big_cells_size)
        } else {
            (0, 0)
        };
        let max_cell_size = 
            2 + // descr bytes
            4 * (DEPTH_SIZE + SHA256_SIZE) + // stored hashe & depths
            MAX_DATA_BYTES +
            MAX_REFERENCES_COUNT * ref_size;
        let min_cell_size = 2; // descr bytes only
        // every raw cell except roots must be referenced at least once, hence the formula
        let tot_cells_size_minimal = (cells_count - big_cells_count) * (min_cell_size + ref_size)
            - ref_size * roots_count;
        if tot_cells_size - big_cells_size < tot_cells_size_minimal {
            fail!("tot_cells_size is too small with respect to cells_count");
        }
        if tot_cells_size - big_cells_size > max_cell_size * (cells_count - big_cells_count) {
            fail!("tot_cells_size is too big with respect to cells_count");
        }

        let roots_indexes = if magic == BOC_GENERIC_TAG || magic == BOC_GENERIC_V2_TAG {
            // root_list:(roots * ##(size * 8)) 
            let mut roots_indexes = Vec::with_capacity(roots_count);
            for _ in 0..roots_count {
                let index = src.read_be_uint(ref_size)? as u32;
                if index as usize >= cells_count {
                    fail!("Invalid root index {} (greater than cells count {})", index, cells_count);
                }
                roots_indexes.push(index); // cells:(##(size * 8))
            }
            roots_indexes
        } else {
            Vec::with_capacity(0)
        };

        Ok(BocHeader {
            magic,
            roots_count,
            ref_size,
            index_included,
            cells_count,
            offset_size,
            has_crc,
            has_cache_bits,
            roots_indexes,
            tot_cells_size,
            big_cells_count,
            big_cells_size,
        })
    }

    fn precheck_cells_tree_len(header: &BocHeader, header_len: u64, actual_len: u64, unbounded: bool) -> Result<()> {
        // calculate boc len
        let index_size = header.index_included as u64 * ((header.cells_count * header.offset_size) as u64);
        let len = header_len + index_size + header.tot_cells_size as u64 + header.has_crc as u64 * 4;
        if unbounded {
            if actual_len < len {
                fail!("Actual boc length {} is smaller than calculated one {}", actual_len, len);
            }
        } else if actual_len != len {
            fail!("Actual boc length {} in not equal calculated one {}", actual_len, len);
        }
        Ok(())
    }

    fn read_raw_cell<T>(
        src: &mut T,
        ref_size: usize,
        cell_index: usize,
        cells_count: usize,
        remaining_big_cells: &mut usize,
    ) -> Result<RawCell> where T: Read {
        let mut refs = [0; 4];
        let mut data;
        let mut d1d2 = [0_u8; 2];
        src.read_exact(&mut d1d2[0..1])?;
        if cell::is_big_cell(&d1d2[0..1]) {
            if *remaining_big_cells == 0 {
                fail!("big cell is not allowed");
            }
            *remaining_big_cells -= 1;
            let len = src.read_be_uint(3)? as usize;
            if len > MAX_BIG_DATA_BYTES {
                fail!("big cell data length {} is too big", len);
            }
            data = vec!(0; 1 + 3 + len);
            data[0] = d1d2[0];
            data[1] = (len >> 16) as u8;
            data[2] = (len >> 8) as u8;
            data[3] = len as u8;
            src.read_exact(&mut data[4..])?;
            return Ok(RawCell{data, refs});
        }

        src.read_exact(&mut d1d2[1..2])?;
        let refs_count = cell::refs_count(&d1d2);
        if refs_count > MAX_REFERENCES_COUNT {
            fail!("refs_count can't be {}", refs_count);
        }

        let data_len = cell::full_len(&d1d2);
        data = vec!(0; data_len);
        data[..2].copy_from_slice(&d1d2);
        src.read_exact(&mut data[2..])?;
        let tag_completed = d1d2[1] & 1 != 0;
        if tag_completed && data_len > 2 && (data[data_len - 1] & 0x7f == 0) {
            fail!("overly long tag-completed encoding")
        }

        for reference in refs.iter_mut().take(refs_count) {
            let r = src.read_be_uint(ref_size)? as u32;
            if r > cells_count as u32 || r <= cell_index as u32 {
                fail!("reference out of range, cells_count: {}, ref: {}, cell_index: {}", cells_count, r, cell_index)
            } else {
                *reference = r;
            }
        }
        Ok(RawCell{data, refs})
    }

    fn read_refs_indexes<T>(
        src: &mut T,
        ref_size: usize,
        cell_index: usize,
        cells_count: usize,
    ) -> Result<SmallVec<[u32; 4]>> where T: Read + Seek {

        let mut d1d2 = [0_u8; 2];
        src.read_exact(&mut d1d2[0..1])?;

        if cell::is_big_cell(&d1d2) {
            let len = src.read_be_uint(3)? as usize;
            if len > MAX_BIG_DATA_BYTES {
                fail!("big cell data length {} is too big", len);
            }
            src.seek(SeekFrom::Current(len as i64))?;
            Ok(SmallVec::new())
        } else {
            src.read_exact(&mut d1d2[1..2])?;

            let to_skip = cell::full_len(&d1d2) - 2;
            src.seek(SeekFrom::Current(to_skip as i64))?;

            let refs_count = cell::refs_count(&d1d2);
            let mut references: SmallVec<[u32; 4]> = SmallVec::with_capacity(refs_count);
            for _ in 0..refs_count {
                let i = src.read_be_uint(ref_size)? as usize;
                if i > cells_count || i <= cell_index {
                    fail!("reference out of range, cells_count: {}, ref: {}, cell_index: {}", cells_count, i, cell_index)
                } else {
                    references.push(i as u32);
                }
            }

            Ok(references)
        }
    }

    fn skip_cell<T>(src: &mut T, ref_size: usize) -> Result<()> where T: Read + Seek {
        let mut d1d2 = [0_u8; 2];
        src.read_exact(&mut d1d2[0..1])?;
        let rest_size = if cell::is_big_cell(&d1d2) {
            let len = src.read_be_uint(3)? as usize;
            if len > MAX_BIG_DATA_BYTES {
                fail!("big cell data length {} is too big", len);
            }
            len
        } else {
            src.read_exact(&mut d1d2[1..2])?;
            cell::full_len(&d1d2) + ref_size * cell::refs_count(&d1d2) - 2
        };
        src.seek(SeekFrom::Current(rest_size as i64))?;
        Ok(())
    }
}

/// Wraps I/O operations and computes CRC32-C of the data being processed
struct IoCrcFilter<'a, T> {
    io_object: &'a mut T,
    hasher: Digest<'a, u32>
}

impl<'a, T: Write> IoCrcFilter<'a, T> {
    pub fn new_writer(io_object: &'a mut T) -> Self {
        IoCrcFilter{ 
            io_object,
            hasher: CASTAGNOLI.digest()
        }
    }

    pub fn finalize(self) -> Result<()> {
        let crc = self.hasher.finalize();
        self.io_object.write_all(&crc.to_le_bytes())?;
        Ok(())
    }

}

impl<'a, T: Read> IoCrcFilter<'a, T> {
    pub fn new_reader(io_object: &'a mut T) -> Self {
        IoCrcFilter{ 
            io_object,
            hasher: CASTAGNOLI.digest()
        }
    }

    pub fn check_crc(self) -> Result<()> {
        let read_crc = self.io_object.read_le_u32()?;
        let crc = self.hasher.finalize();
        if read_crc != crc {
            fail!("crc not the same, values: {}, {}", read_crc, crc)
        }
        Ok(())
    }
}

impl<'a, T> IoCrcFilter<'a, T> where T: Seek {
    fn stream_position(&mut self) -> Result<u64> {
        let p = self.io_object.stream_position()?;
        Ok(p)
    }
}

impl<'a, T> Write for IoCrcFilter<'a, T> where T: Write {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.hasher.update(buf);
        self.io_object.write(buf)
    }

    fn flush(&mut self) -> std::io::Result<()> {
        self.io_object.flush()
    }
}

impl<'a, T> Read for IoCrcFilter<'a, T> where T: Read {
    fn read(&mut self, buf: &mut [u8]) -> std::io::Result<usize> {
        let res = self.io_object.read(buf);
        self.hasher.update(buf);
        res
    }
}

