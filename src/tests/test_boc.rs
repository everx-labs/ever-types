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

use std::fs::read;
use std::io::Cursor;
use std::path::Path;
use rand::{thread_rng, Rng};
use crate::{BuilderData, IBitstring, create_big_cell, base64_decode, MAX_DEPTH, SliceData};

use super::*;

fn build_tree_with_params(mut depth: u16, max_depth: u16, cells_count: &mut u32) -> Result<Cell> {
    let mut b = BuilderData::new();
    b.append_u32(rand::random::<u32>())?;
    b.append_u32(rand::random::<u32>())?;
    b.append_u32(rand::random::<u32>())?;
    b.append_u32(rand::random::<u32>())?;
    depth += 1;
    if depth < max_depth {
        b.checked_append_reference(build_tree_with_params(depth, max_depth, cells_count)?)?;
        b.checked_append_reference(build_tree_with_params(depth, max_depth, cells_count)?)?;
        b.checked_append_reference(build_tree_with_params(depth, max_depth, cells_count)?)?;
        b.checked_append_reference(build_tree_with_params(depth, max_depth, cells_count)?)?;
    }
    *cells_count += 1;
    b.into_cell()
}

/*
                                root0
        c1				c7				c12			c15
    c2	c4	c5		c8		c9			c13
    c3		c6				c10			c14
                            c11
*/

fn build_tree() -> Cell {
    let mut root = BuilderData::new();
    let mut c1 = BuilderData::new();
    let mut c2 = BuilderData::new();
    let mut c3 = BuilderData::new();
    let mut c4 = BuilderData::new();
    let mut c5 = BuilderData::new();
    let mut c6 = BuilderData::new();
    let mut c7 = BuilderData::new();
    let mut c8 = BuilderData::new();
    let mut c9 = BuilderData::new();
    let mut c10 = BuilderData::new();
    let mut c11 = BuilderData::new();
    let mut c12 = BuilderData::new();
    let mut c13 = BuilderData::new();
    let mut c14 = BuilderData::new();
    let mut c15 = BuilderData::new();

    root.append_u8(0).unwrap();
    c1.append_u8(1).unwrap();
    c2.append_u8(2).unwrap();
    c3.append_u8(3).unwrap();
    c4.append_u8(4).unwrap();
    c5.append_u8(5).unwrap();
    c6.append_u8(6).unwrap();
    c7.append_u8(7).unwrap();
    c8.append_u8(8).unwrap();
    c9.append_u8(9).unwrap();
    c10.append_u8(10).unwrap();
    c11.append_u8(11).unwrap();
    c12.append_u8(12).unwrap();
    c13.append_u8(13).unwrap();
    c14.append_u8(14).unwrap();
    c15.append_u8(15).unwrap();

    c13.append_reference(c14);
    c12.append_reference(c13);
    c10.append_reference(c11);
    c9.append_reference(c10);	
    c7.append_reference(c8);
    c7.append_reference(c9);
    c5.append_reference(c6);
    c2.append_reference(c3);
    c1.append_reference(c2);
    c1.append_reference(c4);
    c1.append_reference(c5);
    root.append_reference(c1);
    root.append_reference(c7);
    root.append_reference(c12);
    root.append_reference(c15);

    root.into_cell().unwrap()
}

fn build_tree_with_big(val: u8) -> Cell {
    let mut root = BuilderData::new();
    let mut c1 = BuilderData::new();
    let mut c2 = BuilderData::new();
    let mut c3 = BuilderData::new();
    let mut c4 = BuilderData::new();

    root.append_u8(val).unwrap();
    c1.append_u8(val + 1).unwrap();
    c2.append_u8(val + 2).unwrap();
    c3.append_u8(val + 3).unwrap();
    c4.append_u8(val + 4).unwrap();


    let mut data = vec![0; 1024 * 1024];
    thread_rng().try_fill(&mut data[..]).unwrap();
    let c5 = create_big_cell(&data).unwrap();

    c1.append_reference(c2);
    c1.append_reference(c3);
    root.append_reference(c1);
    root.append_reference(c4);
    root.checked_append_reference(c5).unwrap();
    
    root.into_cell().unwrap()
}

/*
                root0
        c1				c4	
    c2		c3							

*/
fn build_tree2(val: u8) -> Cell {
    let mut root = BuilderData::new();
    let mut c1 = BuilderData::new();
    let mut c2 = BuilderData::new();
    let mut c3 = BuilderData::new();
    let mut c4 = BuilderData::new();	

    root.append_u8(val).unwrap();
    c1.append_u8(val + 1).unwrap();
    c2.append_u8(val + 2).unwrap();
    c3.append_u8(val + 3).unwrap();
    c4.append_u8(val + 4).unwrap();
    
    c1.append_reference(c2);
    c1.append_reference(c3);
    root.append_reference(c1);
    root.append_reference(c4);

    root.into_cell().unwrap()
}

/*
                root0
        c1				c4	
    c2		c3							

*/
fn build_tree3(val: u32) -> Cell {

    let mut root = BuilderData::new();
    let mut c1 = BuilderData::new();
    let mut c2 = BuilderData::new();
    let mut c3 = BuilderData::new();
    let mut c4 = BuilderData::new();	

    root.append_u32(val).unwrap();
    c1.append_u32(val + 1).unwrap();
    c2.append_u32(val + 2).unwrap();
    c3.append_u32(val + 3).unwrap();
    c4.append_u32(val + 4).unwrap();
    
    c1.append_reference(c2);
    c1.append_reference(c3);
    root.append_reference(c1);
    root.append_reference(c4);

    root.into_cell().unwrap()
}

#[test]
fn test_many_bocs_in_one_file() -> Result<()> {
    let mut data = Vec::new();
    let mut roots = vec!();

    for i in 0..10 {
        let root = build_tree3(i);
        BocWriter::with_root(&root)?.write(&mut data)?;
        roots.push(root);
    }

    let mut cursor = Cursor::new(&data);
    for root in roots {
        let roots_restored = BocReader::new().read(&mut cursor)?.roots;
        assert_eq!(root, roots_restored[0]);
    }
    Ok(())
}

#[test]
fn test_tree_of_cells_serialization_deserialization() -> Result<()> {
    std::env::set_var("RUST_BACKTRACE", "full");
    
    println!("one root");
    for include_index in &[true, false] {
        for include_crc in &[true, false] {
            println!("include_index: {}, include_crc: {}", include_index, include_crc);
            
            let root = build_tree();
                            
            let mut data = Vec::new();
            BocWriter::with_root(&root)?.write_ex(
                &mut data,
                *include_index,
                *include_crc,
                None,
                None
            )?;
            
            let roots_restored = BocReader::new().read(&mut Cursor::new(&data))?.roots;
            assert_eq!(root, roots_restored[0].clone());

            let roots_restored_2 = BocReader::new().read_inmem(Arc::new(data))?.roots;
            assert_eq!(root, roots_restored_2[0].clone());
        }
    }

    println!("many roots");
    for include_index in &[true, false] {
        println!("include_index: {}", include_index);
        
        let root0 = build_tree();
        let root1 = build_tree2(111);
        let root2 = build_tree2(222);
        
        let mut data = Vec::new();
        BocWriter::with_roots([root0.clone(), root1.clone(), root2.clone()])?
            .write_ex(&mut data, *include_index, false, None, None)?;
        let roots_restored = BocReader::new().read(&mut Cursor::new(&data))?.roots;

        assert_eq!(root0, roots_restored[0].clone());
        assert_eq!(root1, roots_restored[1].clone());
        assert_eq!(root2, roots_restored[2].clone());

        assert_ne!(root0, roots_restored[2].clone());
        assert_ne!(root1, roots_restored[0].clone());
        assert_ne!(root2, roots_restored[1].clone());

        let roots_restored_2 = BocReader::new().read_inmem(Arc::new(data))?.roots;

        assert_eq!(root0, roots_restored_2[0].clone());
        assert_eq!(root1, roots_restored_2[1].clone());
        assert_eq!(root2, roots_restored_2[2].clone());

    }

    println!("so many roots");
    for include_index in &[true, false] {
        println!("include_index: {}", include_index);
        
        let len = 1024u32;
        let mut roots = vec!();
        for i in 0..len {
            roots.push(build_tree3(i * 100));
        }
        
        let mut data = Vec::new();
        BocWriter::with_roots(roots.clone())?.write_ex(&mut data, *include_index, true, None, None)?;

        let roots_restored = BocReader::new().read(&mut Cursor::new(&data))?.roots;
        for i in 0..len {
            assert_eq!(&roots[i as usize], &roots_restored[i as usize]);
        }

        let roots_restored_2 = BocReader::new().read_inmem(Arc::new(data))?.roots;
        for i in 0..len {
            assert_eq!(&roots[i as usize], &roots_restored_2[i as usize]);
        }
    }

    println!("big cell");
    for include_index in &[true, false] {
        
        println!("include_index: {}", include_index);
        let root = build_tree_with_big(1);
        
        let mut data = Vec::new();
        BocWriter::with_root(&root)?.write_ex(&mut data, *include_index, true, None, None)?;

        let root_restored = BocReader::new()
            .set_allow_big_cells(true)
            .read(&mut Cursor::new(&data))?.withdraw_single_root()?;
        assert_eq!(root, root_restored);

        let root_restored = BocReader::new()
            .set_allow_big_cells(true)
            .read_inmem(Arc::new(data))?.withdraw_single_root()?;
        assert_eq!(root, root_restored);
    }

    Ok(())
}

/*
    root0    root1
     c2       c1
     c1       c0
     c0
 */
#[test]
fn test_roots_share_same_tree() -> Result<()> {
    let cell0 = Cell::default();
    let cell1 = BuilderData::with_raw_and_refs(vec!(), 0, vec!(cell0))?.into_cell()?;
    let cell2 = BuilderData::with_raw_and_refs(vec!(), 0, vec!(cell1.clone()))?.into_cell()?;
    let roots = vec!(
        cell2,
        cell1,
    );
    let mut output = vec!();
    let boc = BocWriter::with_roots(roots.clone())?;
    boc.write(&mut output)?;
    let res = BocReader::new().read(&mut Cursor::new(&output))?;
    assert_eq!(roots, res.roots);
    Ok(())
}

// non-unique roots are banned
#[ignore]
#[test]
fn test_bug_serialization() -> Result<()> {
    let node0 = Cell::default();
    let node1 = BuilderData::with_raw(vec!(0xff), 8)?.into_cell()?;
    let roots = vec!(
        node0.clone(),
        node1,
        node0,
    );
    let mut output = vec!();
    let boc = BocWriter::with_roots(roots.clone())?;
    boc.write(&mut output)?;
    let res = BocReader::new().read(&mut Cursor::new(&output))?;
    assert_eq!(roots, res.roots);
    Ok(())
}

#[test]
fn test_number_of_bytes_to_fit() {
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(255), 1);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(256), 2);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(200), 1);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(400), 2);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(333), 2);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(2000), 2);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(16000), 2);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(160000), 3);
    assert_eq!(BocWriter::<SimpleOrderedCellsStorage>::number_of_bytes_to_fit(1073741823), 4);
}

#[test]
fn test_crc_pure() {
    // Some part of crc module's test from real ton sorces
    assert_eq!(crc32_digest([0;32]), 0x8a9136aa);
    assert_eq!(crc32_digest([0xff;32]), 0x62a8ab43);
    let data = [
        0x01, 0xc0, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x00, 0x00, 0x04, 0x00,
        0x00, 0x00, 0x00, 0x14, 0x00, 0x00, 0x00, 0x18, 0x28, 0x00, 0x00, 0x00,
        0x00, 0x00, 0x00, 0x00, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
    ];
    assert_eq!(crc32_digest(data), 0xd9963a56);

    let mut digest = Crc32::new();
    digest.update(&data[..10]);
    digest.update(&data[10..]);
    assert_eq!(digest.finalize(), 0xd9963a56);
}

//#[ignore]
#[test]
fn test_crc_with_files() {
    let orig_bytes = read(
        Path::new(Path::new("src/tests/data/new-wallet-query.boc"))
    ).expect("Error reading file");
    
    let crc1 = crc32_digest(&orig_bytes[..orig_bytes.len() - 4]);
    let crc2 = u32::from_le_bytes(orig_bytes[orig_bytes.len() - 4..].try_into().expect("incorrect length"));

    println!("{:x}", crc1);
    println!("{:x}", crc2);

    assert_eq!(crc1, crc2);
}

#[test]
fn test_boc_write_crc() -> crate::Status {
    let mut bytes = Vec::new();
    BocWriter::with_params([Cell::default()], u16::MAX - 1, SimpleOrderedCellsStorage::default(), &|| false)?
        .write_ex(&mut bytes, false, true, None, None)?;

    let crc1 = crc32_digest(&bytes[..bytes.len() - 4]);
    let crc2 = u32::from_le_bytes(bytes[bytes.len() - 4..].try_into()?);
    assert_eq!(crc1, crc2);
    Ok(())
}

#[test]
fn test_real_ever_boc2() -> Result<()> {

    // Compatibility checking
    
    let input = "B5EE9C7241040301000000004600024789FF86EE2B1CE113242F7CAE3511009B84F9E460D38773688AF808406AA75537991A11900102002C20DDA4F260F8005F04ED44D0D31F30A4C8CB1FC9ED540008000000005A785C4E";
    let orig_bytes = hex::decode(input)?;
    let rr = read_boc(&orig_bytes)?;

    let boc = BocWriter::with_roots(rr.roots.clone())?;
    let mut bytes = Vec::with_capacity(orig_bytes.len());
    boc.write_ex(
        &mut bytes,
        rr.header.index_included,
        rr.header.has_crc,
        Some(rr.header.ref_size),
        Some(rr.header.offset_size)
    )?;
    BocReader::new().read(&mut Cursor::new(&bytes)).expect("Error deserialising BOC");
    assert_eq!(orig_bytes.len(), bytes.len());

    Ok(())
}

fn build_tree_with_depth(depth: u16) -> Cell {
    let mut c = None;
    for _ in 0..=depth {
        let mut b = BuilderData::new();
        if let Some(c) = c {
            b.checked_append_reference(c).unwrap();
        }
        c = Some(b.finalize(depth).unwrap())
    }
    c.unwrap()
}

// #[cfg(release)] TODO: test overflows stack in debug mode
#[test]
fn test_default_max_safe_depth() {
    let handler = std::thread::Builder::new().stack_size(4 * 1024 * 1024).spawn(|| {
        let c = build_tree_with_depth(2048);
        let b = write_boc(&c).unwrap();
        let c2 = BocReader::new()
            .read(&mut std::io::Cursor::new(&b)).unwrap()
            .withdraw_single_root().unwrap();
        assert_eq!(c, c2);
    }).unwrap();

    handler.join().unwrap();
}

// #[cfg(release)] TODO: test overflows stack in debug mode
#[test]
fn test_max_depth() {
    std::thread::Builder::new().stack_size(128 * 1024 * 1024).spawn(|| {
        let depth = u16::MAX - 1;
        let c = build_tree_with_depth(depth);
        let mut b = vec![];

        BocWriter::with_params([c.clone()], depth, SimpleOrderedCellsStorage::default(), &|| false).unwrap()
            .write(&mut b).unwrap();

        let c2 = BocReader::new()
            .set_max_cell_depth(depth)
            .read(&mut std::io::Cursor::new(&b)).unwrap()
            .withdraw_single_root().unwrap();
        assert_eq!(c, c2);

        let c3 = BocReader::new()
            .set_max_cell_depth(depth)
            .read_inmem(Arc::new(b)).unwrap()
            .withdraw_single_root().unwrap();
        assert_eq!(c, c3);

    }).unwrap().join().unwrap();
}

pub struct TestCellByHashStorage {
    cells: HashMap<UInt256, Cell>,
}

impl TestCellByHashStorage {
    pub fn new() -> Self {
        Self {
            cells: HashMap::new(),
        }
    }
    
    pub fn with_root(root_cell: Cell) -> Self {
        let mut storage = Self::new();
        storage.add_root(root_cell);        
        storage
    }

    fn add_root(&mut self, root_cell: Cell) {
        self.add_cell(root_cell.clone());
        for i in 0..root_cell.references_count() {
            let ref_cell = root_cell.reference(i).unwrap();
            self.add_root(ref_cell);
        }
    }

    pub fn add_cell(&mut self, cell: Cell) {
        self.cells.entry(cell.repr_hash()).or_insert(cell);
    }
}

impl CellByHashStorage for TestCellByHashStorage {
    fn get_cell_by_hash(&self, hash: &UInt256) -> Result<Cell> {
        self.cells.get(hash).cloned().ok_or_else(|| error!("Can't find cell with hash {:x}", hash))
    }
}

#[test]
fn test_boc_writer_stack() -> Result<()> {
    let mut cells_count = 0;
    let now = std::time::Instant::now();
    let root = build_tree_with_params(0, 10, &mut cells_count)?;
    let serialized_root = root.clone();
    let storage = TestCellByHashStorage::with_root(root.clone());
    let build_time = now.elapsed().as_millis();
 
    let now = std::time::Instant::now();
    let mut data = Vec::new();
    BocWriterStack::write(
        &mut data,
        Path::new("src/tests/data/"),
        root,
        MAX_DEPTH,
        storage,
        &|| false,
    )?;
    let serialize_time = now.elapsed().as_millis();

    println!("total cells {}", cells_count);
    println!("boc size {}", data.len());
    println!("build time {}ms  {}ms per cell", build_time, build_time as f64 / cells_count as f64);
    println!("serialize time {}ms  {}ms per cell", serialize_time, serialize_time as f64 /cells_count as f64);

    let now = std::time::Instant::now();
    let deserialized_root = BocReader::new().read_inmem(Arc::new(data))?.withdraw_single_root()?;
    let deserialize_time = now.elapsed().as_millis();
    println!("deserialize time {}ms  {}ms per cell", deserialize_time, deserialize_time  as f64 /cells_count as f64);

    assert_eq!(serialized_root, deserialized_root);

    Ok(())
}

#[test]
fn test_full_tree() -> Result<()> {
    let mut cells_count = 0;
    let now = std::time::Instant::now();
    let c = build_tree_with_params(0, 10, &mut cells_count)?;
    let build_time = now.elapsed().as_millis();

    let now = std::time::Instant::now();
    let b = write_boc(&c)?;
    let serialize_time = now.elapsed().as_millis();

    println!("total cells {}", cells_count);
    println!("boc size {}", b.len());
    println!("build time {}ms  {}ms per cell", build_time, build_time as f64 / cells_count as f64);
    println!("serialize time {}ms  {}ms per cell", serialize_time, serialize_time as f64 /cells_count as f64);

    let now = std::time::Instant::now();
    let c2 = BocReader::new().read_inmem(Arc::new(b))?.withdraw_single_root()?;
    let deserialize_time = now.elapsed().as_millis();
    println!("deserialize time {}ms  {}ms per cell", deserialize_time, deserialize_time  as f64 /cells_count as f64);

    assert_eq!(c, c2);

    Ok(())
}

fn c(bitstring: &str, children: impl AsRef<[Cell]>) -> Result<Cell> {
    let mut b = SliceData::from_string(bitstring)?.as_builder();
    for child in children.as_ref() {
        b.checked_append_reference(child.clone())?;
    }
    b.into_cell()
}

macro_rules! C {
    ($s:expr) => {
        c($s, &[])?
    };
    ($s:expr, $($x:expr),+ $(,)?) => {
        c($s, vec!($($x),+))?
    };
}

#[test]
fn test_boc_write_iterative() -> Status {
    let root =
        C!("9023afe200000000000000000000000000000000000000000000000000000000000000000000000000000000002_",
            C!("00000000000000001_"),
            C!("dd45d21dba003_",
                C!("a0000020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3f75174876e800800000000000000000000000000000000000000000000000000000000000000000000000000000004_",
                    C!("cec_",
                        C!("2_",
                            C!("50b24_"),
                            C!("2_",
                                C!("0391_"),
                                C!("040259_")
                            )
                        ),
                        C!("2_",
                            C!("2_",
                                C!("040321_"),
                                C!("0403e9_")
                            ),
                            C!("2_",
                                C!("0404b1_"),
                                C!("07312dc9_")
                            )
                        )
                    ),
                    C!("dc4c190b8000008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f916407be01d6f34562de0000000000000000a2e90edd001ef7c_",
                        C!("cec_",
                            C!("2_",
                                C!("50b24_"),
                                C!("2_",
                                    C!("0391_"),
                                    C!("040259_")
                                )
                            ),
                            C!("2_",
                                C!("2_",
                                    C!("040321_"),
                                    C!("0403e9_")
                                ),
                                C!("2_",
                                    C!("0404b1_"),
                                    C!("07312dc9_")
                                )
                            )
                        ),
                        C!("3ffffffffffffff4_",
                            C!("3ffffffffffffff4_",
                                C!("3f3ffffffffffff4_",
                                    C!("0ffffffffffffff4_",
                                        C!("3fff3ffffffffff4_")
                                    )
                                )
                            )
                        ),
                        C!("3fff1ffffffffff4_"),
                        C!("a00f4172af42bd2799479d2d99695d9e4eb46e3144c7915d9455629fcdc3cc42e59",
                            C!("3ffffffffffffff4_")
                        )
                    )
                ),
                C!("cec_",
                    C!("2_",
                        C!("50b24_"),
                        C!("2_",
                            C!("0391_"),
                            C!("040259_")
                        )
                    ),
                    C!("2_",
                        C!("2_",
                            C!("040321_"),
                            C!("0403e9_")
                        ),
                        C!("2_",
                            C!("0404b1_"),
                            C!("07312dc9_")
                        )
                    )
                )
            ),
            C!("00000000000000000000000000000000000")
        );

    let mut data = Vec::new();
    BocWriter::with_root(&root).unwrap().write(&mut data)?;

    let expected = hex::decode("b5ee9c7201021b010001a700035b9023afe20000000000000000000000000000000000000000000000000000000000000000000000000000000000201a02010023000000000000000000000000000000000008020ddd45d21dba0030030d029fa0000020406080a0c0e10121416181a1c1e20222426282a2c2e30323436383a3c3f75174876e8008000000000000000000000000000000000000000000000000000000000000000000000000000000040d04047ddc4c190b8000008101820283038404850586068707880889098a0a8b0b8c0c8d0d8e0e8f0f916407be01d6f34562de0000000000000000a2e90edd001ef7c00d0807050143a00f4172af42bd2799479d2d99695d9e4eb46e3144c7915d9455629fcdc3cc42e59806000f3ffffffffffffff4000f3fff1ffffffffff4010f3ffffffffffffff409010f3ffffffffffffff40a010f3f3ffffffffffff40b010f0ffffffffffffff40c000f3fff3ffffffffff40203cec0150e020120120f0201201110000707312dc900050404b1020120141300050403e9000504032102012019160201201817000504025900030391000550b2400011000000000000000010").unwrap();
    assert_eq!(expected, data);

    Ok(())
}

fn test_bad_boc(boc: Vec<u8>) {
    match BocReader::new().read(&mut std::io::Cursor::new(&boc)) {
        Ok(_) => panic!("BocReader::new().read must panic"),
        Err(e) => println!("{:?}", e),
    }
    match BocReader::new().read_inmem(Arc::new(boc)) {
        Ok(_) => panic!("BocReader::new().read_inmem must panic"),
        Err(e) => println!("{:?}", e),
    }
}

#[test]
fn test_bad_boc_1() {
    let mut bb = Vec::new();
    bb.extend_from_slice(&0xb5ee9c72_u32.to_be_bytes()); // magic
    bb.push(0b0000_0100); // flags
    bb.push(1); // offset size
    bb.extend_from_slice(&u32::MAX.to_be_bytes()); // cells
    bb.extend_from_slice(&u32::MAX.to_be_bytes()); // roots
    bb.extend_from_slice(&0u32.to_be_bytes()); // absent count
    bb.push(0); // tot_cells_size

    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_2() {
    let bb = base64_decode("aP9l8wIGAAAAAAAAAABo8w==").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_3() {
    let mut bb = Vec::new();
    bb.extend_from_slice(&0xb5ee9c72_u32.to_be_bytes()); // magic
    bb.push(0b0000_0100); // flags
    bb.push(1); // offset size
    bb.extend_from_slice(&0_u32.to_be_bytes()); // cells
    bb.extend_from_slice(&0_u32.to_be_bytes()); // roots
    bb.extend_from_slice(&0_u32.to_be_bytes()); // absent count
    bb.push(0); // tot_cells_size

    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_4() {
    let bb = base64_decode("te6ccjEHBwIAEO6ccjAHBw0AAAAAJgAAAAEvAAAAAAEv8PDw8Cpk/wsAAAAAAAAAAAAAAAAAAv+s/8M=").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_5() {
    let bb = vec![
        0xb5u8, 0xee, 0x9c, 0x72, // magic
        1,   // flags ref size
        1,   // offset size
        1,   // cells count
        0,   // roots count
        0,   // absent count
        2,  // total cell size
        8, // d1 <-- exotic cell
        0, // d2 <-- empty data
    ];
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_6() {
    let bb = base64_decode("te6ccgEBBAEBIQEAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_7() {
    let bb = base64_decode("te6ccgEBAwEABgAAAAAAAAAAAAAAAAAAAAAA").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_8() {
    // 6GB allocation
    let bb = base64_decode("te6ccnQG+1d+m1sBAAEBAVsAAAaIm/YAGG4Anp6enhhuAJ6enp4A/yWGmwEBAQAABoib9gAYbgCenp76AKoBMAQlKv8=").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_9() {
    let bb = hex::decode("b5ee9c72010101000002080065").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_10() {
    let bb = base64_decode("aP9l8wEBAgEAKQP/QQABSEgBAgAo//8A/wAo//8AAAAAAwAAAAMXeuR65P//////AP////8AAAADAAAAA+Q=").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_11() {
    std::env::set_var("RUST_BACKTRACE", "full");

    let bb = base64_decode("te6ccgECNwEACRUABCSK7VMg4wMgwP/jAiDA/uMC8gs0AgE2A4jtRNDXScMB+GaJ+Gkh2zzTAAGegwjXGCD5AVj4QvkQ8qje0z8B+EMhufK0IPgjgQPoqIIIG3dAoLnytPhj0x8B2zzyPCAbAwNS7UTQ10nDAfhmItDTA/pAMPhpqTgA3CHHAOMCIdcNH/O8IeMDAds88jwzMwMCKCCCEDBCXM674wIgguNurhC7ScICDgwEUCCCEDZpLEK64wIgghBAjZGDuuMCIIIQRSVc17rjAiCCEG5JrsK64wIMCgcFAzow+Eby4Ez4Qm7jACGT1NHQ3vpA0x/R2zww2zzyADEGJQEq+En4SscF8uPvAfh1+HRx+Hv4Vds8KANGMPhG8uBM+EJu4wAhldL/1NHQktL/4tP/0//U0ds8MNs88gAxCCUCNFv4SfhNxwXy4+/4I/hRb7WhtR8BvI6A4w0wCSMBCiC1f9s8EwNGMPhG8uBM+EJu4wAhk9TR0N76QNMf9ARZbwIB0ds8MNs88gAxCyUBKvhJ+ErHBfLj7wH4evh5cvh7+FrbPCgDLDD4RvLgTPhCbuMA03/U0ds8MNs88gAxDSUBLvhJ+E7HBfLj7/kA+FFvuPkAuvLj7ds8EwRQIIIQFqlr+brjAiCCECHGW+a64wIgghAtBFzvuuMCIIIQMEJczrrjAiQhGQ8DojD4RvLgTPhCbuMAIY4W1NHQ0gABb6Gc0//T/9Mf0x9VMG8E3o4T0gABb6Gc0//T/9Mf0x9VMG8E3uIB0x/0BFlvAgHU0dD6QNTR2zww2zzyADEQJQKyIfgoxwXy4+8g0NP/0fhRbxD4SV8ib7WAIPQP8rLQ2zxvEMcF8uPv+En4XMgnbyICyx/0AFmBAQv0Qfh8cG1vAvhcIIEBC/SCb6GZAdMf9AVvAm8C3pMgbrMuEQFsjidTIG8QAW8iIaRVIIAg9BZvAjNvECGBAQv0dG+hmQHTH/QFbwJvAt7oW28QIW+0uo6A3l8GEgN6IG8QgjAN4LazI2QAACJvtXBtjoCOgOhfA4EPoFj4TMcF8vSCEDuaygCCMA3gtrOnZAAAqYS1f6dktX/bPBcVEwHoggiYloBw+wL4W45o+FvAAY4m+FMh+E/4VPhV+Ev4SsjPhYjOcc82AAAAyM+RMS+zEss/zssfyx+OLPhTIfhZ+E/4WvhL+ErIz4WIznHPC25VUMjPkdBSzVrLP87LHwFvIgLLH/QA4st/AW8jXiDLH8sfAcgUAJaOP/hTIfhY+Ff4VvhP+FT4VfhL+ErIz4WINgAAAG5VgMjPkOtVHdLLP87LH8sfy3/LH8sHWcjLfwFvI14gyx/LH+LOzc3Jgwb7ADABlnAhbxD4XIEBC/QKlNMf9AWScG3ibwIibxEnxwWOLXEhbxGAIPQO8rLXC3+CMA3gtrOnZAAAcCNvEYAg9A7ystcLf6mEtX8yIm8SNxYAqI48Im8SJ8cFji1wIW8RgCD0DvKy1wt/gjAN4Lazp2QAAHEjbxGAIPQO8rLXC3+phLV/MiJvETeVgQ+g8vDi4jBSQIIwDeC2s6dkAACphLV/NCGkMgEcUxKAIPQPb6HjACAybrMYAQbQ2zwuAv4w+EJu4wD4RvJzIZPU0dDe+kDU0dD6QNTR0PpA0x/TByHCAvLQSdTR0PpA0x/0BFlvAhJvAgHU0x/TD1UgbwMB1NMf0x9VIG8DAVUgbwMB0//U0dDTH9TTH9P/VUBvBQHTH9Mf+kBVIG8DAdH4SfhKxwXy4+9VBvhsVQT4bVUEGxoBLPhuVQP4b1UC+HBY+HEB+HL4c9s88gAlAhbtRNDXScIBjoDjDRwxBHpw7UTQ9AVw+ED4QfhC+EP4RPhF+Eb4R/hI+ElxK4BA9A6OgN9yLIBA9A5vkZPXCz/eiV8gcCCJcG1vAm8CHyAgHQQqiHAgbwMgbwNwIIhwIG8FcCCJbwNwNjYgHgI8iXBfMG1vAolwbYAdb4DtV4BA9A7yvdcL//hicPhjICABAokgAEOAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAQAygw+Eby4Ez4Qm7jANTR2zww2zzyADEiJQEYMPhJ+E3HBfLj79s8IwA6+FvAApL4WpL4VeLIz4UIzoBvz0DJgwamILUH+wADUjD4RvLgTPhCbuMAIZPU0dDe+kDTH9N/0x/TByHCAfLQSdHbPDDbPPIAMSclAf7tR3CAHW+HgB5vgjCAHXBkXwr4Q/hCyMv/yz/Pg87LP4ARYsjOVfDIzlXgyM7LH8sHAW8jXiABbyICVeDIzgFvIgLLH/QAAW8jXiDMyx/LDwFvI170DvKy1wt/qYS1fzIibxI3FgCojjwibxInxwWOLXAhbxGAIPQO8rLXC3+CMA3gtrOnZAAAcSNvEYAg9A7ystcLf6mEtX8yIm8RN5WBD6Dy8OLiMFJAgjAN4Lazp2QAAKmEtX80IaQyARxTEoAg9A9voeMAIDJusxgBBtDbPC4C/jD4Qm7jAPhG8nMhk9TR0N76QNTR0PpA1NHQ+kDTH9MHIcIC8tBJ1NHQ+kDTH/QEWW8CEm8CAdTTH9MPVSBvAwHU0x/TH1UgbwMBVSBvAwHT/9TR0NMf1NMf0/9VQG8FAdMf0x/6QFUgbwMB0fhJ+ErHBfLj71UG+GxVBPhtVQQbGgEs+G5VA/hvVQL4cFj4cQH4cvhz2zzyACUCFu1E0NdJwgGOgOMNHDEEenDtRND0BXD4QPhB+EL4Q/hE+EX4RvhH+Ej4SXErgED0Do6A33IsgED0Dm+Rk9cLP96IzoIQTEZkGc8LjszJgwb7AAH+7UTQ0//TP9MAMfpA0z/U0dD6QNTR0PpA1NHQ+kDTH9MHIcIC8tBJ1NHQ+kDTH/QEWW8CEm8CAdTTH9MPVSBvAwHU0x/TH1UgbwMBVSBvAwHT/9TR0NMf1NMf0/9VQG8FAdMf0x/6QFUgbwMB0x/U0dD6QNN/0x/TByHCAfLQSTIAdtMf9ARZbwIB1NHQ+kDTByHCAvLQSfQE0XD4QPhB+EL4Q/hE+EX4RvhH+Ej4SYATemOAHW+A7Vf4Y/hiAAr4RvLgTAIK9KQg9KE2NQAUc29sIDAuNjIuMAAA").unwrap();
    test_bad_boc(bb);
}

#[test]
fn test_bad_boc_12() {
    let data = base64_decode("tv+acwEBBwEAgQJAAA3S0tLSjwAAAAAAAADS///DyG0BXNKPAAAAAAAAANL//8PIbQFcBQCrSP///wAAAAAAAAAAAAAAAQAAAAAAAAAAAAD/kwAAAAAA0tLS0gUAq0j///8AAAAAAAAAAAAAAAEAAAAAAAAAAAAA/5MAAAAAANLS0tLS0tLS0tLS0tIAAQ==").unwrap();
    let d1 = std::time::Instant::now();
    let _read_result = read_boc(data);
    let elapsed = d1.elapsed().as_nanos();
    println!("Parse: {}nanos,", elapsed);
    assert!(elapsed < 1_000_000);
}