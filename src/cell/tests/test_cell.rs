/*
* Copyright (C) 2019-2022 EverX. All Rights Reserved.
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

use rand::{thread_rng, Rng};
use super::*;

#[test]
fn test_format_cell() {
    let mut root = BuilderData::new();
    let mut c1 = BuilderData::new();
    let mut c2 = BuilderData::new();
    let mut c3 = BuilderData::new();
    let mut c4 = BuilderData::new();	

    root.append_u32(0xfff0).unwrap();
    c1.append_u32(0xfff1).unwrap();
    c2.append_u32(0xfff2).unwrap();
    c3.append_u32(0xfff3).unwrap();
    c4.append_u32(0xfff4).unwrap();
    
    c1.append_reference(c2);
    c1.append_reference(c3);
    root.append_reference(c1);
    root.append_reference(c4);

    let cell = root.into_cell().unwrap();

    assert_eq!(
        format!("{}", cell),
        "bits: 32   refs: 2   data: 0000fff0");

    assert_eq!(
        format!("{:#}", cell),
r#"Ordinary   l: 000   bits: 32   refs: 2   data: 0000fff0
hashes: 2284543e5a1301a2f7035b17e5381479d56296760e745f284cc0ef6474c090ab
depths: 2"#);

    assert_eq!(
        format!("{:.1}", cell),
        r#"bits: 32   refs: 2   data: 0000fff0
 ├─bits: 32   refs: 2   data: 0000fff1
 └─bits: 32   refs: 0   data: 0000fff4"#);

    assert_eq!(
        format!("{:.2}", cell),
        r#"bits: 32   refs: 2   data: 0000fff0
 ├─bits: 32   refs: 2   data: 0000fff1
 │ ├─bits: 32   refs: 0   data: 0000fff2
 │ └─bits: 32   refs: 0   data: 0000fff3
 └─bits: 32   refs: 0   data: 0000fff4"#);

    assert_eq!(
        format!("{:#.1}", cell),
        r#"Ordinary   l: 000   bits: 32   refs: 2   data: 0000fff0
hashes: 2284543e5a1301a2f7035b17e5381479d56296760e745f284cc0ef6474c090ab
depths: 2
 ├─Ordinary   l: 000   bits: 32   refs: 2   data: 0000fff1
 │ hashes: 013a48b1f5da4a3ed97975185ef221aa031fb14c189d791db859a003bbde9c6a
 │ depths: 1
 └─Ordinary   l: 000   bits: 32   refs: 0   data: 0000fff4
   hashes: 8d7e5e5b7b0533c2bc2e18991c561d2f2a0a30225af61bb42ff55cd2fec2d3cc
   depths: 0"#);

    assert_eq!(
        format!("{:#.2}", cell),
        r#"Ordinary   l: 000   bits: 32   refs: 2   data: 0000fff0
hashes: 2284543e5a1301a2f7035b17e5381479d56296760e745f284cc0ef6474c090ab
depths: 2
 ├─Ordinary   l: 000   bits: 32   refs: 2   data: 0000fff1
 │ hashes: 013a48b1f5da4a3ed97975185ef221aa031fb14c189d791db859a003bbde9c6a
 │ depths: 1
 │ ├─Ordinary   l: 000   bits: 32   refs: 0   data: 0000fff2
 │ │ hashes: 89497332e5fc3e6a9256db6eca374b4c322b1f7e32da90d17cf5bcc78044dc67
 │ │ depths: 0
 │ └─Ordinary   l: 000   bits: 32   refs: 0   data: 0000fff3
 │   hashes: 138a0c065fa8178a3cb164a093bd0f9f2cdbfb824b5aae88fccd37e789d63da1
 │   depths: 0
 └─Ordinary   l: 000   bits: 32   refs: 0   data: 0000fff4
   hashes: 8d7e5e5b7b0533c2bc2e18991c561d2f2a0a30225af61bb42ff55cd2fec2d3cc
   depths: 0"#);

    let mut data = [0; 24];
    data[0] = 1;
    data[23] = 7;
    let cell = create_big_cell(&data).unwrap();
    assert_eq!(
        format!("{}", cell),
        "Big   bytes: 24   data: 010000000000000000000000000000000000000000000007");
    assert_eq!(
        format!("{:#}", cell),
        "Big   bytes: 24   data: 010000000000000000000000000000000000000000000007
hash: bee6d912b344447b23d23aa2f4bd8d550da1be353e5ae62766a5bf64a4803113");

    let mut data = [0; 101];
    data[0] = 9;
    data[100] = 0x15;
    let cell = create_big_cell(&data).unwrap();
    assert_eq!(
        format!("{}", cell),
        "Big   bytes: 101
data: 0900000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000015");

    let mut data = [0; 1024];
    data[0] = 0x76;
    let cell = create_big_cell(&data).unwrap();
    assert_eq!(
        format!("{}", cell),
        "Big   bytes: 1024
data: 7600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000...");

assert_eq!(
    format!("{:#}", cell),
    "Big   bytes: 1024
data: 7600000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000...
hash: e002f2230f56f0d5219ef4baf2ee1d343c73cba7a9d9d9a57fc09a3db790991b");


    let slice = SliceData::new(vec![0x0, 0x1, 0x80]);
    assert_eq!(format!("{:b}", slice.into_cell()), "0000000000000001");

    let slice = SliceData::new(vec![0x0, 0x0, 0x80]);
    assert_eq!(format!("{:b}", slice.into_cell()), "0000000000000000");

    let slice = SliceData::new(vec![0x0, 0x1, 0x20]);
    assert_eq!(format!("{:b}", slice.into_cell()), "000000000000000100");

    let slice = SliceData::new(vec![0x0, 0x1, 0x02]);
    assert_eq!(format!("{:b}", slice.into_cell()), "0000000000000001000000");

    let slice = SliceData::new(vec![0xff, 0x00, 0xfc]);
    assert_eq!(format!("{:b}", slice.into_cell()), "111111110000000011111");

    let slice = SliceData::new(vec![0b10010111, 0b10001010, 0b10000010]);
    assert_eq!(format!("{:b}", slice.into_cell()), "1001011110001010100000");
}

#[test]
fn test_format_slice() {
    let slice = SliceData::new(vec![0x25, 0x67]);
    assert_eq!(format!("{:x}", slice), r#"2567_"#);
    let slice = SliceData::new(vec![0x25, 0x68]);
    assert_eq!(format!("{:x}", slice), r#"256"#);
    let slice = SliceData::new(vec![0x25, 0x68, 0x80]);
    assert_eq!(format!("{:x}", slice), r#"2568"#);
    let slice = SliceData::new(vec![0x25, 0x68, 0x80]);
    assert_eq!(format!("{}", slice.into_cell()), r#"bits: 16   refs: 0   data: 2568"#);
}

#[test]
fn test_compare_cells() {
    let builder1 = BuilderData::with_raw(vec![0xF0], 4).unwrap();
    let builder2 = BuilderData::with_bitstring(vec![0xF8]).unwrap();
    let builder3 = BuilderData::with_bitstring(vec![0xFF, 0x80]).unwrap();

    let cell1 = builder1.into_cell().unwrap();
    let cell2 = builder2.into_cell().unwrap();
    let cell3 = builder3.into_cell().unwrap();

    assert_eq!(cell1, cell2);
    assert_ne!(cell1, cell3);
    assert_ne!(cell2, cell3);
    assert_eq!(cell3.clone(), cell3);
}

#[test]
fn test_compare_slice_cells() {
    let cell1 = SliceData::new(vec![0x78]).into_cell();
    let mut slice = SliceData::new(vec![0, 0x78]);
    slice.move_by(8).unwrap();
    let cell2 = slice.into_cell();
    assert_eq!(SliceData::load_cell(cell1.clone()).unwrap(), SliceData::load_cell(cell2.clone()).unwrap());

    assert_eq!(cell1, cell2);
}

#[test]
fn test_usage_cell() {
    /*
                      1
             2                  3
        4          5         6     7 
        8        9   10
                     11
    */

    let c11 = create_cell(vec!(), &[11, 0x80]).unwrap();
    let c10 = create_cell(vec!(c11.clone()), &[10, 0x80]).unwrap();
    let c9 =  create_cell(vec!(), &[9, 0x80]).unwrap();
    let c8 =  create_cell(vec!(), &[8, 0x80]).unwrap();
    let c7 =  create_cell(vec!(), &[7, 0x80]).unwrap();
    let c6 =  create_cell(vec!(), &[6, 0x80]).unwrap();
    let c5 =  create_cell(vec!(c9.clone(), c10.clone()), &[5, 0x80]).unwrap();
    let c4 =  create_cell(vec!(c8.clone()), &[4, 0x80]).unwrap();
    let c3 =  create_cell(vec!(c6.clone(), c7.clone()), &[3, 0x80]).unwrap();
    let c2 =  create_cell(vec!(c4.clone(), c5.clone()), &[2, 0x80]).unwrap();
    let c1 =  create_cell(vec!(c2.clone(), c3.clone()), &[1, 0x80]).unwrap();

    assert_eq!(c1.tree_bits_count(), 8 * 11);
    assert_eq!(c1.tree_cell_count(), 11);

    let ut = UsageTree::with_root(c1.clone());
    let mut c1_slice = SliceData::load_cell(ut.root_cell()).unwrap();

    let mut c2_slice = SliceData::load_cell(c1_slice.checked_drain_reference().unwrap()).unwrap();
    let _c3_slice = SliceData::load_cell(c1_slice.checked_drain_reference().unwrap()).unwrap();
    let mut c4_slice = SliceData::load_cell(c2_slice.checked_drain_reference().unwrap()).unwrap();
    let mut c5_slice = SliceData::load_cell(c2_slice.checked_drain_reference().unwrap()).unwrap();
    let _c9_slice = SliceData::load_cell(c5_slice.checked_drain_reference().unwrap()).unwrap();
    let mut c10_slice = SliceData::load_cell(c5_slice.checked_drain_reference().unwrap()).unwrap();
    let mut c11_slice = SliceData::load_cell(c10_slice.checked_drain_reference().unwrap()).unwrap();

    assert_eq!(11, c11_slice.get_next_byte().unwrap());

    for c in [&c1, &c2, &c5, &c10, &c11] {
        assert!(ut.contains(&c.hash(0)));
    }
    for c in [&c3, &c4, &c6, &c7, &c8, &c9] {
        assert!(!ut.contains(&c.hash(0)));
    }

    let mut c8_slice = SliceData::load_cell(c4_slice.checked_drain_reference().unwrap()).unwrap();
    assert_eq!(8, c8_slice.get_next_byte().unwrap());

    // create usage subtree with root in c4
    let subvisited = ut.build_visited_subtree(&|h| h == &c4.hash(0)).unwrap();

    assert_eq!(subvisited.len(), 2);
    assert!(subvisited.contains(&c4.hash(0)));
    assert!(subvisited.contains(&c8.hash(0)));

    // create usage subtree with root in c5
    let subvisited = ut.build_visited_subtree(&|h| h == &c5.hash(0)).unwrap();

    assert_eq!(subvisited.len(), 3);
    assert!(subvisited.contains(&c5.hash(0)));
    assert!(subvisited.contains(&c10.hash(0)));
    assert!(subvisited.contains(&c11.hash(0)));
}

#[test]
fn test_cell_count_cells() {
    let cell = Cell::default();
    let mut builder = BuilderData::default();
    builder.checked_append_reference(cell.clone()).unwrap();
    builder.checked_append_reference(cell).unwrap();
    let cell = builder.into_cell().unwrap();
    assert_eq!(cell.count_cells(3).unwrap(), 3);
    cell.count_cells(1).expect_err("3 must exceeds 1");
    cell.count_cells(2).expect_err("3 must exceeds 2");
}

#[test]
fn test_default_cell() {
    let d1 = calc_d1(LevelMask::with_mask(0), false, CellType::Ordinary, 0);
    let d2 = calc_d2(0);

    assert_eq!(UInt256::calc_file_hash(&[d1, d2]), UInt256::DEFAULT_CELL_HASH);

    let cell = BuilderData::default().into_cell().unwrap();
    assert_eq!(cell.repr_hash(), UInt256::DEFAULT_CELL_HASH);

    assert_eq!(BuilderData::default(), BuilderData::from_cell(&Cell::default()).unwrap());
}

#[test]
fn test_cell_state() {
    let c1 = BuilderData::with_raw(vec![10, 20], 15).unwrap().into_cell().unwrap();
    let c2 = BuilderData::with_raw(vec![40], 3).unwrap().into_cell().unwrap();
    let c0 = BuilderData::with_raw_and_refs(vec![77], 1, vec![c1.clone(), c1, c2]).unwrap().into_cell().unwrap();

    assert_eq!(c0.tree_bits_count(), 34);
    assert_eq!(c0.tree_cell_count(), 4);
}


#[test]
fn test_cell_data_serialization() {

    let initial_cell = CellData::with_params(
        CellType::Ordinary,
        &[1, 2, 3, 0x84], // data
        1, // level mask
        2, // refs count
        false, // store hashes
        Some([
            UInt256::from_slice(&[0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,]),
            UInt256::from_slice(&[0x8a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0x00, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0x11, 0x92, 0x5b,]),
            UInt256::default(),
            UInt256::default(),
        ]),
        Some([3, 2, 0, 0])
    ).unwrap();


    let mut output_buf: Vec<u8> = Vec::new();
    initial_cell.serialize(&mut output_buf).unwrap();

    let serialized: Vec<u8> = vec![
        // cell type
        0x01,
        // bit length (tag is not included)
        0x1d, 0x00,
        // cell data
        0x01, 0x02, 0x03, 0x84,
        // level mask
        0x01,
        // store_hashes
        0x00,
        // hashes are stored
        0x01,
        // hashes count
        0x02,
        // hashes
        0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
        0x8a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0x00, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0x11, 0x92, 0x5b,
        // depths are stored 
        0x01,
        // depths count 
        0x02,
        // depths
        0x03, 0x00, 0x02, 0x00,
        // refs count
        0x02
    ];

    assert_eq!(output_buf, serialized);

    let deserialized = CellData::deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(deserialized, initial_cell);
}


#[test]
fn test_cell_data_serialization_2() {

    let cell = DataCell::with_params(
        vec!(), // references
        // data   type + level_mask + level * (hashes + depths)
        &[
            0x1,
            0x1, 
            0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89,
            0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
            0x1, 0x0,
            0x80,
        ], 
        CellType::PrunedBranch,
        0x1, // level_mask
        None,
        None,
        None
    ).unwrap();

    let initial_cell = cell.cell_data;

    let mut output_buf: Vec<u8> = Vec::new();
    initial_cell.serialize(&mut output_buf).unwrap();

    let serialized: Vec<u8> = vec![
        // cell type 
        0x02, 
        // bitlen
        0x20, 0x01, 
        // data
        0x01, 0x01, 
        0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89,
        0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b, 
        0x01, 0x00,
        0x00, // compatibility bite
        // level mask
        0x01,
        // store_hashes
        0x00,
        // hashes are stored
        0x01,
        // hashes count
        0x01,
        // hash
        0xcd, 0xd9, 0x93, 0xaf, 0xdc, 0xba, 0x18, 0x49, 0xb4, 0x61, 0xf7, 0x5d, 0x8d, 0x5f, 0xd3, 0x74,
        0xe6, 0x1d, 0x5c, 0x23, 0xd6, 0x3c, 0xfd, 0xc9, 0xe4, 0xd9, 0x31, 0xb7, 0x95, 0xea, 0xf4, 0x5b,
        // depths are stored 
        0x01,
        // depths count 
        0x01,
        // depths
        0x00, 0x00,
        // refs count
        0x00,
    ];

    for b in &output_buf {
        print!("0x{:02x}, ", b)
    }
    println!();
    for b in &serialized {
        print!("{:02x}, ", b)
    }

    assert_eq!(output_buf, serialized);

    let deserialized = CellData::deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(deserialized, initial_cell);
}

#[test]
fn test_cell_data_serialization_3() {

    let data = [
        1, // type
        0b011_u8, // levelmask
        // 2 hashes
        0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89,
        0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
        0x8a, 0x86, 0x6c, 0x98, 0xfb, 0x11, 0x0b, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89,
        0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
        // 2 depths
        0, 1,
        0, 1,
        0x80
    ];
    dbg!(data.len());

    let cell = DataCell::with_params(
        vec!(), // references
        // data   type + level_mask + level * (hashes + depths)
        &data, 
        CellType::PrunedBranch,
        0b011,
        None,
        None,
        None
    ).unwrap();

    let initial_cell = cell.cell_data;

    let mut output_buf: Vec<u8> = Vec::new();
    initial_cell.serialize(&mut output_buf).unwrap();

    let serialized: Vec<u8> = vec![
        // type
        0x2, 
        // bitlen
        0x30, 0x2,
        // data
            // type
            0x1, 
            // level mask
            0b011, 
            // 2 hashes
            0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89,
            0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
            0x8a, 0x86, 0x6c, 0x98, 0xfb, 0x11, 0x0b, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89,
            0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
            // 2 depths
            0x0, 0x1, 0x0, 0x1,
            0x00, // compatibility bite
        // level mask
        0b011, 
        // store hashes
        0x0, 
        0x1, 
        // hashes count
        0x1, 
        // hash
        0x0b, 0x37, 0x98, 0x44, 0x5a, 0x06, 0x01, 0xce, 0x08, 0xdc, 0xff, 0x85, 0xb5, 0x95, 0x2f, 0x80,
        0xea, 0x8b, 0xa7, 0xfc, 0x80, 0x22, 0x81, 0xb6, 0x33, 0x77, 0x49, 0xe4, 0x8c, 0x8b, 0x88, 0x02,
        // store depths
        0x1, 
        0x1, 
        0x0, 0x0, 
        // refs
        0x0, 

    ];

    assert_eq!(output_buf, serialized);

    let deserialized = CellData::deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(deserialized, initial_cell);
}


#[test]
fn test_cell_data_serialization_4() {

    let initial_cell = CellData::with_params(
        CellType::Ordinary,
        &[1, 2, 3, 0x84], // data
        0b101, // level mask
        2, // refs count
        true, // store hashes
        Some([
            UInt256::from_slice(&[0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,]),
            UInt256::from_slice(&[0x8a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,]),
            UInt256::from_slice(&[0x9a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0x00, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0x11, 0x92, 0x5b,]),
            UInt256::default(),
        ]),
        Some([3, 2, 0, 0])
    ).unwrap();


    let mut output_buf: Vec<u8> = Vec::new();
    initial_cell.serialize(&mut output_buf).unwrap();

    let serialized: Vec<u8> = vec![
        // cell type
        0x01,
        // bit length (tag is not included)
        0x1d, 0x00,
        // cell data
        0x01, 0x02, 0x03, 0x84,
        // level mask
        0b101,
        // store_hashes
        0x01,
        // hashes are stored
        0x01,
        // hashes count
        0x03,
        // hashes
        0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
        0x8a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
        0x9a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0x00, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0x11, 0x92, 0x5b,
        // depths are stored 
        0x01,
        // depths count 
        0x03,
        // depths
        0x03, 0x00, 0x02, 0x00, 0x00, 0x00,
        // refs count
        0x02
    ];

    assert_eq!(output_buf, serialized);

    let deserialized = CellData::deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(deserialized, initial_cell);
}

#[test]
fn test_cell_data_serialization_5() {

    let initial_cell = CellData::with_params(
        CellType::Ordinary,
        &[1, 2, 3, 0x84], // data
        0, // level mask
        2, // refs count
        true, // store hashes
        Some([
            UInt256::from_slice(&[0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,]),
            UInt256::default(),
            UInt256::default(),
            UInt256::default(),
        ]),
        Some([0xf121, 0, 0, 0])
    ).unwrap();


    let mut output_buf: Vec<u8> = Vec::new();
    initial_cell.serialize(&mut output_buf).unwrap();

    let serialized: Vec<u8> = vec![
        // cell type
        0x01,
        // bit length (tag is not included)
        0x1d, 0x00,
        // cell data
        0x01, 0x02, 0x03, 0x84,
        // level mask
        0,
        // store_hashes
        0x01,
        // hashes are stored
        0x01,
        // hashes count
        0x01,
        // hashes
        0x7a, 0x86, 0x6c, 0x58, 0xfb, 0x11, 0xab, 0xf4, 0x6c, 0xca, 0xf0, 0x2f, 0xdf, 0x02, 0x9c, 0x89, 0xfc, 0x24, 0xf6, 0x4d, 0x76, 0x07, 0x4a, 0x58, 0x0e, 0x0c, 0xab, 0x7d, 0x5c, 0xf5, 0x92, 0x5b,
        // depths are stored 
        0x01,
        // depths count 
        0x01,
        // depths
        0x21, 0xf1,
        // refs count
        0x02
    ];

    assert_eq!(output_buf, serialized);

    let deserialized = CellData::deserialize(&mut serialized.as_slice()).unwrap();
    assert_eq!(deserialized, initial_cell);
}

#[test]
fn test_cell_data_serialization_big_cell() {

    fn test(len: usize) -> Result<()> {
        let mut data = vec![0; len];
        thread_rng().try_fill(&mut data[..])?;

        let mut initial_cell = CellData::with_params(
            CellType::Big,
            // data
            &data,  // data
            0, // level mask
            0, // refs count
            false, // store hashes
            None,
            None
        )?;
        let hash = sha256_digest(&data[..]);
        initial_cell.set_hash_depth(0, &hash, 0)?;

        let mut output_buf: Vec<u8> = Vec::new();
        initial_cell.serialize(&mut output_buf)?;

        let mut serialized = Vec::new();
        serialized.write_all(&[CellType::Big as u8])?;
        serialized.write_all(&data.len().to_le_bytes()[0..3])?;
        serialized.write_all(&data)?;

        assert_eq!(output_buf, serialized);

        let deserialized = CellData::deserialize(&mut serialized.as_slice())?;
        if deserialized != initial_cell {
            fail!("deserialized != initial_cell");
        }

        Ok(())
    }

    test(0).unwrap();
    test(100).unwrap();
    test(1024).unwrap();
    test(1024 * 1024).unwrap();
    test(1024 * 1024 * 2).unwrap();
    test(0xffffff).unwrap();

}

#[test]
fn test_big_cell_creation() {

    std::env::set_var("RUST_BACKTRACE", "full");

    fn check_big_cell(cell: &Cell, data: &[u8]) -> Result<()> {
        let mut hasher = Sha256::new();
        hasher.update(data);
        let data_hash = hasher.finalize();

        if cell.data() != data {
            fail!("Cell data [{}] is not equal to original data [{}]", hex::encode(cell.data()), hex::encode(data));
        }
        if cell.repr_hash().as_slice() != data_hash.as_slice() {
            fail!("Cell hash is not equal to data hash");
        }
        if cell.bit_length() != data.len() * 8 {
            fail!("Cell bit length is not equal to data length");
        }
        if cell.references_count()!= 0 {
            fail!("Cell references count is not equal to 0");
        }
        if cell.level() != 0 {
            fail!("Cell level is not equal to 0");
        }
        if cell.cell_type() != CellType::Big {
            fail!("Cell type is not equal to Big");
        }
        if cell.repr_depth() != 0 {
            fail!("Cell depth is not equal to 0");
        }
        if cell.store_hashes() {
            fail!("Cell store_hashes is not false");
        }
        Ok(())
    }

    let testcase = |len| -> Result<()> {

        let mut data = vec![0; len];
        thread_rng().try_fill(&mut data[..])?;
        let cell = create_big_cell(&data)?;
        check_big_cell(&cell, &data)?;
        Ok(())
    };
    testcase(0).unwrap();
    testcase(1).unwrap();
    testcase(100).unwrap();
    testcase(1024).unwrap();
    testcase(1024 * 1024).unwrap();
    testcase(16 * 1024 * 1024 - 1).unwrap();

    assert!(create_big_cell(&[0; 16 * 1024 * 1024]).is_err());
    assert!(create_big_cell(&[0; 17 * 1024 * 1024]).is_err());
    let refs = vec!(Cell::default());
    assert!(DataCell::with_params(refs,   &[0; 1024], CellType::Big, 0, None, None, None).is_err());
    assert!(DataCell::with_params(vec!(), &[0; 1024], CellType::Big, 1, None, None, None).is_err());
    assert!(DataCell::with_params(vec!(), &[0; 1024], CellType::Big, 2, None, None, None).is_err());
    assert!(DataCell::with_params(vec!(), &[0; 1024], CellType::Big, 3, None, None, None).is_err());

    let hashes = Some([UInt256::rand(), UInt256::default(), UInt256::default(), UInt256::default()]);
    let depths = Some([0x1234, 0, 0, 0]);
    assert!(DataCell::with_params(vec!(), &[0; 1024], CellType::Big, 0, None, hashes, depths).is_err());

    // Big cell layout:
    // - the first byte is a constant **0b0000_1101** = 13, because
    //     - level mask - always **0**
    //     - store hashes - always **0**
    //     - exotic - always **1**
    //     - refs count - always **5 -** actually refs 0, 5 is a label to identify a big cell by the first byte
    // - the next three bytes encode the data size of the big cell (0..16 777 215)
    // - followed by the specified number of data bytes

    let mut offset = 0;
    let mut buf = Vec::new();
    let mut testcase = |len| -> Result<()> {
        offset = buf.len();
        buf.write_all(&[BIG_CELL_D1])?;

        let mut data = vec![0; len];
        thread_rng().try_fill(&mut data[..])?;
        buf.write_all(&data.len().to_be_bytes()[5..8])?;
        buf.write_all(&data)?;

        let cell1 = Cell::with_cell_impl(DataCell::with_raw_data(vec!(), buf[offset..].to_vec(), None)?);
        let cell2 = Cell::with_cell_impl(DataCell::with_external_data(vec!(), &Arc::new(buf.clone()), offset, None)?);
        assert_eq!(cell1, cell2);
        check_big_cell(&cell1, &data)?;
        check_big_cell(&cell2, &data)?;

        Ok(())
    };
    testcase(0).unwrap();
    testcase(1).unwrap();
    testcase(100).unwrap();
    testcase(1024).unwrap();
    testcase(1024 * 1024).unwrap();
    testcase(16 * 1024 * 1024 - 1).unwrap();

    assert!(testcase(16 * 1024 * 1024).is_err());
    assert!(testcase(17 * 1024 * 1024).is_err());

}

