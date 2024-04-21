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

use super::*;

#[test]
fn test_hmlabel() {
    fn check_label(key: SliceData, max: usize, value: usize) {
        let label = hm_label(&key, max).unwrap();
        println!("key: {}, max: {}, hm_label: {} value: {:b}", key, max, label, value);
        let len = label.length_in_bits();
        let x: usize = SliceData::load_builder(label).unwrap().get_next_int(len).unwrap() as usize;
        assert_eq!(x, value);
    }
    // check same
    check_label(SliceData::from_raw(vec![0], 8), 16, 0b11001000);
    check_label(SliceData::from_raw(vec![0b11111000], 5), 8, 0b1110101);

    //check
    check_label(SliceData::from_raw(vec![0], 1), 2, 0b0100);

    //additional special tests here:
}

#[test]
fn test_long_keys() {
    hm_label(&SliceData::from_raw(vec![0x77; 64], 512), 512).expect("must be constructed");
    hm_label(&SliceData::from_raw(vec![0x77; 96], 768), 768).expect("must be constructed");
    hm_label(&SliceData::from_raw(vec![0x77; 128], 1011), 1011).expect("must be constructed");
    hm_label(&SliceData::from_raw(vec![0x77; 128], 1012), 1012).expect_err("must not be constructed");
}

#[test]
fn test_merge_complex() -> Result<()> {
    fn init(keys: &[u8], out_keys: &mut Vec<SliceData>) -> Result<HashmapE> {
        let mut tree = HashmapE::with_bit_len(8);
        for key in keys {
            let key = SliceData::new(vec![*key, 0x80]);
            tree.set(key.clone(), &key)?;
            out_keys.push(key);
        }
        Ok(tree)
    }
    fn check(keys1: &[u8], keys2: &[u8]) -> Result<()> {
        let keys = &mut vec![];
        
        let mut tree1 = init(keys1, keys)?;
        let tree2 = init(keys2, keys)?;
        
        tree1.merge(&tree2, &SliceData::default())?;
        
        assert_eq!(tree1.len()?, keys.len());
        for key in keys {
            let value = tree1.get(key.clone())?.expect("must present");
            assert_eq!(key, &value)
        }
        Ok(())
    }

    fn bad_check(keys1: &[u8], keys2: &[u8]) -> Result<()> {
        let keys = &mut vec![];
        
        let mut tree1 = init(keys1, keys)?;
        let tree2 = init(keys2, keys)?;
        
        tree1.merge(&tree2, &SliceData::default()).expect_err("hashmap should not merge same leafs");
        Ok(())
    }

    let keys1 = [0b0000_0000, 0b0011_0000];
    let keys2 = [0b0000_0000, 0b0011_1111];
    bad_check(&keys1, &keys2)?;

    let keys1 = [0b0000_0000, 0b0100_0000, 0b0000_1000];
    let keys2 = [0b0000_0001, 0b0011_1111, 0b0001_1111, 0b0011_0000];
    check(&keys1, &keys2)?;

    let keys1 = [0b1111_1111, 0b1011_1111, 0b1111_0111];
    let keys2 = [0b1111_1110, 0b1100_0000, 0b1110_0000];
    check(&keys1, &keys2)?;

    let keys1 = [0b0000_0000, 0b0010_0000];
    let keys2 = [0b0001_1111, 0b0011_1111];
    check(&keys1, &keys2)?;

    let keys1 = [0b0001_0000, 0b0011_0000];
    let keys2 = [0b0001_1111, 0b0011_1111];
    check(&keys1, &keys2)?;

    Ok(())
}

