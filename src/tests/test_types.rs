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

use super::*;
use crate::{
    cell::{Cell, CellType, DataCell}, base64_decode, base64_encode, Ed25519KeyOption, 
    ed25519_generate_private_key, ed25519_sign_with_secret
};

#[test]
fn test_uint256_formatting() {
    let value = UInt256::from_str("1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef").unwrap();
    assert_eq!(value.to_string(), "UInt256[[12, 34, 56, 78, 90, AB, CD, EF, 12, 34, 56, 78, 90, AB, CD, EF, 12, 34, 56, 78, 90, AB, CD, EF, 12, 34, 56, 78, 90, AB, CD, EF]]");
    assert_eq!(format!("{:?}", value), "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    assert_eq!(format!("{:x}", value), "1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    assert_eq!(format!("{:#x}", value), "0x1234567890abcdef1234567890abcdef1234567890abcdef1234567890abcdef");
    assert_eq!(format!("{:#X}", value), "0x1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF1234567890ABCDEF");
}

#[test]
fn test_uint256_construct() {
    assert_eq!(UInt256::from_le_bytes(&0x0123456789ABCDEFu64.to_be_bytes()), UInt256::from_str("0123456789ABCDEF000000000000000000000000000000000000000000000000").unwrap());
    assert_eq!(UInt256::from_be_bytes(&0x0123456789ABCDEFu64.to_be_bytes()), UInt256::from_str("0000000000000000000000000000000000000000000000000123456789ABCDEF").unwrap());
    assert_eq!(UInt256::from_le_bytes(&0x0123456789ABCDEFu64.to_le_bytes()), UInt256::from_str("EFCDAB8967452301000000000000000000000000000000000000000000000000").unwrap());
    assert_eq!(UInt256::from_be_bytes(&0x0123456789ABCDEFu64.to_le_bytes()), UInt256::from_str("000000000000000000000000000000000000000000000000EFCDAB8967452301").unwrap());

    assert_eq!(UInt256::from_le_bytes(&[1, 2, 3]), UInt256::from_str("0102030000000000000000000000000000000000000000000000000000000000").unwrap());
    assert_eq!(UInt256::from_be_bytes(&[1, 2, 3]), UInt256::from_str("0000000000000000000000000000000000000000000000000000000000010203").unwrap());
}

#[test]
fn test_uint256_ordering() {
    assert!(UInt256::from_str("b5fb2792ecc96042d5f2f739c0a2586896c60719d1d8ad34f9d5f7ff578ffd89").unwrap() <
            UInt256::from_str("de48d8a9c6823c908cbf72c42f60d993424e4ac5298a16c6b811c9876b366827").unwrap());

    assert!(UInt256::from_str("de48d8a9c6823c908cbf72c42f60d993424e4ac5298a16c6b811c9876b366827").unwrap() >
            UInt256::from_str("15de0c10aaed5c7b9cdef181fd1b00abb8890ea5a1b86c961d7125e00c114691").unwrap());
}

#[test]
fn test_check_cell_types() {

    let prepare_data = |cell_type: CellType, len: usize| {
        assert!(len > 1);
        let mut data = vec![0x80; len];
        data[0] = cell_type.into();
        data
    };

    DataCell::with_params(vec![], &prepare_data(CellType::LibraryReference, 2), CellType::LibraryReference, 0, None, None, None)
        .expect_err("LibraryReference cell should be checked for 264 bits length");
    DataCell::with_params(vec![], &prepare_data(CellType::LibraryReference, 35), CellType::LibraryReference, 0, None, None, None)
        .expect_err("LibraryReference cell should be checked for 264 bits length");
    DataCell::with_params(vec![Cell::default()], &prepare_data(CellType::LibraryReference, 34), CellType::LibraryReference, 0, None, None, None)
        .expect_err("LibraryReference cell should be checked for no references");
    DataCell::with_params(vec![], &prepare_data(CellType::LibraryReference, 34), CellType::LibraryReference, 0, None, None, None).unwrap();

    DataCell::with_params(vec![], &prepare_data(CellType::MerkleProof, 2), CellType::MerkleProof, 0, None, None, None)
        .expect_err("MerkleProof cell should be checked for 280 bits length");
    DataCell::with_params(vec![], &prepare_data(CellType::MerkleProof, 37), CellType::MerkleProof, 0, None, None, None)
        .expect_err("MerkleProof cell should be checked for 280 bits length");
    DataCell::with_params(vec![], &prepare_data(CellType::MerkleProof, 36), CellType::MerkleProof, 0, None, None, None)
        .expect_err("MerkleProof cell should be checked for single reference");
    DataCell::with_params(vec![Cell::default(); 2], &prepare_data(CellType::MerkleProof, 36), CellType::MerkleProof, 0, None, None, None)
        .expect_err("MerkleProof cell should be checked for single reference");
    DataCell::with_params(vec![Cell::default()], &prepare_data(CellType::MerkleProof, 36), CellType::MerkleProof, 0, None, None, None).unwrap();

    DataCell::with_params(vec![], &prepare_data(CellType::MerkleUpdate, 2), CellType::MerkleUpdate, 0, None, None, None)
        .expect_err("MerkleUpdate cell should be checked for 552 bits length");
    DataCell::with_params(vec![], &prepare_data(CellType::MerkleUpdate, 71), CellType::MerkleUpdate, 0, None, None, None)
        .expect_err("MerkleUpdate cell should be checked for 552 bits length");
    DataCell::with_params(vec![], &prepare_data(CellType::MerkleUpdate, 70), CellType::MerkleUpdate, 0, None, None, None)
        .expect_err("MerkleUpdate cell should be checked for two references");
    DataCell::with_params(vec![Cell::default()], &prepare_data(CellType::MerkleUpdate, 70), CellType::MerkleUpdate, 0, None, None, None)
        .expect_err("MerkleUpdate cell should be checked for two references");
    DataCell::with_params(vec![Cell::default(); 2], &prepare_data(CellType::MerkleUpdate, 70), CellType::MerkleUpdate, 0, None, None, None).unwrap();
}

#[test]
fn test_parse_int256() {
    use crate::UInt256;

    let b64_without_pad = "GfgI79Xf3q7r4q1SPz7wAqBt0W6CjavuADODoz/DQE8";
    let b64 = "GfgI79Xf3q7r4q1SPz7wAqBt0W6CjavuADODoz/DQE8=";
    let hex = "19F808EFD5DFDEAEEBE2AD523F3EF002A06DD16E828DABEE003383A33FC3404F";

    assert_eq!(43, b64_without_pad.len());
    assert_eq!(44, b64.len());

    let ethalon = hex::decode(hex).unwrap();
    assert_eq!(32, ethalon.len());
    assert_eq!(b64, &base64_encode(&ethalon));
    assert_eq!(base64_decode(b64_without_pad).unwrap(), ethalon);
    assert_eq!(base64_decode(b64).unwrap(), ethalon);

    let hex_hash = hex.parse::<UInt256>().unwrap();
    assert_eq!(hex_hash, b64.parse::<UInt256>().unwrap());
    b64_without_pad.parse::<UInt256>().expect_err("we use only canonical padding base64");
}

#[test]
fn test_shard_secret() {
    let alice = Ed25519KeyOption::generate().unwrap();
    let bob = Ed25519KeyOption::generate().unwrap();

    let shard_secret = alice.shared_secret(bob.pub_key().unwrap()).unwrap();
    assert_eq!(shard_secret, bob.shared_secret(alice.pub_key().unwrap()).unwrap());
}

#[test]
fn test_ed25519_signing() {
    let data = [1, 2, 3];
    let secret_key = ed25519_generate_private_key().unwrap();
    let signature1 = secret_key.sign(&data);

    let key = Ed25519KeyOption::from_private_key(secret_key.as_bytes()).unwrap();
    let signature2 = key.sign(&data).unwrap();

    assert_eq!(&signature1, signature2.as_slice());

    let signature3 = ed25519_sign_with_secret(secret_key.as_bytes(), &data).unwrap();

    assert_eq!(signature1, signature3);
}
