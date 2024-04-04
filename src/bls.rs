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

use crate::{fail, Result};
use blst::min_pk::*;
use blst::*;
use rand::Rng;
use rand::{RngCore};
use std::collections::HashMap;

/*
    Constants
*/

pub const BLS_SECRET_KEY_LEN: usize = 32;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE: usize = 48;
pub const BLS_PUBLIC_KEY_LEN_FOR_MIN_SIG_MODE: usize = 96;
pub const BLS_PUBLIC_KEY_LEN: usize = BLS_PUBLIC_KEY_LEN_FOR_MIN_PK_MODE;
pub const BLS_KEY_MATERIAL_LEN: usize = 32;
pub const BLS_SIG_LEN_FOR_MIN_PK_MODE: usize = 96;
pub const BLS_SIG_LEN_FOR_MIN_SIG_MODE: usize = 48;
pub const BLS_SIG_LEN: usize = BLS_SIG_LEN_FOR_MIN_PK_MODE;
pub const BLS_SEED_LEN: usize = 32;

/*
    Utilities
*/

pub fn gen_bls_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> {
    let key_pair = BlsKeyPair::gen_bls_key_pair_based_on_key_material(ikm)?;
    Ok(key_pair.serialize())
}

pub fn gen_bls_key_pair() -> Result<([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])> {
    let key_pair = BlsKeyPair::gen_bls_key_pair()?;
    Ok(key_pair.serialize())
}

pub fn gen_public_key_based_on_secret_key(sk: &[u8; BLS_SECRET_KEY_LEN]) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    let pk = BlsKeyPair::deserialize_based_on_secret_key(sk)?;
    Ok(pk.pk_bytes)
}

pub fn sign(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &[u8]) -> Result<[u8; BLS_SIG_LEN]>  {
    BlsSignature::simple_sign(sk_bytes, msg)
}

pub fn verify(sig_bytes: &[u8; BLS_SIG_LEN], msg: &[u8], pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<bool> {
    BlsSignature::simple_verify(sig_bytes, msg, pk_bytes)
}

pub fn add_node_info_to_sig(sig_bytes: [u8; BLS_SIG_LEN], node_index: u16, total_num_of_nodes: u16) -> Result<Vec<u8>> {
    BlsSignature::add_node_info_to_sig(sig_bytes, node_index, total_num_of_nodes)
}

pub fn sign_and_add_node_info(
    sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
    msg: &[u8],
    node_index: u16,
    total_num_of_nodes: u16,
) -> Result<Vec<u8>> {
    BlsSignature::sign(sk_bytes, msg, node_index, total_num_of_nodes)
}

pub fn truncate_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<[u8; BLS_SIG_LEN]> {
    BlsSignature::truncate_nodes_info_from_sig(sig_bytes_with_nodes_info)
}

pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<Vec<u8>> {
    BlsSignature::get_nodes_info_from_sig(sig_bytes_with_nodes_info)
}

pub fn truncate_nodes_info_and_verify(sig_bytes_with_nodes_info: &[u8], pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN], msg: &[u8]) -> Result<bool> {
    BlsSignature::verify(sig_bytes_with_nodes_info, pk_bytes, msg)
}

/*
    Aggregation
*/

pub fn aggregate_public_keys(bls_pks_bytes: &[&[u8; BLS_PUBLIC_KEY_LEN]]) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    if bls_pks_bytes.len() == 0 {
        fail!("Vector of public keys can not be empty!");
    }
    let mut pks: Vec<PublicKey> = Vec::new();
    for bls_pk in bls_pks_bytes {
        pks.push(convert_public_key_bytes_to_public_key(bls_pk)?);
    }
    let pk_refs: Vec<&PublicKey> = pks.iter().map(|pk| pk).collect();
    let agg = match AggregatePublicKey::aggregate(&pk_refs, true) {
        Ok(agg) => agg,
        Err(err) => fail!("aggregate failure: {:?}", err),
    };
    Ok(agg.to_public_key().to_bytes())
}

pub fn aggregate_public_keys_based_on_nodes_info(
    bls_pks_bytes: &[&[u8; BLS_PUBLIC_KEY_LEN]], 
    nodes_info_bytes: &[u8]
) -> Result<[u8; BLS_PUBLIC_KEY_LEN]> {
    if bls_pks_bytes.len() == 0 {
        fail!("Vector of public keys can not be empty!");
    }
    let nodes_info = NodesInfo::deserialize(nodes_info_bytes)?;
    if bls_pks_bytes.len() != nodes_info.total_num_of_nodes as usize {
        fail!("Vector of public keys is too short!");
    }
    let mut apk_pks_required_refs: Vec<&[u8; BLS_PUBLIC_KEY_LEN]> = Vec::new();
    for (index, number_of_occurrence) in &nodes_info.map {
        for _i in 0..*number_of_occurrence {
            apk_pks_required_refs.push(bls_pks_bytes[*index as usize]);
        }
    }
    let result = aggregate_public_keys(&apk_pks_required_refs)?;

    Ok(result)
}

pub fn aggregate_two_bls_signatures(sig_bytes_with_nodes_info_1: &[u8], sig_bytes_with_nodes_info_2: &[u8]) -> Result<Vec<u8>> {
    let bls_sig_1 = BlsSignature::deserialize(sig_bytes_with_nodes_info_1)?;
    let bls_sig_2 = BlsSignature::deserialize(sig_bytes_with_nodes_info_2)?;
    let new_nodes_info = NodesInfo::merge(&bls_sig_1.nodes_info, &bls_sig_2.nodes_info)?;
    let sig1 = convert_signature_bytes_to_signature(&bls_sig_1.sig_bytes)?;
    let sig2 = convert_signature_bytes_to_signature(&bls_sig_2.sig_bytes)?;
    let sig_validate_res = sig1.validate(false); //set true to exclude infinite point, i.e. zero sig
    if sig_validate_res.is_err() {
        fail!("Signature is not in group.");
    }
    let mut agg_sig = AggregateSignature::from_signature(&sig1);
    let res = AggregateSignature::add_signature(&mut agg_sig, &sig2, true);
    if res.is_err() {
        fail!("Failure while concatenate signatures");
    }
    let new_sig = agg_sig.to_signature();
    let new_agg_sig = BlsSignature {
        sig_bytes: new_sig.to_bytes(),
        nodes_info: new_nodes_info,
    };
    let new_agg_sig_bytes = BlsSignature::serialize(&new_agg_sig);
    Ok(new_agg_sig_bytes)
}

pub fn aggregate_bls_signatures(sig_bytes_with_nodes_info_vec: &[&[u8]]) -> Result<Vec<u8>> {
    if sig_bytes_with_nodes_info_vec.len() == 0 {
        fail!("Vector of signatures can not be empty!");
    }
    let mut bls_sigs: Vec<BlsSignature> = Vec::new();
    for bytes in sig_bytes_with_nodes_info_vec {
        let agg_sig = BlsSignature::deserialize(&bytes)?;
        bls_sigs.push(agg_sig);
    }

    let bls_sigs_refs: Vec<&BlsSignature> = bls_sigs.iter().map(|sig| sig).collect();
    let mut nodes_info_refs: Vec<&NodesInfo> = Vec::new();
    let mut sigs: Vec<Signature> = Vec::new();
    for i in 0..bls_sigs_refs.len() {
        nodes_info_refs.push(&bls_sigs_refs[i].nodes_info);
        let sig = convert_signature_bytes_to_signature(&bls_sigs_refs[i].sig_bytes)?;
        //return this part to exclude zero sig
       /* let res = sig.validate(true);
        if res.is_err() {
            fail!("Sig is point of infinity or does not belong to group.");
        }*/
        sigs.push(sig);
    }

    let new_nodes_info = NodesInfo::merge_multiple(&nodes_info_refs)?;

    let sig_refs: Vec<&Signature> = sigs.iter().map(|sig| sig).collect();

    let agg = match AggregateSignature::aggregate(&sig_refs, true) {
        Ok(agg) => agg,
        Err(err) => fail!("aggregate failure: {:?}", err),
    };
    let new_sig = agg.to_signature();
    let new_sig_bytes = convert_signature_to_signature_bytes(new_sig);
    let new_agg_sig = BlsSignature {
        sig_bytes: new_sig_bytes,
        nodes_info: new_nodes_info,
    };
    let new_agg_sig_bytes = BlsSignature::serialize(&new_agg_sig);
    Ok(new_agg_sig_bytes)
}

/*
    Converter
*/

pub fn convert_secret_key_bytes_to_secret_key(sk_bytes: &[u8; BLS_SECRET_KEY_LEN]) -> Result<SecretKey> {
    let sk = match SecretKey::from_bytes(sk_bytes) {
        Ok(sk) => sk,
        Err(err) => fail!("BLS secret key deserialize failure: {:?}", err),
    };
    Ok(sk)
}

pub fn convert_signature_bytes_to_signature(sig_bytes: &[u8; BLS_SIG_LEN]) -> Result<Signature> {
    let sig = match Signature::from_bytes(sig_bytes) {
        Ok(sig) => sig,
        Err(err) => fail!("BLS signature deserialize failure: {:?}", err),
    };
    Ok(sig)
}

pub fn convert_public_key_bytes_to_public_key(pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<PublicKey> {
    let pk = match PublicKey::from_bytes(pk_bytes) {
        Ok(pk) => pk,
        Err(err) => fail!("BLS public key deserialize failure: {:?}", err),
    };
    Ok(pk)
}

pub fn convert_signature_to_signature_bytes(sig: Signature) -> [u8; BLS_SIG_LEN] {
    return sig.to_bytes();
}

/*
    Keygen
*/

pub struct KeyPair {
    pub sk: SecretKey,
    pub pk: PublicKey,
}

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsKeyPair {
    pub pk_bytes: [u8; BLS_PUBLIC_KEY_LEN],
    pub sk_bytes: [u8; BLS_SECRET_KEY_LEN]
}

impl BlsKeyPair {
    pub fn print_bls_public_key(bls_pk_bytes: &[u8]) {
        if bls_pk_bytes.len() != BLS_PUBLIC_KEY_LEN{
            panic!("Incorrect length of secret key byte array!")
        }
        println!("--------------------------------------------------");
        println!("Aggregated BLS public key");
        println!("--------------------------------------------------");
        println!("Public key bytes:");
        println!("{:?}", bls_pk_bytes);
        println!("--------------------------------------------------");
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("BLS key pair:");
        println!("--------------------------------------------------");
        println!("Secret key bytes:");
        println!("{:?}", &self.sk_bytes);
        println!("Secret key len: {}", &self.sk_bytes.len());
        println!("Public key bytes:");
        println!("{:?}", &self.pk_bytes);
        println!("Public key len: {}", &self.pk_bytes.len());
        println!("--------------------------------------------------");
    }


    pub fn serialize(&self) -> ([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])  {
        (self.pk_bytes, self.sk_bytes)
    }

    pub fn deserialize(key_pair_data: &([u8; BLS_PUBLIC_KEY_LEN], [u8; BLS_SECRET_KEY_LEN])) -> Result<Self> {
        let sk = convert_secret_key_bytes_to_secret_key(&key_pair_data.1)?;
        let pk = sk.sk_to_pk();
        if key_pair_data.0 != pk.to_bytes() {
            fail!("Public key does not correspond to secret key!")
        }
        Ok(Self {
            pk_bytes: key_pair_data.0,
            sk_bytes: key_pair_data.1
        })
    }

    pub fn deserialize_based_on_secret_key(sk_bytes: &[u8; BLS_SECRET_KEY_LEN]) -> Result<Self> {
        let sk = convert_secret_key_bytes_to_secret_key(sk_bytes)?;
        let pk = sk.sk_to_pk();
        Ok(Self {
            pk_bytes: pk.to_bytes(),
            sk_bytes: sk.to_bytes()
        })
    }

    pub fn gen_bls_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<Self> {
        let key_pair = BlsKeyPair::gen_key_pair_based_on_key_material(&ikm)?;
        Ok(BlsKeyPair::convert_key_pair_to_bls_key_pair(key_pair))
    }

    pub fn gen_bls_key_pair() -> Result<Self> {
        let key_pair = BlsKeyPair::gen_key_pair()?;
        Ok(BlsKeyPair::convert_key_pair_to_bls_key_pair(key_pair))
    }

    pub fn gen_key_pair() -> Result<KeyPair> {
        let mut ikm = [0u8; BLS_KEY_MATERIAL_LEN];
        rand::thread_rng().fill_bytes(&mut ikm);
        BlsKeyPair::gen_key_pair_based_on_key_material(&ikm)
    }

    pub fn gen_key_pair_based_on_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<KeyPair> {
        if ikm.len() != BLS_KEY_MATERIAL_LEN {
            fail!("Incorrect length of key material byte array!")
        }
        if let Ok(sk) = SecretKey::key_gen(ikm, &[]) {
            let pk = sk.sk_to_pk();
            Ok(KeyPair { sk: sk, pk: pk })
        } else {
            fail!("Failed while generate key")
        }
    }

    fn convert_key_pair_to_bls_key_pair(key_pair: KeyPair) -> Self {
        return BlsKeyPair {
            sk_bytes: key_pair.sk.to_bytes(),
            pk_bytes: key_pair.pk.to_bytes(),
        };
    }
}

/*
    NodesInfo
*/

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct NodesInfo {
    pub map: HashMap<u16, u16>,
    pub total_num_of_nodes: u16,
}

impl NodesInfo {
    pub fn create_node_info(total_num_of_nodes: u16, node_index: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let mut info = HashMap::new();
        let num_of_occurrences = 1;
        info.insert(node_index, num_of_occurrences);
        Ok(Self {
            map: info,
            total_num_of_nodes,
        })
    }

    pub fn with_data(info: HashMap<u16, u16>, total_num_of_nodes: u16) -> Result<Self> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if info.len() == 0 {
            fail!("Node info should not be empty!")
        }
        for (index, number_of_occurrence) in &info {
            if *index >= total_num_of_nodes {
                fail!("Index of node can not be greater than total number of nodes!")
            }
            if *number_of_occurrence == 0 {
                fail!("Number of occurrence for node can not be zero!")
            }
        }
        let nodes_info = NodesInfo {
            map: info,
            total_num_of_nodes,
        };
        Ok(nodes_info)
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Total number of nodes: {}", &self.total_num_of_nodes);
        println!("Indexes -- occurrences: ");
        for (index, number_of_occurrence) in &self.map {
            println!("{}: \"{}\"", index, number_of_occurrence);
        }
        println!("--------------------------------------------------");
        println!("--------------------------------------------------");
    }

    pub fn merge(info1: &NodesInfo, info2: &NodesInfo) -> Result<NodesInfo> {
        if info1.total_num_of_nodes != info2.total_num_of_nodes {
            fail!("Total number of nodes must be the same!");
        }
        let mut new_info = info1.map.clone();
        for (index, number_of_occurrence) in &info2.map {
            new_info.insert(
                *index,
                if new_info.contains_key(&index) {
                    new_info[index] + *number_of_occurrence
                   } else {
                    *number_of_occurrence
                   },
            );
        }
        Ok(NodesInfo {
            map: new_info,
            total_num_of_nodes: info1.total_num_of_nodes,
        })
    }

    pub fn merge_multiple(info_vec: &[&NodesInfo]) -> Result<NodesInfo> {
        if info_vec.len() <= 1 {
            fail!("Nodes info collection must have at least two elements!!")
        }
        let mut final_nodes_info = NodesInfo::merge(&info_vec[0], &info_vec[1])?;
        for i in 2..info_vec.len() {
            final_nodes_info = NodesInfo::merge(&final_nodes_info, &info_vec[i])?;
        }
        Ok(final_nodes_info)
    }

    pub fn serialize(&self) -> Vec<u8> {
        let mut result_vec = Vec::new();
        let total_num_of_nodes = &self.total_num_of_nodes;
        let total_num_of_nodes_bytes = total_num_of_nodes.to_be_bytes();
        result_vec.extend_from_slice(&total_num_of_nodes_bytes);
        for (index, number_of_occurrence) in &self.map {
            let index_bytes = index.to_be_bytes();
            result_vec.extend_from_slice(&index_bytes);
            let number_of_occurrence_bytes = number_of_occurrence.to_be_bytes();
            result_vec.extend_from_slice(&number_of_occurrence_bytes);
        }
        result_vec
    }

    pub fn deserialize(info_bytes: &[u8]) -> Result<NodesInfo> {
        if info_bytes.len() <= 2 || (info_bytes.len() % 4) != 2 {
            fail!("node_info_bytes must have non zero length (> 2) being of form 4*k+2!");
        }
        let total_num_of_nodes = ((info_bytes[0] as u16) << 8) | info_bytes[1] as u16;
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        let mut new_info = HashMap::new();
        for i in (2..info_bytes.len()).step_by(4) {
            let index = ((info_bytes[i] as u16) << 8) | info_bytes[i + 1] as u16;
            if index >= total_num_of_nodes {
                fail!("Index can not be greater than total_num_of_nodes!");
            }
            let number_of_occurrence = ((info_bytes[i + 2] as u16) << 8) | info_bytes[i + 3] as u16;
            new_info.insert(index, number_of_occurrence);
        }

        NodesInfo::with_data(new_info, total_num_of_nodes)
    }
}

/*
    Random helpers
*/

pub fn generate_random_msg() -> Vec<u8> {
    let msg_len = rand::thread_rng().gen_range(2..100);
    let mut msg = vec![0u8; msg_len as usize];
    rand::thread_rng().fill_bytes(&mut msg);
    msg
}

pub fn generate_random_msg_of_fixed_len( msg_len: i32) -> Vec<u8> {
    let mut msg = vec![0u8; msg_len as usize];
    rand::thread_rng().fill_bytes(&mut msg);
    msg
}

pub fn gen_signer_indexes(n: u16, k: u16) -> Vec<u16> {
    let mut rng = rand::thread_rng();

    loop {
        let mut indexes = Vec::new();

        for _i in 0..k {
            indexes.push(rng.gen_range(0..n));
        }

        if indexes.len() == (k as usize) {
            return indexes;
        }
    }
}

pub fn gen_random_index(n: u16) -> u16 {
    let mut rng = rand::thread_rng();
    rng.gen_range(0..n)
}

pub fn create_random_nodes_info(total_num_of_nodes: u16, attempts: u16) -> NodesInfo{
    let indexes: Vec<u16> =  gen_signer_indexes(total_num_of_nodes, attempts);
    let mut node_info_vec = Vec::new();
    for ind in &indexes {
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, *ind).unwrap();
        node_info_vec.push(nodes_info)

    }
    let node_info_vec_refs: Vec<&NodesInfo> = node_info_vec.iter().map(|info| info).collect();
    let info = NodesInfo::merge_multiple(&node_info_vec_refs).unwrap();
    info
}

/*
    Signing
*/

pub const DST: [u8; 43] = *b"BLS_SIG_BLS12381G2_XMD:SHA-256_SSWU_RO_NUL_";

#[derive(Clone, PartialEq, Eq, Debug)]
pub struct BlsSignature {
    pub sig_bytes: [u8; BLS_SIG_LEN],
    pub nodes_info: NodesInfo,
}

impl BlsSignature {
    pub fn serialize(&self) -> Vec<u8> {
        let mut vec = Vec::new();
        vec.extend_from_slice(&self.sig_bytes);
        let nodes_info_bytes = &self.nodes_info.serialize();
        vec.extend_from_slice(&nodes_info_bytes);
        vec
    }

    pub fn deserialize(sig_bytes_with_nodes_info: &[u8]) -> Result<Self> {
        if sig_bytes_with_nodes_info.len() < BLS_SIG_LEN + 6 {
            fail!("Length of sig_bytes_with_nodes_info is too short!")
        }
        let mut sig_bytes: [u8; BLS_SIG_LEN] = [0; BLS_SIG_LEN];
        sig_bytes.copy_from_slice(&sig_bytes_with_nodes_info[0..BLS_SIG_LEN]);
        let len = sig_bytes_with_nodes_info.len() - BLS_SIG_LEN;
        let mut nodes_info_data = vec![0; len];
        nodes_info_data.copy_from_slice(&sig_bytes_with_nodes_info[BLS_SIG_LEN..]);
        let nodes_info = NodesInfo::deserialize(&nodes_info_data)?;
        Ok(Self{sig_bytes, nodes_info})
    }

    pub fn simple_sign(sk_bytes: &[u8; BLS_SECRET_KEY_LEN], msg: &[u8]) -> Result<[u8; BLS_SIG_LEN]> {
        if msg.len() == 0 {
            fail!("Msg to sign can not be empty!")
        }
        let sk = convert_secret_key_bytes_to_secret_key(sk_bytes)?;
        let sig = sk.sign(msg, &DST, &[]);
        Ok(sig.to_bytes())
    }

    pub fn simple_verify(sig_bytes: &[u8; BLS_SIG_LEN], msg: &[u8], pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN]) -> Result<bool> {
        if msg.len() == 0 {
            fail!("Msg to sign can not be empty!")
        }
        let sig = convert_signature_bytes_to_signature(sig_bytes)?;
        let pk = convert_public_key_bytes_to_public_key(pk_bytes)?;
        let res = sig.verify(true, msg, &DST, &[], &pk, true);
        Ok(res == BLST_ERROR::BLST_SUCCESS)
    }

    pub fn add_node_info_to_sig(sig_bytes: [u8; BLS_SIG_LEN], node_index: u16, total_num_of_nodes: u16) -> Result<Vec<u8>> {
        if total_num_of_nodes == 0 {
            fail!("Total number of nodes can not be zero!");
        }
        if node_index >= total_num_of_nodes {
            fail!("Index of node can not be greater than total number of nodes!");
        }
        let nodes_info = NodesInfo::create_node_info(total_num_of_nodes, node_index)?;
        let sig = Self {
            sig_bytes,
            nodes_info,
        };
        let sig_bytes = BlsSignature::serialize(&sig);
        Ok(sig_bytes)
    }

    pub fn sign(
        sk_bytes: &[u8; BLS_SECRET_KEY_LEN],
        msg: &[u8],
        node_index: u16,
        total_num_of_nodes: u16,
    ) -> Result<Vec<u8>> {
        let sig = BlsSignature::simple_sign(sk_bytes, msg)?;
        add_node_info_to_sig(sig, node_index, total_num_of_nodes)
    }

    pub fn get_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<Vec<u8>> {
        let bls_sig = BlsSignature::deserialize(sig_bytes_with_nodes_info)?;
        Ok(bls_sig.nodes_info.serialize())
    }

    pub fn truncate_nodes_info_from_sig(sig_bytes_with_nodes_info: &[u8]) -> Result<[u8; BLS_SIG_LEN]> {
        let bls_sig = BlsSignature::deserialize(sig_bytes_with_nodes_info)?;
        Ok(bls_sig.sig_bytes)
    }

    pub fn verify(sig_bytes_with_nodes_info: &[u8], pk_bytes: &[u8; BLS_PUBLIC_KEY_LEN], msg: &[u8]) -> Result<bool> {
        let sig_bytes = BlsSignature::truncate_nodes_info_from_sig(sig_bytes_with_nodes_info)?;
        let res = BlsSignature::simple_verify(&sig_bytes, msg, pk_bytes)?;
        Ok(res)
    }

    pub fn print_signature_bytes(sig_bytes: &[u8]) {
        if sig_bytes.len() != BLS_SIG_LEN {
            panic!("Incorrect length of signature byte array!")
        }
        println!("--------------------------------------------------");
        println!("BLS Signature bytes:");
        println!("--------------------------------------------------");
        println!("{:?}", sig_bytes);
        println!("--------------------------------------------------");
    }

    pub fn print_bls_signature(bls_sig_bytes: &[u8]) {
        let bls_sig = BlsSignature::deserialize(bls_sig_bytes).unwrap();
        bls_sig.print();
    }

    pub fn print(&self) {
        println!("--------------------------------------------------");
        println!("Aggregated BLS signature:");
        println!("--------------------------------------------------");
        println!("Signature bytes:");
        println!("{:?}", &self.sig_bytes);
        self.nodes_info.print();
        println!("--------------------------------------------------");
    }
}

#[cfg(test)]
#[path = "tests/test_bls.rs"]
mod tests;
