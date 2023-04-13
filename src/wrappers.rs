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

use crate::{error, fail, Result};
use aes_ctr::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use core::ops::Range;
use ed25519_dalek::Verifier;
use sha2::Digest;

// AES-CTR --------------------------------------------------------------

pub struct AesCtr {
    inner: aes_ctr::Aes256Ctr
}

impl AesCtr {

    pub fn with_params(key: &[u8], ctr: &[u8]) -> Result<Self> {
        let aes_ctr = aes_ctr::Aes256Ctr::new(
            aes_ctr::cipher::generic_array::GenericArray::from_slice(key),
            aes_ctr::cipher::generic_array::GenericArray::from_slice(ctr),
        );
        let ret = Self { 
            inner: aes_ctr 
        };
        Ok(ret)
    }

    pub fn apply_keystream(&mut self, buf: &mut [u8], range: Range<usize>) -> Result<()> {
        self.inner.apply_keystream(&mut buf[range]);
        Ok(())
    }

}

// Base-64 -------------------------------------------------------------- 

pub fn base64_decode(input: impl AsRef<[u8]>) -> Result<Vec<u8>> {
    Ok(base64::decode(input)?)
}

pub fn base64_decode_to_slice(input: impl AsRef<[u8]>, output: &mut [u8]) -> Result<()> {
    let config = base64::STANDARD;
    let result = base64::decode_config_slice(input, config, output)?;
    if output.len() != result {
        fail!("not enough bytes to decode only {}", result)
    }
    Ok(())
}

pub fn base64_encode(input: impl AsRef<[u8]>) -> String {
    base64::encode(input)
}

// Ed25519 --------------------------------------------------------------

pub struct Ed25519ExpandedPrivateKey {
    inner: ed25519_dalek::ExpandedSecretKey
}

impl Ed25519ExpandedPrivateKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner.to_bytes()
    }
}

pub struct Ed25519PrivateKey {
    inner: ed25519_dalek::SecretKey
}

impl Ed25519PrivateKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

pub struct Ed25519PublicKey {
    inner: ed25519_dalek::PublicKey
}

impl Ed25519PublicKey {
    pub fn to_bytes(&self) -> [u8; 32] {
        self.inner.to_bytes()
    }
}

pub fn ed25519_create_expanded_private_key(src: &[u8]) -> Result<Ed25519ExpandedPrivateKey> {
    let ret = Ed25519ExpandedPrivateKey {
        inner: ed25519_dalek::ExpandedSecretKey::from_bytes(src)?
    };
    Ok(ret)
}

pub fn ed25519_create_private_key(src: &[u8]) -> Result<Ed25519PrivateKey> {
    let ret = Ed25519PrivateKey {
        inner: ed25519_dalek::SecretKey::from_bytes(src)?
    };
    Ok(ret)
}

pub fn ed25519_create_public_key(src: &Ed25519ExpandedPrivateKey) -> Result<Ed25519PublicKey> {
    let ret = Ed25519PublicKey {
        inner: ed25519_dalek::PublicKey::from(&src.inner)
    };
    Ok(ret)
}

pub fn ed25519_expand_private_key(src: &Ed25519PrivateKey) -> Result<Ed25519ExpandedPrivateKey> {
    let ret = Ed25519ExpandedPrivateKey {
        inner: ed25519_dalek::ExpandedSecretKey::from(&src.inner)
    };
    Ok(ret)
}

pub fn ed25519_generate_private_key() -> Result<Ed25519PrivateKey> {
    let ret = Ed25519PrivateKey {
        inner: ed25519_dalek::SecretKey::generate(&mut rand::thread_rng())
    };
    Ok(ret)
}

pub fn ed25519_sign(
    exp_pvt_key: &[u8], 
    pub_key: Option<&[u8]>, 
    data: &[u8]
) -> Result<Vec<u8>> {
    let exp_key = ed25519_dalek::ExpandedSecretKey::from_bytes(exp_pvt_key)?;
    let pub_key = if let Some(pub_key) = pub_key {
        ed25519_dalek::PublicKey::from_bytes(pub_key)?
    } else {
        ed25519_dalek::PublicKey::from(&exp_key)
    };
    Ok(exp_key.sign(data, &pub_key).to_bytes().to_vec())
}

pub fn ed25519_verify(pub_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let pub_key = ed25519_dalek::PublicKey::from_bytes(pub_key)?;
    pub_key.verify(data, &ed25519::Signature::from_bytes(signature)?)?;
    Ok(())
}

pub fn x25519_shared_secret(exp_pvt_key: &[u8], other_pub_key: &[u8]) -> Result<[u8; 32]> {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(other_pub_key.try_into()?)
        .decompress()
        .ok_or_else(|| error!("Bad public key data"))?
        .to_montgomery()
        .to_bytes();
    Ok(x25519_dalek::x25519(exp_pvt_key.try_into()?, point))
}

// SHA-2 ----------------------------------------------------------------

pub struct Sha256 {
    inner: sha2::Sha256
}

impl Sha256 {

    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            inner: sha2::Sha256::new()
        }
    }

    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.inner.update(data)
    }

    pub fn finalize(self) -> [u8; 32] {
        self.inner.finalize().into()
    }

}

pub fn sha256_digest(data: impl AsRef<[u8]>) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub fn sha256_digest_slices(data: &[&[u8]]) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    for data in data {
        digest.update(data);
    }
    digest.finalize().into()
}

pub fn sha512_digest(data: impl AsRef<[u8]>) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

