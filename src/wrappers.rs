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

use crate::{error, fail, Result};
use aes_ctr::cipher::stream::{NewStreamCipher, SyncStreamCipher};
use core::ops::Range;
use crc::{Crc, CRC_32_ISCSI};
use ed25519_dalek::{SecretKey, Verifier, VerifyingKey, SigningKey, Signer};
use sha2::Digest;

pub use ed25519_dalek::SIGNATURE_LENGTH as ED25519_SIGNATURE_LENGTH;
pub use ed25519_dalek::SECRET_KEY_LENGTH as ED25519_SECRET_KEY_LENGTH;
pub use ed25519_dalek::PUBLIC_KEY_LENGTH as ED25519_PUBLIC_KEY_LENGTH;

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

pub fn base64_encode_url_safe(input: impl AsRef<[u8]>) -> String {
    base64::encode_config(input, base64::URL_SAFE)
}

// Ed25519 --------------------------------------------------------------

pub struct Ed25519ExpandedPrivateKey {
    // Currently, ed25519_dalek::hazmat::ExpandedSecretKey can't be
    // converted back to bytes, so we have to have a raw slice here
    inner: [u8; 64]
}

impl Ed25519ExpandedPrivateKey {
    pub fn to_bytes(&self) -> [u8; 64] {
        self.inner
    }
}

pub struct Ed25519PrivateKey {
    inner: SecretKey
}

impl Ed25519PrivateKey {
    pub fn to_bytes(&self) -> [u8; ED25519_SECRET_KEY_LENGTH] {
        self.inner
    }
    pub fn as_bytes(&self) -> &[u8; ED25519_SECRET_KEY_LENGTH] {
        &self.inner
    }
    pub fn sign(&self, data: &[u8]) -> [u8; ED25519_SIGNATURE_LENGTH] {
        let signing_key = SigningKey::from(&self.inner);
        signing_key.sign(data).to_bytes()
    }
    pub fn verifying_key(&self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        let signing_key = SigningKey::from(&self.inner);
        VerifyingKey::from(&signing_key).to_bytes()
    }
}

pub struct Ed25519PublicKey {
    inner: VerifyingKey
}

impl Ed25519PublicKey {
    pub fn as_bytes(&self) -> &[u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.inner.as_bytes()
    }
    pub fn to_bytes(&self) -> [u8; ED25519_PUBLIC_KEY_LENGTH] {
        self.inner.to_bytes()
    }
    pub fn from_bytes(bytes: &[u8; ED25519_PUBLIC_KEY_LENGTH]) -> Result<Self> {
        Ok(Self { inner: VerifyingKey::from_bytes(bytes)? })
    }
    pub fn verify(&self, data: &[u8], signature: &[u8; ED25519_SIGNATURE_LENGTH]) -> bool {
        self.inner.verify(data, &ed25519::Signature::from_bytes(signature)).is_ok()
    }
}

pub fn ed25519_create_expanded_private_key(src: &[u8]) -> Result<Ed25519ExpandedPrivateKey> {
    let ret = Ed25519ExpandedPrivateKey {
        inner: src.try_into()?
    };
    Ok(ret)
}

pub fn ed25519_create_private_key(src: &[u8]) -> Result<Ed25519PrivateKey> {
    let ret = Ed25519PrivateKey {
        inner: src.try_into()?
    };
    Ok(ret)
}

pub fn ed25519_create_public_key(src: &Ed25519ExpandedPrivateKey) -> Result<Ed25519PublicKey> {
    let exp_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(&src.inner);
    let ret = Ed25519PublicKey {
        inner: VerifyingKey::from(&exp_key)
    };
    Ok(ret)
}

pub fn ed25519_expand_private_key(src: &Ed25519PrivateKey) -> Result<Ed25519ExpandedPrivateKey> {
    let bytes = sha2::Sha512::default().chain_update(src.inner).finalize();
    let ret = Ed25519ExpandedPrivateKey {
        inner: bytes.into()
    };
    Ok(ret)
}

pub fn ed25519_generate_private_key() -> Result<Ed25519PrivateKey> {
    let ret = Ed25519PrivateKey {
        inner: SigningKey::generate(&mut rand::thread_rng()).to_bytes()
    };
    Ok(ret)
}

pub fn ed25519_sign_with_secret(secret_key: &[u8], data: &[u8]) -> Result<[u8; ED25519_SIGNATURE_LENGTH]> {
    let signing_key = SigningKey::from_bytes(secret_key.try_into()?);
    Ok(signing_key.sign(data).to_bytes())
}

pub fn ed25519_sign(
    exp_pvt_key: &[u8], 
    pub_key: Option<&[u8]>, 
    data: &[u8]
) -> Result<Vec<u8>> {
    let exp_key = ed25519_dalek::hazmat::ExpandedSecretKey::from_bytes(exp_pvt_key.try_into()?);
    let pub_key = if let Some(pub_key) = pub_key {
        VerifyingKey::from_bytes(pub_key.try_into()?)?
    } else {
        VerifyingKey::from(&exp_key)
    };
    Ok(ed25519_dalek::hazmat::raw_sign::<sha2::Sha512>(&exp_key, data, &pub_key).to_vec())
}

pub fn ed25519_verify(pub_key: &[u8], data: &[u8], signature: &[u8]) -> Result<()> {
    let pub_key = VerifyingKey::from_bytes(pub_key.try_into()?)?;
    pub_key.verify(data, &ed25519::Signature::from_bytes(signature.try_into()?))?;
    Ok(())
}

pub fn x25519_shared_secret(exp_pvt_key: &[u8], other_pub_key: &[u8]) -> Result<[u8; 32]> {
    let point = curve25519_dalek::edwards::CompressedEdwardsY(other_pub_key.try_into()?)
        .decompress()
        .ok_or_else(|| error!("Bad public key data"))?
        .to_montgomery()
        .to_bytes();
    Ok(x25519_dalek::x25519(exp_pvt_key[..32].try_into()?, point))
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

const CASTAGNOLI: Crc<u32> = Crc::<u32>::new(&CRC_32_ISCSI);

pub struct Crc32<'a> {
    hasher: crc::Digest<'a, u32>
}

impl<'a> Crc32<'a> {
    #[allow(clippy::new_without_default)]
    pub fn new() -> Self {
        Self {
            hasher: CASTAGNOLI.digest()
        }
    }
    pub fn update(&mut self, data: impl AsRef<[u8]>) {
        self.hasher.update(data.as_ref())
    }
    pub fn finalize(self) -> u32 {
        self.hasher.finalize()
    }
}

pub fn crc32_digest(data: impl AsRef<[u8]>) -> u32 {
    CASTAGNOLI.checksum(data.as_ref())
}
