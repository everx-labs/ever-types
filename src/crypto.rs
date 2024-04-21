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

use crate::{
    fail, Result, base64_decode, base64_encode, ed25519_create_expanded_private_key, 
    ed25519_create_private_key, ed25519_create_public_key, ed25519_expand_private_key, 
    ed25519_generate_private_key, ed25519_verify, ed25519_sign, Ed25519ExpandedPrivateKey, 
    Ed25519PrivateKey, sha256_digest_slices, x25519_shared_secret
};
use std::{convert::TryInto, fmt::{self, Debug, Display, Formatter}, sync::Arc};
use super::bls::{BLS_PUBLIC_KEY_LEN, BLS_SECRET_KEY_LEN, BLS_KEY_MATERIAL_LEN};

pub trait KeyOption: Sync + Send + Debug {
    fn id(&self) -> &Arc<KeyId>;
    fn type_id(&self) -> i32;
    fn pub_key(&self) -> Result<&[u8]>;
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>>;
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()>;
    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]>;
    fn shared_secret(&self, other_pub_key: &[u8]) -> Result<[u8; 32]>;
}

#[derive(Debug)]
pub struct Ed25519KeyOption {
    id: Arc<KeyId>,
    pub_key: Option<[u8; Self::PUB_KEY_SIZE]>,
    exp_key: Option<[u8; Self::EXP_KEY_SIZE]>,
}

impl Ed25519KeyOption {

    pub const KEY_TYPE: i32 = 1209251014;
    pub const EXP_KEY_SIZE: usize = 64;
    pub const PVT_KEY_SIZE: usize = 32;
    pub const PUB_KEY_SIZE: usize = 32;

    /// Create from Ed25519 expanded secret key raw data
    pub fn from_expanded_key(exp_key: &[u8; Self::EXP_KEY_SIZE]) -> Result<Arc<dyn KeyOption>> {
        Self::create_from_expanded_key(ed25519_create_expanded_private_key(exp_key)?)
    }

    /// Create from Ed25519 secret key raw data
    pub fn from_private_key(pvt_key: &[u8; Self::PVT_KEY_SIZE]) -> Result<Arc<dyn KeyOption>> {
        Self::create_from_expanded_key(
            ed25519_expand_private_key(&ed25519_create_private_key(pvt_key)?)?
        )
    }

    /// Create from Ed25519 secret key raw data and export JSON
    pub fn from_private_key_with_json(
        pvt_key: &[u8; Self::PVT_KEY_SIZE],
    ) -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        Self::create_from_private_key_with_json(ed25519_create_private_key(pvt_key)?)
    }

    /// Create from Ed25519 secret key JSON
    pub fn from_private_key_json(src: &KeyOptionJson) -> Result<Arc<dyn KeyOption>> {
        match src.type_id {
            Self::KEY_TYPE => match &src.pvt_key {
                Some(key) => {
                    if src.pub_key.is_some() {
                        fail!("No public key expected");
                    }
                    let key = base64_decode(key)?;
                    if key.len() != Self::PVT_KEY_SIZE {
                        fail!("Bad private key");
                    }
                    Self::from_private_key(key.as_slice().try_into()?)
                }
                None => fail!("No private key"),
            },
            _ => fail!(
                "Type-id {} is not supported for Ed25519 private key",
                src.type_id
            ),
        }
    }

    /// Create from Ed25519 public key raw data
    pub fn from_public_key(pub_key: &[u8; Self::PUB_KEY_SIZE]) -> Arc<dyn KeyOption> {
        Arc::new(Self {
            id: Self::calc_id(Self::KEY_TYPE, pub_key),
            pub_key: Some(*pub_key),
            exp_key: None,
        })
    }

    /// Create from Ed265519 public key JSON
    pub fn from_public_key_json(src: &KeyOptionJson) -> Result<Arc<dyn KeyOption>> {
        match src.type_id {
            Self::KEY_TYPE => match &src.pub_key {
                Some(key) => {
                    if src.pvt_key.is_some() {
                        fail!("No private key expected");
                    }
                    let key = base64_decode(key)?;
                    if key.len() != Self::PUB_KEY_SIZE {
                        fail!("Bad public key");
                    }
                    Ok(Self::from_public_key(key.as_slice().try_into()?))
                }
                None => fail!("No public key"),
            },
            _ => fail!(
                "Type-id {} is not supported for Ed25519 public key",
                src.type_id
            ),
        }
    }

    /// Generate new Ed25519 key
    pub fn generate() -> Result<Arc<dyn KeyOption>> {
        Self::create_from_expanded_key(
            ed25519_expand_private_key(&ed25519_generate_private_key()?)?
        )
    }

    /// Generate new Ed25519 key and export JSON
    pub fn generate_with_json() -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        Self::create_from_private_key_with_json(ed25519_generate_private_key()?)
    }

    fn create_from_expanded_key(
        exp_key: Ed25519ExpandedPrivateKey
    ) -> Result<Arc<dyn KeyOption>> {
        let pub_key = ed25519_create_public_key(&exp_key)?.to_bytes();
        let exp_key = exp_key.to_bytes();
        let ret = Self {
            id: Self::calc_id(Self::KEY_TYPE, &pub_key),
            pub_key: Some(pub_key),
            exp_key: Some(exp_key),
        };
        Ok(Arc::new(ret))
    }

    fn create_from_private_key_with_json(
        pvt_key: Ed25519PrivateKey
    ) -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        let ret = Self::create_from_expanded_key(ed25519_expand_private_key(&pvt_key)?)?;
        let json = KeyOptionJson {
            type_id: Self::KEY_TYPE,
            pub_key: None,
            pvt_key: Some(base64_encode(pvt_key.to_bytes())),
        };
        Ok((json, ret))
    }

    // Calculate key ID
    fn calc_id(type_id: i32, pub_key: &[u8; Self::PUB_KEY_SIZE]) -> Arc<KeyId> {
        let data = sha256_digest_slices(&[&type_id.to_le_bytes(), pub_key]);
        KeyId::from_data(data)
    }

    fn exp_key(&self) -> Result<&[u8; Self::EXP_KEY_SIZE]> {
        if let Some(exp_key) = self.exp_key.as_ref() {
            Ok(exp_key)
        } else {
            fail!("No expansion key set for key option {}", self.id())
        }
    }
}

impl KeyOption for Ed25519KeyOption {

    /// Get key id
    fn id(&self) -> &Arc<KeyId> {
        &self.id
    }

    /// Get type id
    fn type_id(&self) -> i32 {
        Self::KEY_TYPE
    }

    /// Get public key
    fn pub_key(&self) -> Result<&[u8]> {
        if let Some(pub_key) = self.pub_key.as_ref() {
            Ok(pub_key)
        } else {
            fail!("No public key set for key option {}", self.id())
        }
    }

    /// Calculate signature
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        ed25519_sign(self.exp_key()?, self.pub_key().ok(), data)
    }

    /// Verify signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        ed25519_verify(self.pub_key()?, data, signature)
    }

    /// Calculate shared secret
    fn shared_secret(&self, other_pub_key: &[u8]) -> Result<[u8; 32]> {
        x25519_shared_secret(self.exp_key()?, other_pub_key)
    }

    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]> {
        Ok(self.exp_key()?)
    }

}

#[derive(Debug)]
pub struct BlsKeyOption {
    id: Arc<KeyId>,
    pub_key: [u8; BLS_PUBLIC_KEY_LEN],
    pvt_key: Option<[u8; BLS_SECRET_KEY_LEN]>
}

impl BlsKeyOption {
    pub const KEY_TYPE: i32 = 7;

    pub fn generate_with_json() -> Result<(KeyOptionJson, Arc<dyn KeyOption>)> {
        let key = Self::generate()?;
        let json = KeyOptionJson {
            type_id: Self::KEY_TYPE,
            pub_key: Some(base64::encode(key.pub_key)),
            pvt_key: key.pvt_key.map(base64::encode)
        };

        Ok((json, Arc::new(key)))
    }

    pub fn from_key_material(ikm: &[u8; BLS_KEY_MATERIAL_LEN]) -> Result<Self> {
        let (pub_key, pvt_key) = super::bls::gen_bls_key_pair_based_on_key_material(ikm)?;
        Ok(Self {
            id: Self::calc_id(&pub_key),
            pub_key,
            pvt_key: Some(pvt_key)
        })
    }

    pub fn from_private_key_json(json: &KeyOptionJson) -> Result<Arc<dyn KeyOption>> {
        let pub_key: [u8; BLS_PUBLIC_KEY_LEN] = match &json.pub_key {
            Some(pub_key) => {
                let pub_key = base64::decode(pub_key)?;
                pub_key.as_slice().try_into()?
            },
            None => fail!("Bad public key")
        };

        let pvt_key: [u8; BLS_SECRET_KEY_LEN] = match &json.pvt_key {
            Some(pvt_key) => {
                let pvt_key = base64::decode(pvt_key)?;
                pvt_key.as_slice().try_into()?
            },
            None => fail!("Bad private key")
        };

        Ok(Arc::new(Self {
            id: Self::calc_id(&pub_key),
            pub_key,
            pvt_key: Some(pvt_key)
        }))
    }

    pub fn from_public_key(pub_key: [u8; BLS_PUBLIC_KEY_LEN]) -> Arc<dyn KeyOption> {
        Arc::new(
            Self {
                id: Self::calc_id(&pub_key), 
                pub_key, 
                pvt_key: None
            }
        )
    }

    fn generate() -> Result<Self> {
        let (pub_key, pvt_key) = super::bls::gen_bls_key_pair()?;
        Ok(Self {
            id: Self::calc_id(&pub_key),
            pub_key,
            pvt_key: Some(pvt_key)
        })
    }

    fn calc_id(pub_key: &[u8; BLS_PUBLIC_KEY_LEN]) -> Arc<KeyId> {
        let data = sha256_digest_slices(&[pub_key]);
        KeyId::from_data(data)
    }

    fn pvt_key(&self) -> Result<&[u8; BLS_SECRET_KEY_LEN]> {
        match &self.pvt_key {
            Some(pvt_key) => Ok(pvt_key), 
            None => fail!("private bls key was not found!")
        }
    }
}

impl KeyOption for BlsKeyOption {
    /// Get key id
    fn id(&self) -> &Arc<KeyId> {
        &self.id
    }
    /// Get type id 
    fn type_id(&self) -> i32 {
        Self::KEY_TYPE
    }

    /// Get public key
    fn pub_key(&self) -> Result<&[u8]> {
        Ok(self.pub_key.as_ref())
    }

    /// Calculate simple signature
    fn sign(&self, data: &[u8]) -> Result<Vec<u8>> {
        let sign = super::bls::sign(self.pvt_key()?, data)?;
        Ok(sign.into())
    }

    /// Verify signature
    fn verify(&self, data: &[u8], signature: &[u8]) -> Result<()> {
        let status = super::bls::verify(
            signature.try_into()?, 
            data, &self.pub_key
        )?;

        if !status {
            fail!("bad signature!");
        }

        Ok(())
    }

    #[cfg(feature = "export_key")]
    fn export_key(&self) -> Result<&[u8]> {
        match self.pvt_key.as_ref() {
            Some(pvt_key) => Ok(pvt_key),
            None => fail!("pvt_key is None")
        }
    }

    fn shared_secret(&self, _other_pub_key: &[u8]) -> Result<[u8; 32]> {
        fail!("shared_secret not implemented for BlsKeyOption!")
    }

}

/// ADNL key ID (node ID)
#[derive(Debug, Eq, Hash, Ord, PartialEq, PartialOrd, serde::Serialize, serde::Deserialize)]
pub struct KeyId([u8; 32]);

impl KeyId {
    pub fn from_data(data: [u8; 32]) -> Arc<Self> {
        Arc::new(Self(data))
    }
    pub fn data(&self) -> &[u8; 32] {
        &self.0
    }
}

impl Display for KeyId {
    fn fmt(&self, f: &mut Formatter) -> fmt::Result {
        write!(f, "{}", base64_encode(self.data()))
    }
}

#[derive(serde::Deserialize, serde::Serialize)]
pub struct KeyOptionJson {
    type_id: i32,
    pub_key: Option<String>,
    pvt_key: Option<String>,
}

impl KeyOptionJson {
    pub fn type_id(&self) -> &i32 {
        &self.type_id
    }
}
