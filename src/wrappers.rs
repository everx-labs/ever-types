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
use sha2::Digest;

pub fn sha256_digest(data: impl AsRef<[u8]>) -> [u8; 32] {
    sha2::Sha256::digest(data).into()
}

pub fn sha256_digest2(data: &[&[u8]]) -> [u8; 32] {
    let mut digest = sha2::Sha256::new();
    for data in data {
        digest.update(data);
    }
    digest.finalize().into()
}

pub fn sha512_digest(data: impl AsRef<[u8]>) -> [u8; 64] {
    sha2::Sha512::digest(data).into()
}

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
