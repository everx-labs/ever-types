/*
* Copyright 2018-2020 TON DEV SOLUTIONS LTD.
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

use crate::cell::{BuilderData, SliceData};
use num::FromPrimitive;
use sha2::Digest;
use std::{cmp, convert::TryInto, fmt, fmt::{LowerHex, UpperHex}, str::{self, FromStr}};
use smallvec::SmallVec;

pub type Result<T> = std::result::Result<T, failure::Error>;
pub type Failure = Option<failure::Error>;
pub type Status = Result<()>;

#[macro_export]
macro_rules! error {
    ($error:literal) => {
        failure::err_msg(format!("{} {}:{}", $error, file!(), line!()))
    };
    ($error:expr) => {
        failure::Error::from($error)
    };
    ($fmt:expr, $($arg:tt)+) => {
        failure::err_msg(format!("{} {}:{}", format!($fmt, $($arg)*), file!(), line!()))
    };
}

#[macro_export]
macro_rules! fail {
    ($error:literal) => {
        return Err(failure::err_msg(format!("{} {}:{}", $error, file!(), line!())))
    };
    // uncomment to explicit panic for any ExceptionCode
    // (ExceptionCode::CellUnderflow) => {
    //     panic!("{}", error!(ExceptionCode::CellUnderflow))
    // };
    ($error:expr) => {
        return Err(error!($error))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(failure::err_msg(format!("{} {}:{}", format!($fmt, $($arg)*), file!(), line!())))
    };
}

// TBD: Copy
#[derive(Clone, Copy, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct UInt256([u8; 32]);

impl PartialEq<SliceData> for UInt256 {
    fn eq(&self, other: &SliceData) -> bool {
        if other.remaining_bits() == 256 {
            return self.0 == other.get_bytestring(0).as_slice()
        }
        false
    }
}

impl PartialEq<SliceData> for &UInt256 {
    fn eq(&self, other: &SliceData) -> bool {
        if other.remaining_bits() == 256 {
            return self.0 == other.get_bytestring(0).as_slice()
        }
        false
    }
}

impl UInt256 {

    pub const fn default() -> Self { Self::new() }
    pub const fn new() -> Self {
        Self::ZERO
    }
    pub const fn with_array(data: [u8; 32]) -> Self {
        Self(data)
    }

    pub fn is_zero(&self) -> bool {
        for b in &self.0 {
            if b != &0 {
                return false
            }
        }
        true
    }

    pub const fn as_array(&self) -> &[u8; 32] {
        &self.0
    }

    pub const fn as_slice(&self) -> &[u8; 32] {
        &self.0
    }

    // Returns solid string like this: a80b23bfe4d301497f3ce11e753f23e8dec32368945ee279d044dbc1f91ace2a
    pub fn as_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    // TODO: usage should be changed to as_hex_string
    #[allow(clippy::wrong_self_convention)]
    pub fn to_hex_string(&self) -> String { self.as_hex_string() }

    // TODO: usage should be changed to str::FromStr
    // #[deprecated]
    #[allow(clippy::should_implement_trait)]
    #[cfg(not(test))]
    pub fn from_str(value: &str) -> Result<Self> { FromStr::from_str(value) }

    pub fn calc_file_hash(bytes: &[u8]) -> Self { Self::calc_sha256(bytes) }

    pub fn calc_sha256(bytes: &[u8]) -> Self {
        Self(sha2::Sha256::digest(bytes).into())
    }

    pub fn first_u64(&self) -> u64 {
        u64::from_le_bytes(self.0[0..8].try_into().unwrap())
    }

    pub fn from_raw(data: Vec<u8>, length: usize) -> Self {
        assert_eq!(length, 256);
        let hash: [u8; 32] = data.try_into().unwrap();
        Self(hash)
    }

    pub fn from_slice(value: &[u8]) -> Self {
        match value.try_into() {
            Ok(hash) => Self(hash),
            Err(_) => Self::from_le_bytes(value)
        }
    }

    pub fn from_be_bytes(value: &[u8]) -> Self {
        let mut data = [0; 32];
        let len = cmp::min(value.len(), 32);
        let offset = 32 - len;
        (0..len).for_each(|i| data[i + offset] = value[i]);
        Self(data)
    }

    pub fn from_le_bytes(value: &[u8]) -> Self {
        let mut data = [0; 32];
        let len = cmp::min(value.len(), 32);
        (0..len).for_each(|i| data[i] = value[i]);
        Self(data)
    }

    pub const fn max() -> Self {
        UInt256::MAX
    }

    pub fn rand() -> Self {
        Self((0..32).map(|_| { rand::random::<u8>() }).collect::<Vec<u8>>().try_into().unwrap())
    }

    pub fn inner(self) -> [u8; 32] {
        self.0
    }

    pub fn into_vec(self) -> Vec<u8> {
        self.0.to_vec()
    }

    pub const ZERO: UInt256 = UInt256([0; 32]);
    pub const MIN: UInt256 = UInt256([0; 32]);
    pub const MAX: UInt256 = UInt256([0xFF; 32]);
    // hash of default cell 0x96a296d224f285c67bee93c30f8a309157f0daa35dc5b87e410b78630a09cfc7;
    pub const DEFAULT_CELL_HASH: UInt256 = UInt256([150, 162, 150, 210, 36, 242, 133, 198, 123, 238, 147,
        195, 15, 138, 48, 145, 87, 240, 218, 163, 93, 197, 184, 126, 65, 11, 120, 99, 10, 9, 207, 199]);
}

impl From<[u8; 32]> for UInt256 {
    fn from(data: [u8; 32]) -> Self {
        UInt256(data)
    }
}

// TBD: use inner
impl From<UInt256> for [u8; 32] {
    fn from(data: UInt256) -> Self {
        data.0
    }
}

impl From<&[u8; 32]> for UInt256 {
    fn from(data: &[u8; 32]) -> Self {
        UInt256(*data)
    }
}

impl From<&[u8]> for UInt256 {
    fn from(value: &[u8]) -> Self { Self::from_le_bytes(value) }
}

impl From<Vec<u8>> for UInt256 {
    fn from(value: Vec<u8>) -> Self {
        match value.try_into() {
            Ok(hash) => Self(hash),
            Err(value) => UInt256::from_le_bytes(value.as_slice())
        }
    }
}

impl FromStr for UInt256 {
    type Err = failure::Error;
    fn from_str(value: &str) -> Result<Self> {
        let bytes = match value.len() {
            64 => hex::decode(value)?,
            66 => hex::decode(&value[2..])?,
            44 => base64::decode(value)?,
            len => fail!("invalid account ID string length (64 expected), but got {} for string {}", len, value)
        };
        match bytes.try_into() {
            Ok(bytes) => Ok(Self(bytes)),
            Err(bytes) => fail!("array length is {} for {}", bytes.len(), value)
        }
    }
}

impl fmt::Debug for UInt256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        LowerHex::fmt(self, f)
    }
}

impl fmt::Display for UInt256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "UInt256[{:X?}]", self.as_slice()
        )
    }    
}

impl LowerHex for UInt256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x{}", hex::encode(&self.0))
        } else {
            write!(f, "{}", hex::encode(&self.0))
            // write!(f, "{}...{}", hex::encode(&self.0[..2]), hex::encode(&self.0[30..32]))
        }
    }
}

impl UpperHex for UInt256 {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if f.alternate() {
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode_upper(&self.0))
    }
}

impl AsRef<[u8; 32]> for UInt256 {
    fn as_ref(&self) -> &[u8; 32] {
        &self.0
    }
}

impl AsRef<[u8]> for UInt256 {
    fn as_ref(&self) -> &[u8] {
        &self.0
    }
}

pub type AccountId = SliceData;

impl From<[u8; 32]> for AccountId {
    fn from(data: [u8; 32]) -> AccountId {
        BuilderData::with_raw(SmallVec::from_slice(&data), 256).unwrap().into_cell().unwrap().into()
    }
}

impl From<UInt256> for AccountId {
    fn from(data: UInt256) -> AccountId {
        BuilderData::with_raw(SmallVec::from_slice(&data.0), 256).unwrap().into_cell().unwrap().into()
    }
}

impl From<&UInt256> for AccountId {
    fn from(data: &UInt256) -> AccountId {
        BuilderData::with_raw(SmallVec::from_slice(&data.0), 256).unwrap().into_cell().unwrap().into()
    }
}

impl FromStr for AccountId {
    type Err = failure::Error;
    fn from_str(s: &str) -> Result<Self> {
        let uint: UInt256 = FromStr::from_str(s)?;
        Ok(AccountId::from(uint.0))
    }
}

// Exceptions *****************************************************************

#[derive(Clone, Copy, Debug, num_derive::FromPrimitive, PartialEq, Eq, failure::Fail)]
pub enum ExceptionCode {
    #[fail(display = "normal termination")]
    NormalTermination = 0,
    #[fail(display = "alternative termination")]
    AlternativeTermination = 1,
    #[fail(display = "stack underflow")]
    StackUnderflow = 2,
    #[fail(display = "stack overflow")]
    StackOverflow = 3,
    #[fail(display = "integer overflow")]
    IntegerOverflow = 4,
    #[fail(display = "range check error")]
    RangeCheckError = 5,
    #[fail(display = "invalid opcode")]
    InvalidOpcode = 6,
    #[fail(display = "type check error")]
    TypeCheckError = 7,
    #[fail(display = "cell overflow")]
    CellOverflow = 8,
    #[fail(display = "cell underflow")]
    CellUnderflow = 9,
    #[fail(display = "dictionaty error")]
    DictionaryError = 10,
    #[fail(display = "unknown error")]
    UnknownError = 11,
    #[fail(display = "fatal error")]
    FatalError = 12,
    #[fail(display = "out of gas")]
    OutOfGas = 13
}

/*
impl fmt::Display for ExceptionCode {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{}", self.message())
    }
}
*/

#[rustfmt::skip]
impl ExceptionCode {
/*
    pub fn message(&self) -> &'static str {
        match self {
            ExceptionCode::NormalTermination        => "normal termination",
            ExceptionCode::AlternativeTermination   => "alternative termination",
            ExceptionCode::StackUnderflow           => "stack underflow",
            ExceptionCode::StackOverflow            => "stack overflow",
            ExceptionCode::IntegerOverflow          => "integer overflow",
            ExceptionCode::RangeCheckError          => "range check error",
            ExceptionCode::InvalidOpcode            => "invalid opcode",
            ExceptionCode::TypeCheckError           => "type check error",
            ExceptionCode::CellOverflow             => "cell overflow",
            ExceptionCode::CellUnderflow            => "cell underflow",
            ExceptionCode::DictionaryError          => "dictionary error",
            ExceptionCode::UnknownError             => "unknown error",
            ExceptionCode::FatalError               => "fatal error",
            ExceptionCode::OutOfGas                 => "out of gas error"
        }
    }
*/
    pub fn from_usize(number: usize) -> Option<ExceptionCode> {
        FromPrimitive::from_usize(number)
    }
}

pub trait ByteOrderRead {
    fn read_be_uint(&mut self, bytes: usize) -> std::io::Result<u64>;
    fn read_byte(&mut self) -> std::io::Result<u8>;
    fn read_be_u16(&mut self) -> std::io::Result<u16>;
    fn read_be_u32(&mut self) -> std::io::Result<u32>;
    fn read_be_u64(&mut self) -> std::io::Result<u64>;
    fn read_le_u16(&mut self) -> std::io::Result<u16>;
    fn read_le_u32(&mut self) -> std::io::Result<u32>;
    fn read_le_u64(&mut self) -> std::io::Result<u64>;
    fn read_u256(&mut self) -> std::io::Result<[u8; 32]>;
}

impl<T: std::io::Read> ByteOrderRead for T {
    fn read_be_uint(&mut self, bytes: usize) -> std::io::Result<u64> {
        match bytes {
            1 => {
                let mut buf = [0];
                self.read_exact(&mut buf)?;
                Ok(buf[0] as u64)
            }
            2 => {
                let mut buf = [0; 2];
                self.read_exact(&mut buf)?;
                Ok(u16::from_be_bytes(buf) as u64)
            }
            3..=4 => {
                let mut buf = [0; 4];
                self.read_exact(&mut buf[4 - bytes..])?;
                Ok(u32::from_be_bytes(buf) as u64)
            },
            5..=8 => {
                let mut buf = [0; 8];
                self.read_exact(&mut buf[8 - bytes..])?;
                Ok(u64::from_be_bytes(buf))
            },
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many bytes to read in u64")),
        }
    }

    fn read_byte(&mut self) -> std::io::Result<u8> {
        self.read_be_uint(1).map(|value| value as u8)
    }

    fn read_be_u16(&mut self) -> std::io::Result<u16> {
        self.read_be_uint(2).map(|value| value as u16)
    }

    fn read_be_u32(&mut self) -> std::io::Result<u32> {
        self.read_be_uint(4).map(|value| value as u32)
    }

    fn read_be_u64(&mut self) -> std::io::Result<u64> {
        self.read_be_uint(8)
    }

    fn read_le_u16(&mut self) -> std::io::Result<u16> {
        let mut buf = [0; 2];
        self.read_exact(&mut buf)?;
        Ok(u16::from_le_bytes(buf))
    }

    fn read_le_u32(&mut self) -> std::io::Result<u32> {
        let mut buf = [0; 4];
        self.read_exact(&mut buf)?;
        Ok(u32::from_le_bytes(buf))
    }

    fn read_le_u64(&mut self) -> std::io::Result<u64> {
        let mut buf = [0; 8];
        self.read_exact(&mut buf)?;
        Ok(u64::from_le_bytes(buf))
    }

    fn read_u256(&mut self) -> std::io::Result<[u8; 32]> {
        let mut buf = [0; 32];
        self.read_exact(&mut buf)?;
        Ok(buf)
    }
}

pub type Bitmask = u8;

