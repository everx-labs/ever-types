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

use crate::cell::SliceData;
use std::fmt;
use std::str;
use std::cmp;
use num::FromPrimitive;
use std::fmt::{LowerHex, UpperHex};


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
    ($error:expr) => {
        return Err(error!($error))
    };
    ($fmt:expr, $($arg:tt)*) => {
        return Err(failure::err_msg(format!("{} {}:{}", format!($fmt, $($arg)*), file!(), line!())))
    };
}

#[derive(Clone, Default, PartialEq, Eq, Hash, Ord, PartialOrd)]
pub struct UInt256([u8; 32]);

impl PartialEq<SliceData> for UInt256 {
    fn eq(&self, other: &SliceData) -> bool {
        if other.remaining_bits() == 256 {
            return &self.0 == other.get_bytestring(0).as_slice()
        }
        return false
    }
}

impl UInt256 {
    pub fn is_zero(&self) -> bool {
        for b in &self.0 {
            if b != &0 {
                return false
            }
        }
        true
    }

    pub fn as_slice(&self) -> &[u8;32] {
        &self.0
    }

    // Returns solid string like this: a80b23bfe4d301497f3ce11e753f23e8dec32368945ee279d044dbc1f91ace2a
    pub fn to_hex_string(&self) -> String {
        hex::encode(self.0)
    }

    pub fn max() -> Self {
        Self::from([0xFF; 32])
    }
}

impl From<[u8;32]> for UInt256 {
    fn from(data: [u8;32]) -> Self {
        UInt256(data)
    }
}

impl Into<[u8;32]> for UInt256 {
    fn into(self) -> [u8; 32] {
        self.0
    }
}

impl<'a> Into<&'a [u8;32]> for &'a UInt256 {
    fn into(self) -> &'a [u8; 32] {
        &self.0
    }
}

impl<'a> From<&'a [u8;32]> for UInt256 {
    fn from(data: &[u8;32]) -> Self {
        UInt256(data.clone())
    }
}

impl From<&[u8]> for UInt256 {
    fn from(value: &[u8]) -> Self {
        let mut data = [0; 32];
        let len = cmp::min(value.len(), 32);
        (0..len).for_each(|i| data[i] = value[i]);
        Self(data)
    }
}

impl From<Vec<u8>> for UInt256 {
    fn from(value: Vec<u8>) -> Self {
        UInt256::from(value.as_slice())
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
            write!(f, "0x")?;
        }
        write!(f, "{}", hex::encode(&self.0))
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

impl str::FromStr for UInt256 {
    type Err = failure::Error;
    fn from_str(value: &str) -> Result<Self> {
        if value.len() != 64 {
            fail!(ParseAccountIdError::SizeError)
        } else {
            let mut data: [u8;32] = [0;32];
            for i in 0..data.len() {
                let hex = &value[2*i..2+2*i];
                data[i] = u8::from_str_radix(hex, 16).map_err(|_| ParseAccountIdError::HexError)?;
            }
            Ok(UInt256::from(data))
        }
    }
}

impl std::convert::AsRef<[u8]> for &UInt256 {
    fn as_ref(&self) -> &[u8] {
        self.as_slice()
    }
}

pub type AccountId = SliceData;

impl From<[u8; 32]> for AccountId {
    fn from(data: [u8; 32]) -> AccountId {
        let data = data.to_vec();
        SliceData::from_raw(data, 256)
    }
}

impl From<UInt256> for AccountId {
    fn from(data: UInt256) -> AccountId {
        let data = data.0.to_vec();
        SliceData::from_raw(data, 256)
    }
}

impl str::FromStr for AccountId {
    type Err = failure::Error;
    fn from_str(value: &str) -> Result<Self> {
        let uint = UInt256::from_str(value)?;
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

#[cfg_attr(rustfmt, rustfmt_skip)]
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

#[derive(Debug, failure::Fail)]
pub enum ParseAccountIdError {
    #[fail(display = "invalid account ID string length (64 expected)")]
    SizeError,
    #[fail(display = "invalid character while parsing account ID hex string")]
    HexError
}

/*
impl fmt::Display for ParseAccountIdError {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "{}",
            match self {
                ParseAccountIdError::SizeError => "invalid string length (64 expected)",
                ParseAccountIdError::HexError => "invalid character while parsing hex string"
            }
        )
    }
}
*/

pub trait ByteOrderRead {
    fn read_be_uint(&mut self, bytes: usize) -> std::io::Result<usize>;
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
    fn read_be_uint(&mut self, bytes: usize) -> std::io::Result<usize> {
        match bytes {
            1 => {
                let mut buf = [0];
                self.read_exact(&mut buf)?;
                Ok(buf[0] as usize)
            }
            2 => {
                let mut buf = [0; 2];
                self.read_exact(&mut buf)?;
                Ok(u16::from_be_bytes(buf) as usize)
            }
            3..=4 => {
                let mut buf = [0; 4];
                self.read_exact(&mut buf[4 - bytes..])?;
                Ok(u32::from_be_bytes(buf) as usize)
            },
            5..=8 => {
                let mut buf = [0; 8];
                self.read_exact(&mut buf[8 - bytes..])?;
                Ok(u64::from_be_bytes(buf) as usize)
            },
            _ => Err(std::io::Error::new(std::io::ErrorKind::InvalidInput, "too many bytes to read in usize")),
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
        self.read_be_uint(8).map(|value| value as u64)
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
