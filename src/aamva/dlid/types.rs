use std::{fmt, io, marker::PhantomData, ops::Deref};

#[derive(Debug, thiserror::Error)]
#[error("invalid field value: {0}")]
pub struct InvalidFieldValue(MaybeAscii);

struct MaybeAscii(Vec<u8>);

impl fmt::Display for MaybeAscii {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.iter().all(u8::is_ascii) {
            write!(f, "{:?}", std::str::from_utf8(&self.0).unwrap())
        } else {
            write!(f, "{:?}", self.0)
        }
    }
}

impl fmt::Debug for MaybeAscii {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.0.iter().all(u8::is_ascii) {
            write!(f, "{:?}", std::str::from_utf8(&self.0).unwrap())
        } else {
            write!(f, "{:?}", self.0)
        }
    }
}

impl From<InvalidFieldValue> for io::Error {
    fn from(_value: InvalidFieldValue) -> Self {
        io::ErrorKind::InvalidData.into()
    }
}

/// ASCII character class.
///
/// # Safety
///
/// The `contains` function must return only for ASCII bytes.
pub unsafe trait CharClass {
    fn contains(c: u8) -> bool;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Alpha;

unsafe impl CharClass for Alpha {
    fn contains(c: u8) -> bool {
        c.is_ascii_alphabetic()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Numeric;

unsafe impl CharClass for Numeric {
    fn contains(c: u8) -> bool {
        c.is_ascii_digit()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlphaNumeric;

unsafe impl CharClass for AlphaNumeric {
    fn contains(c: u8) -> bool {
        c.is_ascii_alphanumeric()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct AlphaNumericSpecial;

unsafe impl CharClass for AlphaNumericSpecial {
    fn contains(c: u8) -> bool {
        c.is_ascii()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Fixed<C: CharClass, const N: usize> {
    data: [u8; N],
    class: PhantomData<C>,
}

impl<C: CharClass, const N: usize> Fixed<C, N> {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, InvalidFieldValue> {
        let bytes = value.as_ref();
        if bytes.len() != N {
            return Err(InvalidFieldValue(MaybeAscii(bytes.to_owned())));
        }

        if !bytes.iter().copied().all(C::contains) {
            return Err(InvalidFieldValue(MaybeAscii(bytes.to_owned())));
        }

        let mut data = [0u8; N];
        data.copy_from_slice(bytes);

        Ok(Self {
            data,
            class: PhantomData,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: the character class `C` ensures that all bytes are in the
            //         ASCII range.
            std::str::from_utf8_unchecked(self.as_bytes())
        }
    }
}

impl<C: CharClass, const N: usize> Deref for Fixed<C, N> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Hash)]
pub struct Variable<C: CharClass, const N: usize> {
    data: [u8; N],
    len: usize,
    class: PhantomData<C>,
}

impl<C: CharClass, const N: usize> Variable<C, N> {
    pub fn new(value: impl AsRef<[u8]>) -> Result<Self, InvalidFieldValue> {
        let bytes = value.as_ref();
        let len = bytes.len();
        if len > N {
            return Err(InvalidFieldValue(MaybeAscii(bytes.to_owned())));
        }

        if !bytes.iter().copied().all(C::contains) {
            return Err(InvalidFieldValue(MaybeAscii(bytes.to_owned())));
        }

        let mut data = [0u8; N];
        data[..len].copy_from_slice(bytes);

        Ok(Self {
            data,
            len,
            class: PhantomData,
        })
    }

    pub fn as_bytes(&self) -> &[u8] {
        &self.data[..self.len]
    }

    pub fn as_str(&self) -> &str {
        unsafe {
            // SAFETY: the character class `C` ensures that all bytes are in the
            //         ASCII range.
            std::str::from_utf8_unchecked(self.as_bytes())
        }
    }
}

impl<C: CharClass, const N: usize> Deref for Variable<C, N> {
    type Target = str;

    fn deref(&self) -> &Self::Target {
        self.as_str()
    }
}

pub type F1A = Fixed<Alpha, 1>;
pub type F2A = Fixed<Alpha, 2>;
pub type F3A = Fixed<Alpha, 3>;

pub type F1N = Fixed<Numeric, 1>;
pub type F3N = Fixed<Numeric, 3>;
pub type F8N = Fixed<Numeric, 8>;

pub type F4An = Fixed<AlphaNumeric, 4>;
pub type F5An = Fixed<AlphaNumeric, 5>;
pub type F12An = Fixed<AlphaNumeric, 12>;

pub type F6Ans = Fixed<AlphaNumericSpecial, 6>;
pub type F11Ans = Fixed<AlphaNumericSpecial, 11>;

pub type V3A = Variable<Alpha, 3>;
pub type V12A = Variable<Alpha, 12>;
pub type V33A = Variable<Alpha, 33>;

pub type V5Ans = Variable<AlphaNumericSpecial, 5>;
pub type V6Ans = Variable<AlphaNumericSpecial, 6>;
pub type V10Ans = Variable<AlphaNumericSpecial, 10>;
pub type V12Ans = Variable<AlphaNumericSpecial, 12>;
pub type V15Ans = Variable<AlphaNumericSpecial, 15>;
pub type V20Ans = Variable<AlphaNumericSpecial, 20>;
pub type V25Ans = Variable<AlphaNumericSpecial, 25>;
pub type V35Ans = Variable<AlphaNumericSpecial, 35>;
pub type V40Ans = Variable<AlphaNumericSpecial, 40>;
pub type V50Ans = Variable<AlphaNumericSpecial, 50>;
