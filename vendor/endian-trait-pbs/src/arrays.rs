//! Panic-safe ownership transfer delegates to the standard library array mapper.
use super::Endian;
impl<T: Endian, const N: usize> Endian for [T; N] {
    fn from_be(self) -> Self {
        self.map(Endian::from_be)
    }
    fn from_le(self) -> Self {
        self.map(Endian::from_le)
    }
    fn to_be(self) -> Self {
        self.map(Endian::to_be)
    }
    fn to_le(self) -> Self {
        self.map(Endian::to_le)
    }
}
