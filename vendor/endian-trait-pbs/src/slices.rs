//! In-place slices require Copy: a conversion panic cannot duplicate ownership.
use super::Endian;
impl<T: Endian + Copy> Endian for &mut [T] {
    fn from_be(self) -> Self {
        for value in self.iter_mut() {
            *value = Endian::from_be(*value);
        }
        self
    }
    fn from_le(self) -> Self {
        for value in self.iter_mut() {
            *value = Endian::from_le(*value);
        }
        self
    }
    fn to_be(self) -> Self {
        for value in self.iter_mut() {
            *value = Endian::to_be(*value);
        }
        self
    }
    fn to_le(self) -> Self {
        for value in self.iter_mut() {
            *value = Endian::to_le(*value);
        }
        self
    }
}
