use endian_trait::Endian;
use std::sync::atomic::{AtomicUsize, Ordering};
static DROPS: [AtomicUsize; 4] = [const { AtomicUsize::new(0) }; 4];
struct Probe {
    id: usize,
    panic_at: usize,
}
impl Drop for Probe {
    fn drop(&mut self) {
        DROPS[self.id].fetch_add(1, Ordering::SeqCst);
    }
}
impl Probe {
    fn convert(self) -> Self {
        assert_ne!(self.id, self.panic_at, "synthetic conversion panic");
        self
    }
}
impl Endian for Probe {
    fn from_be(self) -> Self {
        self.convert()
    }
    fn from_le(self) -> Self {
        self.convert()
    }
    fn to_be(self) -> Self {
        self.convert()
    }
    fn to_le(self) -> Self {
        self.convert()
    }
}
#[test]
fn every_conversion_drops_each_array_element_once_on_unwind() {
    for operation in 0..4 {
        for panic_at in 0..5 {
            for counter in &DROPS {
                counter.store(0, Ordering::SeqCst);
            }
            let result = std::panic::catch_unwind(|| {
                let values: [Probe; 4] = std::array::from_fn(|id| Probe { id, panic_at });
                let converted = match operation {
                    0 => Endian::from_be(values),
                    1 => Endian::from_le(values),
                    2 => Endian::to_be(values),
                    _ => Endian::to_le(values),
                };
                drop(converted);
            });
            assert_eq!(result.is_err(), panic_at < 4);
            for counter in &DROPS {
                assert_eq!(counter.load(Ordering::SeqCst), 1);
            }
        }
    }
}
#[test]
fn array_and_slice_wire_values_match_integer_primitives() {
    let values = [0x01234567u32, 0x89abcdef, 0, u32::MAX];
    assert_eq!(Endian::to_le(values), values.map(u32::to_le));
    assert_eq!(Endian::to_be(values), values.map(u32::to_be));
    let mut slice = values;
    Endian::to_be(slice.as_mut_slice());
    assert_eq!(slice, values.map(u32::to_be));
    Endian::from_be(slice.as_mut_slice());
    assert_eq!(slice, values);
}
#[test]
fn invalid_swapped_unicode_scalar_panics_safely() {
    // Swapping ASCII A creates a value beyond the Unicode scalar range.
    let character = 'A';
    let result = std::panic::catch_unwind(|| {
        if cfg!(target_endian = "little") {
            Endian::to_be(character)
        } else {
            Endian::to_le(character)
        }
    });
    assert!(result.is_err());
}

#[derive(Clone, Copy, Debug)]
struct CopyProbe {
    id: usize,
    converted: bool,
}
impl CopyProbe {
    fn convert(self) -> Self {
        assert_ne!(self.id, 2);
        Self {
            converted: true,
            ..self
        }
    }
}
impl Endian for CopyProbe {
    fn from_be(self) -> Self {
        self.convert()
    }
    fn from_le(self) -> Self {
        self.convert()
    }
    fn to_be(self) -> Self {
        self.convert()
    }
    fn to_le(self) -> Self {
        self.convert()
    }
}
#[test]
fn slice_is_valid_when_element_conversion_panics() {
    for operation in 0..4 {
        let mut values: [CopyProbe; 4] = std::array::from_fn(|id| CopyProbe {
            id,
            converted: false,
        });
        let result = std::panic::catch_unwind(std::panic::AssertUnwindSafe(|| match operation {
            0 => {
                Endian::from_be(values.as_mut_slice());
            }
            1 => {
                Endian::from_le(values.as_mut_slice());
            }
            2 => {
                Endian::to_be(values.as_mut_slice());
            }
            _ => {
                Endian::to_le(values.as_mut_slice());
            }
        }));
        assert!(result.is_err());
        for (index, value) in values.iter().enumerate() {
            assert_eq!(value.id, index);
            assert_eq!(value.converted, index < 2);
        }
    }
}
