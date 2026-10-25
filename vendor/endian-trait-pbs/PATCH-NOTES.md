# Local security compatibility fork

This source is derived from registry `endian_trait` 0.6.0, whose original file
hashes were verified before modification. MIT copyright/license are retained.
PROVENANCE.json records the original package checksum and advisory.

This is a local `0.6.1+pbs.1` source override, not an upstream release and not a
claim that RustSec has marked a published version fixed. No advisory ignore rule
is used. Cargo.lock selects this path source for the complete client graph.

The RUSTSEC-2021-0039 ownership duplication is removed:

* Arrays use the standard library's panic-safe `array.map`, transferring each
  owned element once. The const-generic implementation preserves every earlier
  array length and additionally supports longer arrays.
* Mutable slices require `T: Copy` and use safe assignments. This deliberately
  narrows the old generic API; all PBS usages compile under this requirement.
* All char conversions check `char::from_u32`; byte-swapped values that are not
  Unicode scalars panic safely. The original code could construct invalid chars.
* `#![forbid(unsafe_code)]` makes reintroduction of these unsafe primitives a
  compilation error in the compatibility crate.

Regression tests count drops for all four conversion operations with a panic at
each element, check slice validity after panic, verify exact integer wire values
and reject invalid swapped Unicode scalars. Format and client integration tests
also cover the surrounding original Proxmox code.
