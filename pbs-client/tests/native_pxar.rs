//! Wire regressions shared by Linux and Darwin. Windows fixtures test representation,
//! not Windows filesystem APIs. No production data or credentials are used.
use pxar::format::{self, native::*};
use pxar::{Metadata, PxarVariant};
use std::collections::BTreeMap;
use std::io::{self, Cursor, Read, Write};
use std::sync::{Arc, Mutex};

#[derive(Default, Clone)]
struct Store(Arc<Mutex<BTreeMap<[u8; 32], Vec<u8>>>>);
impl Store {
    fn insert(&self, data: Vec<u8>, kind: u32, name: Vec<u8>) -> NativeAttribute {
        let digest = openssl::sha::sha256(&data);
        let size = data.len() as u64;
        self.0.lock().unwrap().insert(digest, data);
        NativeAttribute {
            kind,
            name,
            size,
            digest,
            location: PayloadLocation::Source,
        }
    }
}
struct Sink {
    store: Store,
    digest: [u8; 32],
    size: u64,
    data: Vec<u8>,
}
impl Write for Sink {
    fn write(&mut self, b: &[u8]) -> io::Result<usize> {
        self.data.extend_from_slice(b);
        Ok(b.len())
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}
impl PayloadWriter for Sink {
    fn finish(self: Box<Self>) -> io::Result<()> {
        if self.data.len() as u64 != self.size || openssl::sha::sha256(&self.data) != self.digest {
            return Err(io::Error::other("digest/size mismatch"));
        }
        self.store.0.lock().unwrap().insert(self.digest, self.data);
        Ok(())
    }
}
impl PayloadStore for Store {
    fn reader(&self, digest: [u8; 32], _: u64) -> io::Result<Box<dyn Read + Send>> {
        Ok(Box::new(Cursor::new(
            self.0.lock().unwrap().get(&digest).unwrap().clone(),
        )))
    }
    fn writer(&self, digest: [u8; 32], size: u64) -> io::Result<Box<dyn PayloadWriter>> {
        Ok(Box::new(Sink {
            store: self.clone(),
            digest,
            size,
            data: Vec::new(),
        }))
    }
}
fn metadata(store: &Store, windows: bool) -> Metadata {
    let platform = if windows {
        PlatformMetadata::Windows(WindowsMetadata {
            attributes: 0x12345678,
            creation_time: 0,
            access_time: u64::MAX,
            write_time: 123,
            change_time: 456,
        })
    } else {
        PlatformMetadata::Darwin(DarwinMetadata {
            birth_seconds: -42,
            birth_nanoseconds: 987654321,
            flags: 0x8001,
            acl: Some((
                1,
                vec![
                    DarwinAce {
                        principal: [0xaa; 16],
                        kind: 2,
                        flags: 0,
                        permissions: 0x1234,
                    },
                    DarwinAce {
                        principal: [0xbb; 16],
                        kind: 1,
                        flags: 0x10,
                        permissions: 0x4321,
                    },
                ],
            )),
        })
    };
    let attributes = if windows {
        vec![
            store.insert(vec![0, 255, 1], WINDOWS_SECURITY, vec![]),
            store.insert(vec![0, 0, 1, 0, 7, 255], WINDOWS_REPARSE, vec![]),
            store.insert(
                vec![0x35; 2 * 1024 * 1024 + 11],
                WINDOWS_STREAM,
                "test🦀".encode_utf16().flat_map(u16::to_le_bytes).collect(),
            ),
        ]
    } else {
        vec![
            store.insert(vec![0, 255, 0, 7], DARWIN_XATTR, b"user.test".to_vec()),
            store.insert(
                vec![0x25; 2 * 1024 * 1024 + 11],
                DARWIN_XATTR,
                b"com.apple.ResourceFork".to_vec(),
            ),
        ]
    };
    Metadata {
        native: Some(NativeMetadata {
            platform,
            attributes,
        }),
        ..Metadata::dir_builder(0o700).build()
    }
}
fn archive(split: bool, windows: bool) -> (Vec<u8>, Vec<u8>, Metadata, Store) {
    let store = Store::default();
    let meta = metadata(&store, windows);
    let mut data = Vec::new();
    let mut payload = Vec::new();
    let writer = if split {
        PxarVariant::Split(
            pxar::encoder::sync::StandardWriter::new(&mut data),
            pxar::encoder::sync::StandardWriter::new(&mut payload),
        )
    } else {
        PxarVariant::Unified(pxar::encoder::sync::StandardWriter::new(&mut data))
    };
    let mut e =
        pxar::encoder::Encoder::new_with_native(writer, &meta, None, Arc::new(store.clone()))
            .unwrap();
    let child = Metadata::file_builder(0o640).build();
    e.add_file(&child, "file", 3, &mut &b"abc"[..]).unwrap();
    e.create_directory("dir", &meta).unwrap();
    e.add_symlink(
        &Metadata {
            stat: format::Stat {
                mode: pxar::mode::IFLNK | 0o751,
                ..Default::default()
            },
            ..Default::default()
        },
        "link",
        "../file",
    )
    .unwrap();
    e.finish().unwrap();
    e.finish().unwrap();
    e.close().unwrap();
    (data, payload, meta, store)
}
fn decoded(
    data: Vec<u8>,
    payload: Option<Vec<u8>>,
    store: Option<Store>,
) -> io::Result<Vec<pxar::Entry>> {
    let input = match payload {
        Some(p) => PxarVariant::Split(Cursor::new(data), Cursor::new(p)),
        None => PxarVariant::Unified(Cursor::new(data)),
    };
    let mut d = pxar::decoder::Decoder::from_std(input)?;
    if let Some(s) = store {
        d.set_native_payload_store(Arc::new(s));
    }
    d.collect()
}
fn roundtrip(split: bool, windows: bool) {
    let (data, payload, expected, original) = archive(split, windows);
    let dest = Store::default();
    if split {
        assert!(data.len() < 10 * 1024);
        assert!(payload.len() > 2 * 1024 * 1024);
    }
    let entries = decoded(data, split.then_some(payload), Some(dest.clone())).unwrap();
    let dirs: Vec<_> = entries.iter().filter(|e| e.metadata().is_dir()).collect();
    assert_eq!(dirs.len(), 2);
    for e in dirs {
        assert_eq!(e.metadata().native, expected.native);
    }
    assert_eq!(*original.0.lock().unwrap(), *dest.0.lock().unwrap());
}
#[test]
fn darwin_unified() {
    roundtrip(false, false)
}
#[test]
fn darwin_split() {
    roundtrip(true, false)
}
#[test]
fn windows_unified() {
    roundtrip(false, true)
}
#[test]
fn windows_split() {
    roundtrip(true, true)
}
#[test]
fn split_metadata_only_needs_no_payload() {
    let (d, _, _, _) = archive(true, false);
    let es = decoded(d, None, None).unwrap();
    assert!(es.iter().any(|e| e.metadata().native.is_some()));
}
#[test]
fn legacy_v1_v2_remain_encodable_and_readable() {
    for split in [false, true] {
        let mut d = Vec::new();
        let mut p = Vec::new();
        let m = Metadata::dir_builder(0o700).build();
        let w = if split {
            PxarVariant::Split(
                pxar::encoder::sync::StandardWriter::new(&mut d),
                pxar::encoder::sync::StandardWriter::new(&mut p),
            )
        } else {
            PxarVariant::Unified(pxar::encoder::sync::StandardWriter::new(&mut d))
        };
        let mut e = pxar::encoder::Encoder::new(w, &m, None).unwrap();
        e.add_file(
            &Metadata::file_builder(0o600).build(),
            "old",
            3,
            &mut &b"old"[..],
        )
        .unwrap();
        e.finish().unwrap();
        e.close().unwrap();
        if split {
            assert_eq!(&d[16..24], &2u64.to_le_bytes());
        } else {
            assert_eq!(&d[..8], &format::PXAR_ENTRY.to_le_bytes());
        }
        assert_eq!(
            decoded(d, split.then_some(p), None)
                .unwrap()
                .iter()
                .filter(|e| e.metadata().is_regular_file())
                .count(),
            1
        );
    }
}
#[test]
fn future_version_and_native_record_in_old_format_rejected() {
    let (d, p, _, _) = archive(true, false);
    for v in [2u64, 3, u64::MAX] {
        let mut bad = d.clone();
        bad[16..24].copy_from_slice(&v.to_le_bytes());
        assert!(decoded(bad, Some(p.clone()), None).is_err());
    }
}
#[test]
fn truncated_native_headers_rejected() {
    let m = metadata(&Store::default(), false).native.unwrap();
    let h = m.header().unwrap();
    for n in 0..h.len() {
        assert!(NativeMetadata::from_header(&h[..n]).is_err());
    }
    let mut h = h;
    h.push(0);
    assert!(NativeMetadata::from_header(&h).is_err());
}
#[test]
fn bad_timestamps_duplicate_names_and_stream_paths_rejected() {
    let mut m = metadata(&Store::default(), false).native.unwrap();
    m.attributes.push(m.attributes[0].clone());
    assert!(m.validate().is_err());
    m.attributes.pop();
    if let PlatformMetadata::Darwin(ref mut d) = m.platform {
        d.birth_nanoseconds = 1_000_000_000;
    }
    assert!(m.validate().is_err());
    let mut m = metadata(&Store::default(), true).native.unwrap();
    m.attributes.last_mut().unwrap().name = "../escape"
        .encode_utf16()
        .flat_map(u16::to_le_bytes)
        .collect();
    assert!(m.validate().is_err());
    m.attributes.last_mut().unwrap().name = vec![0, 0xd8];
    assert!(m.validate().is_err());
}
#[test]
fn payload_corruption_and_truncation_rejected_before_publication() {
    for split in [false, true] {
        let (d, p, _, _) = archive(split, false);
        let mut d = d;
        let mut p = p;
        let bytes = if split { &mut p } else { &mut d };
        let i = bytes
            .windows(16)
            .position(|w| w.iter().all(|v| *v == 0x25))
            .unwrap();
        bytes[i] ^= 1;
        assert!(decoded(d, split.then_some(p), Some(Store::default())).is_err());
    }
    let (d, mut p, _, _) = archive(true, false);
    p.truncate(1000);
    assert!(decoded(d, Some(p), Some(Store::default())).is_err());
}
#[test]
fn random_access_reads_native_metadata() {
    let (d, p, expected, _) = archive(true, false);
    let dir = tempfile::tempdir().unwrap();
    let a = dir.path().join("a");
    let b = dir.path().join("b");
    std::fs::write(&a, &d).unwrap();
    std::fs::write(&b, &p).unwrap();
    let reader =
        pxar::accessor::sync::FileRefReader::new(Arc::new(std::fs::File::open(a).unwrap()));
    let payload =
        pxar::accessor::sync::FileRefReader::new(Arc::new(std::fs::File::open(b).unwrap()));
    let accessor = pxar::accessor::sync::Accessor::new(
        PxarVariant::Split(reader, (payload, p.len() as u64)),
        d.len() as u64,
    )
    .unwrap();
    let root = accessor.open_root().unwrap();
    let mut child = root.lookup("dir").unwrap().unwrap();
    let store = Store::default();
    child
        .materialize_native_metadata(Arc::new(store.clone()))
        .unwrap();
    assert_eq!(child.entry().metadata().native, expected.native);
    assert_eq!(
        child.entry().metadata().native.as_ref().unwrap().platform,
        expected.native.unwrap().platform
    );
}

#[test]
fn invalid_native_reference_lengths_and_counts_are_bounded() {
    let mut m = metadata(&Store::default(), false).native.unwrap();
    m.attributes[0].size = MAX_PAYLOAD + 1;
    assert!(m.validate().is_err());
    m.attributes[0].size = 12;
    m.attributes[0].location = PayloadLocation::Payload(u64::MAX - 3);
    assert!(m.validate().is_err());
    for size in 0..56 {
        assert!(NativeAttribute::from_descriptor(&vec![0; size]).is_err());
    }
    let mut h = metadata(&Store::default(), false)
        .native
        .unwrap()
        .header()
        .unwrap();
    h[32..36].copy_from_slice(&u32::MAX.to_le_bytes());
    assert!(NativeMetadata::from_header(&h).is_err());
}

// Run the pinned upstream's old timestamp fixture through the same client test
// harness; this does not require altering the dependency's excluded workspace.
#[path = "../../vendor/pxar/tests/compat.rs"]
mod original_pxar_compat;
