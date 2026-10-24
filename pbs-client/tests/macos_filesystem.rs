#![cfg(target_os = "macos")]
use anyhow::Error;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use pbs_client::pxar::{darwin_archive::*, *};
use std::ffi::CString;
use std::fs::{self, File};
use std::io::Cursor;
use std::os::fd::AsRawFd;
use std::os::unix::fs::{MetadataExt, PermissionsExt, symlink};

#[test]
fn native_archive_restore_roundtrip() -> Result<(), Error> {
    let sandbox = tempfile::tempdir()?;
    let source = sandbox.path().join("source");
    fs::create_dir(&source)?;
    let path = source.join("zażółć-🦀");
    fs::write(&path, vec![0x5a; 2 * 1024 * 1024 + 37])?;
    fs::set_permissions(&path, fs::Permissions::from_mode(0o640))?;
    fs::hard_link(&path, source.join("hardlink"))?;
    symlink("zażółć-🦀", source.join("symlink"))?;
    fs::create_dir(source.join("nested"))?;
    fs::write(source.join("nested/empty"), [])?;
    let file = File::open(&path)?;
    let fd = file.as_raw_fd();
    for (name, value) in [
        ("user.test", vec![0, 255, 9, 0]),
        (
            "com.apple.FinderInfo",
            [b"TEXTttxt".as_slice(), &[0; 24]].concat(),
        ),
        (
            "com.apple.ResourceFork",
            (0..1024 * 1024 + 101).map(|i| (i % 251) as u8).collect(),
        ),
    ] {
        proxmox_sys::fs::xattr::fsetxattr(fd, &CString::new(name)?, &value)?;
    }
    assert_eq!(unsafe { libc::fchflags(fd, 0x8001) }, 0);
    let payloads = NativePayloads::new()?;
    let archive = sandbox.path().join("primary.pxar");
    let writer = pxar::PxarVariant::Unified(pxar::encoder::sync::StandardWriter::new(
        File::create(&archive)?,
    ));
    let dir = nix::dir::Dir::open(&source, OFlag::O_RDONLY | OFlag::O_DIRECTORY, Mode::empty())?;
    let runtime = tokio::runtime::Runtime::new()?;
    runtime.block_on(create_archive(
        dir,
        PxarWriters::new(writer, None),
        Flags::DEFAULT,
        |_| Ok(()),
        PxarCreateOptions {
            entries_max: ENCODER_MAX_ENTRIES,
            native_payloads: Some(payloads.clone()),
            ..Default::default()
        },
        None,
        None,
    ))?;
    let mut auxiliary = Vec::new();
    payloads.write_archive(&mut auxiliary)?;
    let restored_payloads = NativePayloads::new()?;
    let (count, bytes) = payloads.totals();
    unpack_payloads(
        pxar::decoder::Decoder::from_std(pxar::PxarVariant::Unified(Cursor::new(&auxiliary)))?,
        &restored_payloads,
        count,
        bytes,
    )?;
    let destination = sandbox.path().join("restored");
    let decoder =
        pxar::decoder::Decoder::from_std(pxar::PxarVariant::Unified(File::open(&archive)?))?;
    with_restore_payloads(Some(restored_payloads.clone()), || {
        extract_archive(
            decoder,
            &destination,
            Flags::DEFAULT,
            |_| {},
            PxarExtractOptions {
                match_list: &[],
                extract_match_default: true,
                allow_existing_dirs: false,
                overwrite_flags: OverwriteFlags::empty(),
                on_error: None,
                prelude_path: None,
            },
        )
    })?;
    let restored = destination.join("zażółć-🦀");
    assert_eq!(fs::read(&path)?, fs::read(&restored)?);
    assert_eq!(
        fs::read_link(destination.join("symlink"))?,
        std::path::Path::new("zażółć-🦀")
    );
    assert_eq!(
        fs::metadata(&restored)?.ino(),
        fs::metadata(destination.join("hardlink"))?.ino()
    );
    let target = File::open(&restored)?;
    let expected_stat = nix::sys::stat::fstat(fd)?;
    let actual_stat = nix::sys::stat::fstat(target.as_raw_fd())?;
    assert_eq!(expected_stat.st_mode, actual_stat.st_mode);
    assert_eq!(expected_stat.st_flags, actual_stat.st_flags);
    assert_eq!(
        (expected_stat.st_birthtime, expected_stat.st_birthtime_nsec),
        (actual_stat.st_birthtime, actual_stat.st_birthtime_nsec)
    );
    assert_eq!(
        (expected_stat.st_mtime, expected_stat.st_mtime_nsec),
        (actual_stat.st_mtime, actual_stat.st_mtime_nsec)
    );
    for name in [
        "user.test",
        "com.apple.FinderInfo",
        "com.apple.ResourceFork",
    ] {
        let name = CString::new(name)?;
        assert_eq!(
            proxmox_sys::fs::xattr::fgetxattr(fd, &name)
                .map_err(|e| anyhow::anyhow!("source {name:?}: {e}"))?,
            proxmox_sys::fs::xattr::fgetxattr(target.as_raw_fd(), &name)
                .map_err(|e| anyhow::anyhow!("restored {name:?}: {e}"))?
        );
    }
    // Reject a tampered auxiliary archive and incorrect resource budgets.
    assert!(
        unpack_payloads(
            pxar::decoder::Decoder::from_std(pxar::PxarVariant::Unified(Cursor::new(&auxiliary)))?,
            &NativePayloads::new()?,
            count,
            bytes - 1
        )
        .is_err()
    );
    let mut damaged = auxiliary;
    let middle = damaged.len() / 2;
    damaged[middle] ^= 1;
    assert!(
        unpack_payloads(
            pxar::decoder::Decoder::from_std(pxar::PxarVariant::Unified(Cursor::new(damaged)))?,
            &NativePayloads::new()?,
            count,
            bytes
        )
        .is_err()
    );
    Ok(())
}

#[test]
fn reject_destination_name_alias_before_truncation() -> Result<(), Error> {
    let sandbox = tempfile::tempdir()?;
    let probe = sandbox.path().join("probe");
    fs::write(&probe, b"probe")?;
    // This property is tested only when the mounted filesystem aliases case.
    if !sandbox.path().join("PROBE").exists() {
        return Ok(());
    }
    let mut archive = Vec::new();
    let root = pxar::Metadata {
        stat: pxar::Stat {
            mode: pxar::mode::IFDIR | 0o700,
            ..Default::default()
        },
        ..Default::default()
    };
    let regular = pxar::Metadata {
        stat: pxar::Stat {
            mode: pxar::mode::IFREG | 0o600,
            ..Default::default()
        },
        ..Default::default()
    };
    {
        use std::io::Write;
        let mut encoder = pxar::encoder::sync::Encoder::from_std(&mut archive, &root)?;
        {
            let mut file = encoder.create_file(&regular, "Case", 4)?;
            file.write_all(b"safe")?;
        }
        {
            let mut file = encoder.create_file(&regular, "case", 3)?;
            file.write_all(b"bad")?;
        }
        encoder.finish()?;
    }
    let decoder =
        pxar::decoder::Decoder::from_std(pxar::PxarVariant::Unified(Cursor::new(archive)))?;
    let destination = sandbox.path().join("collision");
    let result = extract_archive(
        decoder,
        &destination,
        Flags::DEFAULT & !Flags::WITH_OWNER,
        |_| {},
        PxarExtractOptions {
            match_list: &[],
            extract_match_default: true,
            allow_existing_dirs: true,
            overwrite_flags: OverwriteFlags::FILE,
            on_error: None,
            prelude_path: None,
        },
    );
    assert!(result.is_err());
    assert_eq!(fs::read(destination.join("Case"))?, b"safe");
    Ok(())
}
