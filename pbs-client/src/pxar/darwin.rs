//! Descriptor-relative Darwin filesystem operations.

use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};
use std::path::{Component, Path};

use nix::errno::Errno;
use nix::fcntl::{FcntlArg, OFlag, fcntl, openat};
use nix::sys::stat::{Mode, SFlag, fstat};

/// Open a relative directory below an already-open root without following any
/// symlinks. Reject parent components even if lexical normalization would stay
/// inside the root. Each directory remains pinned by its descriptor while the
/// next component is opened. Darwin has no Linux openat2/RESOLVE_* syscall.
pub(crate) fn open_directory_beneath(root: RawFd, path: &Path) -> nix::Result<OwnedFd> {
    let kind = SFlag::from_bits_truncate(fstat(root)?.st_mode);
    if kind != SFlag::S_IFDIR {
        return Err(Errno::ENOTDIR);
    }
    // Validate the entire path before opening anything except the root.
    if path
        .components()
        .any(|part| !matches!(part, Component::Normal(_) | Component::CurDir))
    {
        return Err(Errno::EINVAL);
    }
    let mut directory = unsafe { OwnedFd::from_raw_fd(fcntl(root, FcntlArg::F_DUPFD_CLOEXEC(0))?) };
    for component in path.components() {
        if let Component::Normal(name) = component {
            let raw = openat(
                Some(directory.as_raw_fd()),
                name,
                OFlag::O_RDONLY | OFlag::O_DIRECTORY | OFlag::O_NOFOLLOW | OFlag::O_CLOEXEC,
                Mode::empty(),
            )?;
            directory = unsafe { OwnedFd::from_raw_fd(raw) };
        }
    }
    Ok(directory)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn hardlink_parent_rejects_symlink_escape_and_traversal() {
        let base = std::env::temp_dir().join(format!("pbs-beneath-{}", std::process::id()));
        std::fs::create_dir(&base).unwrap();
        std::fs::create_dir(base.join("root")).unwrap();
        std::fs::create_dir_all(base.join("root/żółć/subdir")).unwrap();
        std::fs::create_dir(base.join("outside")).unwrap();
        std::fs::write(base.join("outside/sentinel"), b"must stay unchanged").unwrap();
        std::os::unix::fs::symlink("../outside", base.join("root/escape")).unwrap();
        let root = std::fs::File::open(base.join("root")).unwrap();
        let opened = open_directory_beneath(root.as_raw_fd(), Path::new("żółć/subdir")).unwrap();
        let expected = std::fs::File::open(base.join("root/żółć/subdir")).unwrap();
        assert_eq!(
            fstat(opened.as_raw_fd()).unwrap().st_ino,
            fstat(expected.as_raw_fd()).unwrap().st_ino
        );
        for path in [
            "escape",
            "escape/nested",
            "../outside",
            "/",
            "żółć/../../outside",
        ] {
            assert!(
                open_directory_beneath(root.as_raw_fd(), Path::new(path)).is_err(),
                "{path}"
            );
        }
        assert!(open_directory_beneath(root.as_raw_fd(), Path::new(".")).is_ok());
        assert_eq!(
            std::fs::read(base.join("outside/sentinel")).unwrap(),
            b"must stay unchanged"
        );
        std::fs::remove_dir_all(base).unwrap();
    }
}
