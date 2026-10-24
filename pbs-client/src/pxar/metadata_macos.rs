//! Darwin restoration via held descriptors; no /proc path emulation.
use super::{Flags, darwin_archive};
use anyhow::{Context, Error, bail};
use nix::errno::Errno;
use nix::fcntl::OFlag;
use nix::sys::stat::Mode;
use std::ffi::CStr;
use std::os::fd::{AsRawFd, RawFd};
use std::path::Path;

pub fn apply_at(
    flags: Flags,
    metadata: &pxar::Metadata,
    parent: RawFd,
    name: &CStr,
    path: &Path,
    on_error: &mut (dyn FnMut(Error) -> Result<(), Error> + Send),
) -> Result<(), Error> {
    let open = if metadata.is_symlink() {
        OFlag::from_bits_retain(libc::O_SYMLINK)
    } else {
        OFlag::O_NOFOLLOW
    };
    let fd = proxmox_sys::fd::openat(
        &parent,
        name,
        open | OFlag::O_RDONLY | OFlag::O_NONBLOCK | OFlag::O_CLOEXEC,
        Mode::empty(),
    )?;
    apply(flags, metadata, fd.as_raw_fd(), path, on_error)
}

pub fn apply_initial_flags(
    _flags: Flags,
    _metadata: &pxar::Metadata,
    _fd: RawFd,
    _on_error: &mut (dyn FnMut(Error) -> Result<(), Error> + Send),
) -> Result<(), Error> {
    // Native user flags are deferred until all data and directory children are
    // complete. In particular immutable/append must not block restoration.
    Ok(())
}

pub fn apply(
    flags: Flags,
    metadata: &pxar::Metadata,
    fd: RawFd,
    path: &Path,
    _on_error: &mut (dyn FnMut(Error) -> Result<(), Error> + Send),
) -> Result<(), Error> {
    // Only interpret the reserved envelope when the snapshot manifest/map has
    // opted into native metadata. A Linux user xattr with this name is ordinary data.
    let native = if darwin_archive::restoring_native_metadata() {
        darwin_archive::decode(metadata)?
    } else {
        None
    };
    if flags.contains(Flags::WITH_OWNER) {
        nix::unistd::fchown(
            fd,
            Some(nix::unistd::Uid::from_raw(metadata.stat.uid)),
            Some(nix::unistd::Gid::from_raw(metadata.stat.gid)),
        )
        .context("failed to restore ownership")?;
    }
    if !metadata.is_symlink() && flags.contains(Flags::WITH_PERMISSIONS) {
        nix::sys::stat::fchmod(fd, super::tools::perms_from_metadata(metadata)?)?;
    }
    if let Some(native) = &native {
        native.restore_attributes(fd, flags)?;
        native.restore_acl(fd, flags)?;
        native.restore_birthtime(fd)?;
    } else {
        if flags.contains(Flags::WITH_ACL)
            && (!metadata.acl.users.is_empty()
                || !metadata.acl.groups.is_empty()
                || metadata.acl.default.is_some())
        {
            bail!("POSIX ACL conversion to Darwin ACL requires an explicit policy");
        }
        if flags.contains(Flags::WITH_XATTRS) {
            for attr in &metadata.xattrs {
                proxmox_sys::fs::xattr::fsetxattr(fd, attr.name(), attr.value())?;
            }
        }
    }
    let times = [
        libc::timespec {
            tv_sec: 0,
            tv_nsec: libc::UTIME_OMIT,
        },
        libc::timespec {
            tv_sec: metadata.stat.mtime.secs,
            tv_nsec: metadata.stat.mtime.nanos as _,
        },
    ];
    if unsafe { libc::futimens(fd, times.as_ptr()) } != 0 {
        return Err(std::io::Error::last_os_error())
            .with_context(|| format!("failed to restore mtime for {path:?}"));
    }
    if let Some(native) = native {
        native.restore_flags(fd)?;
    }
    Ok(())
}

pub(crate) fn errno_is_unsupported(errno: Errno) -> bool {
    matches!(errno, Errno::ENOTSUP | Errno::ENOTTY)
}
