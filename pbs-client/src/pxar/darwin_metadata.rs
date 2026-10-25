//! Native metadata primitives. Archive integration is intentionally separate.
//!
//! ACLs retain ordered UUID entries, not translated user names or Linux POSIX
//! ACLs. No untrusted external ACL blob is passed to lengthless acl_copy_int.

use std::ffi::c_void;
use std::io::{self, Read, Write};
use std::os::fd::{AsRawFd, FromRawFd, OwnedFd, RawFd};

use nix::fcntl::{FcntlArg, fcntl};
use nix::sys::stat::fstat;
use serde::{Deserialize, Serialize};

const ACL_TYPE_EXTENDED: i32 = 0x100;
const ACL_FLAGS: [u32; 7] = [1, 1 << 17, 1 << 4, 1 << 5, 1 << 6, 1 << 7, 1 << 8];
const ACL_FLAG_MASK: u32 = 1 | (1 << 17) | (0x1f << 4);
const MAX_ACL_ENTRIES: usize = 128;
const RESOURCE_FORK: &std::ffi::CStr = c"com.apple.ResourceFork";
const MAX_POSITIONAL_FORK: u64 = u32::MAX as u64 + 1;
const RESTORABLE_USER_FLAGS: u32 = 0x800f; // NODUMP, IMMUTABLE, APPEND, OPAQUE, HIDDEN

unsafe extern "C" {
    fn acl_init(count: i32) -> *mut c_void;
    fn acl_free(pointer: *mut c_void) -> i32;
    fn acl_get_fd_np(fd: i32, kind: i32) -> *mut c_void;
    fn acl_set_fd_np(fd: i32, acl: *mut c_void, kind: i32) -> i32;
    fn acl_valid(acl: *mut c_void) -> i32;
    fn acl_get_entry(acl: *mut c_void, id: i32, entry: *mut *mut c_void) -> i32;
    fn acl_create_entry(acl: *mut *mut c_void, entry: *mut *mut c_void) -> i32;
    fn acl_get_qualifier(entry: *mut c_void) -> *mut c_void;
    fn acl_set_qualifier(entry: *mut c_void, qualifier: *const c_void) -> i32;
    fn acl_get_tag_type(entry: *mut c_void, tag: *mut i32) -> i32;
    fn acl_set_tag_type(entry: *mut c_void, tag: i32) -> i32;
    fn acl_get_permset_mask_np(entry: *mut c_void, mask: *mut u64) -> i32;
    fn acl_set_permset_mask_np(entry: *mut c_void, mask: u64) -> i32;
    fn acl_maximal_permset_mask_np(mask: *mut u64) -> i32;
    fn acl_get_flagset_np(object: *mut c_void, flags: *mut *mut c_void) -> i32;
    fn acl_get_flag_np(flags: *mut c_void, flag: i32) -> i32;
    fn acl_clear_flags_np(flags: *mut c_void) -> i32;
    fn acl_add_flag_np(flags: *mut c_void, flag: i32) -> i32;
}

fn checked(result: i32) -> io::Result<()> {
    if result < 0 {
        Err(io::Error::last_os_error())
    } else {
        Ok(())
    }
}

struct Allocation(*mut c_void);
impl Allocation {
    fn new(pointer: *mut c_void) -> io::Result<Self> {
        if pointer.is_null() {
            Err(io::Error::last_os_error())
        } else {
            Ok(Self(pointer))
        }
    }
}
impl Drop for Allocation {
    fn drop(&mut self) {
        if !self.0.is_null() {
            unsafe {
                acl_free(self.0);
            }
        }
    }
}

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Ace {
    pub principal_uuid: [u8; 16],
    pub kind: u32, // Darwin extended ALLOW=1, DENY=2, preserved in order.
    pub permissions: u64,
    pub flags: u32,
}

#[derive(Clone, Debug, Default, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct Acl {
    pub flags: u32,
    pub entries: Vec<Ace>,
}

fn read_flags(object: *mut c_void) -> io::Result<u32> {
    let mut set = std::ptr::null_mut();
    checked(unsafe { acl_get_flagset_np(object, &mut set) })?;
    let mut flags = 0;
    for flag in ACL_FLAGS {
        let result = unsafe { acl_get_flag_np(set, flag as i32) };
        checked(result)?;
        if result != 0 {
            flags |= flag;
        }
    }
    Ok(flags)
}

fn write_flags(object: *mut c_void, flags: u32) -> io::Result<()> {
    if flags & !ACL_FLAG_MASK != 0 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "unknown Darwin ACL flags",
        ));
    }
    let mut set = std::ptr::null_mut();
    checked(unsafe { acl_get_flagset_np(object, &mut set) })?;
    checked(unsafe { acl_clear_flags_np(set) })?;
    for flag in ACL_FLAGS {
        if flags & flag != 0 {
            checked(unsafe { acl_add_flag_np(set, flag as i32) })?;
        }
    }
    Ok(())
}

impl Acl {
    pub fn capture(fd: RawFd) -> io::Result<Self> {
        let pointer = unsafe { acl_get_fd_np(fd, ACL_TYPE_EXTENDED) };
        if pointer.is_null() {
            let error = io::Error::last_os_error();
            if matches!(
                error.raw_os_error(),
                Some(libc::ENOENT) | Some(libc::ENOATTR)
            ) {
                // Darwin reports ENOENT for an existing object with no extended
                // ACL. Do not confuse an invalid/unlinked descriptor with that.
                let stat = fstat(fd).map_err(io::Error::from)?;
                if stat.st_nlink > 0 {
                    return Ok(Self::default());
                }
            }
            return Err(error);
        }
        let acl = Allocation::new(pointer)?;
        checked(unsafe { acl_valid(acl.0) })?;
        let mut result = Self {
            flags: read_flags(acl.0)?,
            entries: Vec::new(),
        };
        for index in 0..=MAX_ACL_ENTRIES {
            let mut entry = std::ptr::null_mut();
            let status =
                unsafe { acl_get_entry(acl.0, if index == 0 { 0 } else { -1 }, &mut entry) };
            // Darwin returns -1/EINVAL at the end, unlike Linux's 0 result.
            if status < 0 && io::Error::last_os_error().raw_os_error() == Some(libc::EINVAL) {
                return Ok(result);
            }
            checked(status)?;
            if index == MAX_ACL_ENTRIES {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "Darwin ACL entry limit exceeded",
                ));
            }
            let qualifier = Allocation::new(unsafe { acl_get_qualifier(entry) })?;
            let mut uuid = [0; 16];
            unsafe {
                std::ptr::copy_nonoverlapping(qualifier.0.cast::<u8>(), uuid.as_mut_ptr(), 16);
            }
            let mut kind = 0;
            let mut permissions = 0;
            checked(unsafe { acl_get_tag_type(entry, &mut kind) })?;
            checked(unsafe { acl_get_permset_mask_np(entry, &mut permissions) })?;
            if kind != 1 && kind != 2 {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unknown Darwin ACL entry type",
                ));
            }
            result.entries.push(Ace {
                principal_uuid: uuid,
                kind: kind as u32,
                permissions,
                flags: read_flags(entry)?,
            });
        }
        unreachable!()
    }

    pub fn apply(&self, fd: RawFd) -> io::Result<()> {
        if self.entries.len() > MAX_ACL_ENTRIES {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "too many Darwin ACL entries",
            ));
        }
        let mut maximum = 0;
        checked(unsafe { acl_maximal_permset_mask_np(&mut maximum) })?;
        // Validate all serialized fields before changing the destination.
        if self.flags & !ACL_FLAG_MASK != 0
            || self.entries.iter().any(|entry| {
                !matches!(entry.kind, 1 | 2)
                    || entry.permissions & !maximum != 0
                    || entry.flags & !ACL_FLAG_MASK != 0
            })
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid Darwin ACL metadata",
            ));
        }
        let mut acl = Allocation::new(unsafe { acl_init(self.entries.len() as i32) })?;
        write_flags(acl.0, self.flags)?;
        for value in &self.entries {
            let mut entry = std::ptr::null_mut();
            checked(unsafe { acl_create_entry(&mut acl.0, &mut entry) })?;
            checked(unsafe { acl_set_tag_type(entry, value.kind as i32) })?;
            checked(unsafe { acl_set_qualifier(entry, value.principal_uuid.as_ptr().cast()) })?;
            checked(unsafe { acl_set_permset_mask_np(entry, value.permissions) })?;
            write_flags(entry, value.flags)?;
        }
        checked(unsafe { acl_valid(acl.0) })?;
        checked(unsafe { acl_set_fd_np(fd, acl.0, ACL_TYPE_EXTENDED) })
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub(crate) struct BirthTime {
    pub seconds: i64,
    pub nanoseconds: i64,
}

#[repr(C)]
struct AttrList {
    count: u16,
    reserved: u16,
    common: u32,
    volume: u32,
    directory: u32,
    file: u32,
    fork: u32,
}

impl BirthTime {
    pub fn capture(fd: RawFd) -> io::Result<Self> {
        let stat = fstat(fd).map_err(io::Error::from)?;
        Ok(Self {
            seconds: stat.st_birthtime,
            nanoseconds: stat.st_birthtime_nsec,
        })
    }
    pub fn apply(self, fd: RawFd) -> io::Result<()> {
        if !(0..1_000_000_000).contains(&self.nanoseconds) {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid birthtime nanoseconds",
            ));
        }
        let mut list = AttrList {
            count: 5,
            reserved: 0,
            common: 0x200,
            volume: 0,
            directory: 0,
            file: 0,
            fork: 0,
        };
        let mut time = libc::timespec {
            tv_sec: self.seconds,
            tv_nsec: self.nanoseconds,
        };
        checked(unsafe {
            libc::fsetattrlist(
                fd,
                (&mut list as *mut AttrList).cast(),
                (&mut time as *mut libc::timespec).cast(),
                std::mem::size_of::<libc::timespec>(),
                0,
            )
        })
    }
}

/// Apply only user flags with ordinary filesystem semantics, and only after
/// writing data, forks, ownership, ACLs and timestamps. System/synthetic flags,
/// compression representation and document tracking need explicit policies.
pub(crate) fn apply_user_flags(fd: RawFd, flags: u32) -> io::Result<()> {
    if flags & !RESTORABLE_USER_FLAGS != 0 {
        return Err(io::Error::new(
            io::ErrorKind::Unsupported,
            "Darwin flags require an explicit restore policy",
        ));
    }
    checked(unsafe { libc::fchflags(fd, flags) })
}

fn duplicate(fd: RawFd) -> io::Result<OwnedFd> {
    fcntl(fd, FcntlArg::F_DUPFD_CLOEXEC(0))
        .map(|raw| unsafe { OwnedFd::from_raw_fd(raw) })
        .map_err(io::Error::from)
}

fn fork_size(fd: RawFd) -> io::Result<Option<u64>> {
    let size =
        unsafe { libc::fgetxattr(fd, RESOURCE_FORK.as_ptr(), std::ptr::null_mut(), 0, 0, 0) };
    if size < 0 {
        let error = io::Error::last_os_error();
        if error.raw_os_error() == Some(libc::ENOATTR) {
            return Ok(None);
        }
        return Err(error);
    }
    Ok(Some(size as u64))
}

pub(crate) struct ForkReader {
    fd: OwnedFd,
    length: u64,
    position: u64,
    ctime: (i64, i64),
}
impl ForkReader {
    pub fn open(fd: RawFd) -> io::Result<Option<Self>> {
        let fd = duplicate(fd)?;
        let stat = fstat(fd.as_raw_fd()).map_err(io::Error::from)?;
        if stat.st_flags & 0x40000000 != 0 {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "dataless placeholder requires an explicit backup policy",
            ));
        }
        let Some(length) = fork_size(fd.as_raw_fd())? else {
            return Ok(None);
        };
        if length > MAX_POSITIONAL_FORK {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "resource fork exceeds Darwin positional xattr range",
            ));
        }
        Ok(Some(Self {
            fd,
            length,
            position: 0,
            ctime: (stat.st_ctime, stat.st_ctime_nsec),
        }))
    }
    pub fn len(&self) -> u64 {
        self.length
    }
    pub fn verify_stable(&self) -> io::Result<()> {
        let stat = fstat(self.fd.as_raw_fd()).map_err(io::Error::from)?;
        if fork_size(self.fd.as_raw_fd())? != Some(self.length)
            || self.ctime != (stat.st_ctime, stat.st_ctime_nsec)
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "source changed while reading resource fork",
            ));
        }
        Ok(())
    }
}
impl Read for ForkReader {
    fn read(&mut self, buffer: &mut [u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        if self.position == self.length {
            self.verify_stable()?;
            return Ok(0);
        }
        let count = buffer.len().min((self.length - self.position) as usize);
        let read = unsafe {
            libc::fgetxattr(
                self.fd.as_raw_fd(),
                RESOURCE_FORK.as_ptr(),
                buffer.as_mut_ptr().cast(),
                count,
                self.position as u32,
                0,
            )
        };
        if read < 0 {
            return Err(io::Error::last_os_error());
        }
        if read == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "resource fork shrank during backup",
            ));
        }
        if read as usize > count {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "invalid resource fork read length",
            ));
        }
        self.position += read as u64;
        Ok(read as usize)
    }
}

pub(crate) struct ForkWriter {
    fd: OwnedFd,
    length: u64,
    position: u64,
}
impl ForkWriter {
    pub fn create(fd: RawFd, length: u64) -> io::Result<Self> {
        if length > MAX_POSITIONAL_FORK {
            return Err(io::Error::new(
                io::ErrorKind::Unsupported,
                "resource fork exceeds Darwin positional xattr range",
            ));
        }
        let fd = duplicate(fd)?;
        let result = unsafe { libc::fremovexattr(fd.as_raw_fd(), RESOURCE_FORK.as_ptr(), 0) };
        if result < 0 && io::Error::last_os_error().raw_os_error() != Some(libc::ENOATTR) {
            return Err(io::Error::last_os_error());
        }
        Ok(Self {
            fd,
            length,
            position: 0,
        })
    }
    pub fn finish(self) -> io::Result<()> {
        if self.position != self.length
            || fork_size(self.fd.as_raw_fd())?.unwrap_or(0) != self.length
        {
            return Err(io::Error::new(
                io::ErrorKind::InvalidData,
                "incomplete resource fork restore",
            ));
        }
        Ok(())
    }
}
impl Write for ForkWriter {
    fn write(&mut self, buffer: &[u8]) -> io::Result<usize> {
        if buffer.is_empty() {
            return Ok(0);
        }
        let count = buffer.len().min((self.length - self.position) as usize);
        if count == 0 {
            return Err(io::Error::new(
                io::ErrorKind::WriteZero,
                "resource fork length exceeded",
            ));
        }
        checked(unsafe {
            libc::fsetxattr(
                self.fd.as_raw_fd(),
                RESOURCE_FORK.as_ptr(),
                buffer.as_ptr().cast(),
                count,
                self.position as u32,
                0,
            )
        })?;
        self.position += count as u64;
        Ok(count)
    }
    fn flush(&mut self) -> io::Result<()> {
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fixture(name: &str) -> (std::path::PathBuf, std::fs::File) {
        let path =
            std::env::temp_dir().join(format!("pbs-native-metadata-{}-{name}", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .create_new(true)
            .read(true)
            .write(true)
            .open(&path)
            .unwrap();
        (path, file)
    }

    #[test]
    fn ordered_uuid_acl_and_birthtime_roundtrip() {
        let (path, file) = fixture("acl");
        let acl = Acl {
            flags: 1 << 17,
            entries: vec![
                Ace {
                    principal_uuid: [0x11; 16],
                    kind: 2,
                    permissions: 2,
                    flags: 0,
                },
                Ace {
                    principal_uuid: [0x22; 16],
                    kind: 1,
                    permissions: 6,
                    flags: 0,
                },
            ],
        };
        acl.apply(file.as_raw_fd()).unwrap();
        assert_eq!(Acl::capture(file.as_raw_fd()).unwrap(), acl);
        let json = serde_json::to_vec(&acl).unwrap();
        assert_eq!(serde_json::from_slice::<Acl>(&json).unwrap(), acl);
        let birth = BirthTime {
            seconds: 946684800,
            nanoseconds: 321000123,
        };
        birth.apply(file.as_raw_fd()).unwrap();
        assert_eq!(BirthTime::capture(file.as_raw_fd()).unwrap(), birth);
        apply_user_flags(file.as_raw_fd(), 0x8001).unwrap();
        assert_eq!(fstat(file.as_raw_fd()).unwrap().st_flags, 0x8001);
        assert!(apply_user_flags(file.as_raw_fd(), 0x40000000).is_err());
        apply_user_flags(file.as_raw_fd(), 0).unwrap();
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn invalid_acl_is_rejected_without_touching_destination() {
        let (path, file) = fixture("invalid-acl");
        let before = Acl::capture(file.as_raw_fd()).unwrap();
        let invalid = Acl {
            flags: 0,
            entries: vec![Ace {
                principal_uuid: [1; 16],
                kind: 99,
                permissions: 2,
                flags: 0,
            }],
        };
        assert!(invalid.apply(file.as_raw_fd()).is_err());
        assert_eq!(Acl::capture(file.as_raw_fd()).unwrap(), before);
        assert!(
            BirthTime {
                seconds: 0,
                nanoseconds: -1
            }
            .apply(file.as_raw_fd())
            .is_err()
        );
        drop(file);
        std::fs::remove_file(path).unwrap();
    }

    #[test]
    fn streaming_fork_roundtrip_and_truncation() {
        let (path, file) = fixture("fork");
        let (other_path, other) = fixture("fork-copy");
        let data: Vec<u8> = (0..1048576).map(|i| (i % 251) as u8).collect();
        let mut writer = ForkWriter::create(file.as_raw_fd(), data.len() as u64).unwrap();
        for chunk in data.chunks(4093) {
            writer.write_all(chunk).unwrap();
        }
        writer.finish().unwrap();
        let mut reader = ForkReader::open(file.as_raw_fd()).unwrap().unwrap();
        assert_eq!(reader.len(), data.len() as u64);
        let mut destination = ForkWriter::create(other.as_raw_fd(), reader.len()).unwrap();
        let mut buffer = [0; 4093];
        loop {
            let read = reader.read(&mut buffer).unwrap();
            if read == 0 {
                break;
            }
            destination.write_all(&buffer[..read]).unwrap();
        }
        reader.verify_stable().unwrap();
        destination.finish().unwrap();
        let mut restored = Vec::new();
        ForkReader::open(other.as_raw_fd())
            .unwrap()
            .unwrap()
            .read_to_end(&mut restored)
            .unwrap();
        assert_eq!(restored.len(), data.len());
        assert!(restored == data);
        let mut shorter = ForkWriter::create(other.as_raw_fd(), 3).unwrap();
        shorter.write_all(b"abc").unwrap();
        shorter.finish().unwrap();
        assert_eq!(fork_size(other.as_raw_fd()).unwrap(), Some(3));
        let unfinished = ForkWriter::create(other.as_raw_fd(), 8).unwrap();
        assert!(unfinished.finish().is_err());
        drop((file, other));
        std::fs::remove_file(path).unwrap();
        std::fs::remove_file(other_path).unwrap();
    }

    #[test]
    fn fork_reader_detects_source_mutation() {
        let (path, file) = fixture("changed-fork");
        let mut writer = ForkWriter::create(file.as_raw_fd(), 8).unwrap();
        writer.write_all(b"12345678").unwrap();
        writer.finish().unwrap();
        let reader = ForkReader::open(file.as_raw_fd()).unwrap().unwrap();
        let mut replacement = ForkWriter::create(file.as_raw_fd(), 3).unwrap();
        replacement.write_all(b"abc").unwrap();
        replacement.finish().unwrap();
        assert!(reader.verify_stable().is_err());
        drop((reader, file));
        std::fs::remove_file(path).unwrap();
    }
}
