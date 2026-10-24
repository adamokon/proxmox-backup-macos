# Native macOS metadata transport

The native client uses the PBS backup/restore protocol, chunking, compression,
encryption, manifests and dynamic indexes. It does not require Docker, a VM or a
Linux helper. FUSE mount/map commands remain Linux-only.

## Representation

Each normal PXAR entry carries a versioned `user.proxmox.macos.v1` envelope in
ordinary PXAR extended attribute records. Its checked JSON payload is split into
60 KiB records, bounded to 4 MiB and SHA-256 checked. It describes the birth time,
ordered Darwin ACL entries using UUID principals, original BSD flags, and native
attribute names and content references. Actual native attribute names cannot
collide with the envelope: all native names are represented inside it.

Attribute bytes, including resource forks, are content-addressed files in one
additional ordinary PXAR archive in the same PBS snapshot. This supports forks
larger than the PXAR xattr record size while keeping the existing wire format.
`macos-metadata.json.blob` associates primary archives with the auxiliary archive
and bounds its file count and total bytes. Its manifest entry is protected using
the selected PBS crypt mode. The names of additional archives are chosen to avoid
user archive names. Linux can inspect/download these standard archives; applying
Darwin metadata requires this native client.

A local temporary spool uses authenticated AES-256-GCM with an ephemeral random
process-local key, unique nonces, and a plaintext SHA-256 content index. Spool
ciphertext and keys are never uploaded. The client authenticates and streams
plaintext into the normal PBS pipeline, preserving deterministic content for
deduplication. Restoring the auxiliary archive uses the same encrypted spool.
The spool is explicitly excluded if it falls beneath a selected backup root.
Its required free space is approximately the unique native attribute data size.

## Filesystem behavior

* Native descriptor-based xattr APIs preserve binary values; resource forks use
  positional streaming. Darwin's API limits individual forks to 4 GiB here;
  larger forks cause an explicit error.
* ACLs preserve ordered allow/deny UUID entries, permissions and inheritance
  flags; no Linux POSIX ACL conversion or account-name translation is implied.
* Birthtime and modification time preserve nanoseconds. Immutable/append flags
  are applied after file data, attributes and directory children.
* Symlink metadata is read/written through an `O_SYMLINK` descriptor. Relative
  hardlink target traversal rejects symlink directories and parent traversal.
* Destination filesystem name aliases are checked before overwriting entries.
  An archive requiring distinct case or Unicode variants needs a destination
  filesystem capable of representing those names distinctly.
* Dataless iCloud placeholders cause an explicit failure. Download files first.
  The client does not silently treat an undownloaded placeholder as backed up.
* Darwin regular files that change size, ctime or mtime during capture cause an
  error. A live directory tree is not an atomic filesystem snapshot.
* Unknown or privileged BSD flags cause a restore error rather than being lost.
  `UF_COMPRESSED` is not reapplied to a decompressed data fork.
* Exact protected attributes `com.apple.provenance` and `com.apple.macl` remain
  archived, but macOS can forbid setting them on the restored object. An EPERM
  for these names produces an explicit warning. Other xattr errors are fatal.

Full Disk Access and access to protected source folders are macOS permission
requirements; this port neither grants nor bypasses them. API tokens and client
encryption keys should stay outside the source repository and backup scripts.

## Upstream review

The envelope/auxiliary archive design is a proposal requiring Proxmox review.
There is no claim of official macOS support. Proxmox requests development patches
on `pbs-devel`, with a valid contributor agreement before inclusion:
https://pbs.proxmox.com/wiki/Developer_Documentation
