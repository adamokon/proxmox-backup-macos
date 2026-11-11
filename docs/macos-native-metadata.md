# Native macOS metadata transport

The native client uses the PBS backup/restore protocol, chunking, compression,
encryption, manifests and dynamic indexes. It does not require Docker, a VM or a
Linux helper. FUSE mount/map commands remain Linux-only.

## Representation

The `codex/native-pxar-metadata` branch uses experimental native PXAR records,
following upstream's architectural feedback. Small descriptors stay in the
metadata stream; attribute bytes and resource forks are streamed in the unified
archive or the split `.ppxar` payload stream. The new writer does not emit
synthetic xattrs, an auxiliary archive, or a metadata map. The old representation
remains readable for backups written by the previously deployed prototype.

See [the wire-format draft](native-pxar-draft.md) for the unallocated experimental
identifiers, Darwin and Windows representation, compatibility, integrity checks,
and upstream review boundaries. The root-owned deployed client continues using
the earlier format until an explicitly reviewed upgrade.

Local temporary payload storage uses authenticated AES-256-GCM with an ephemeral
process-local key and unique nonces. No plaintext temporary files are created;
spool ciphertext and keys are not uploaded. Ordinary PBS encryption/deduplication
processes the archive streams. Spools are excluded from their own backup roots.

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

The native PXAR format is an experimental proposal requiring Proxmox review.
There is no claim of official macOS support. Proxmox requests development patches
on `pbs-devel`, with a valid contributor agreement before inclusion:
https://pbs.proxmox.com/wiki/Developer_Documentation
