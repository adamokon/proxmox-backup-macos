# Native PXAR metadata draft (30 October 2026)

This branch implements the direction requested by Christian Ebner:
https://lore.proxmox.com/pbs-devel/bdf117e2-83f7-4eaf-9300-20e4426c66f4@proxmox.com/

It is an experimental wire-format proposal, not an upstream allocation or a
production migration. It must be reviewed together with pxar and the Linux
reader/server changes before it can become an official format. The existing
Homebrew installation and hourly backup job are not upgraded by this change.

## Framing and compatibility

Existing Version1 and Version2 encoder entrypoints retain their wire format.
`Encoder::new_with_native` explicitly selects `NativeDraft`, with unallocated
version `0x8000000000000001`. Three unallocated draft record identifiers
`0xb1b78c2b1e7a0001..3` denote native metadata, attribute descriptors and native
payloads. These constants are deliberately not named "version 3". They need
upstream allocation or replacement; an old decoder rejects the version.

The new decoder reads old versions, rejects unknown future versions and rejects
native records hidden in old versions. The macOS restore path also reads the
previous prototype's manifest map, xattr envelope and auxiliary archive. New
backups contain none of those synthetic xattrs, maps or auxiliary archives.
No PBS transport, chunking, encryption or manifest changes are required.
Old PBS archive browsers cannot interpret the draft without the reader patches.

All integers are explicit little endian, with checked lengths. No Rust ABI,
lengthless OS ACL blob, JSON or host-endian structure is stored in native records.
Metadata must occur once, after ENTRY and before native attribute descriptors.
Other standard PXAR metadata and content records retain their ordering.

## Native metadata record

The native metadata record starts with a u32 extension schema (1), then u32
platform (1 Darwin, 2 Windows). The schema is distinct from the archive version.

Darwin: birth seconds i64, birth nanoseconds u32, BSD flags u32, ACL-presence u32,
ACL flags u32, ACE count u32. Each ordered ACE contains a 16-byte principal UUID,
kind u32 (allow/deny), flags u32 and permission mask u64. An absent ACL means
capture was disabled; an explicitly empty ACL is distinct. At most 128 ACEs.

Windows: native file attributes u32 followed by creation, access, write and change
FILETIMEs (u64 each). No narrowing to Unix timestamps occurs. Attribute kinds
cover self-relative security descriptors, reparse data and named data streams.
The format preserves Windows payload bytes without applying Windows semantics on
Darwin. Windows filesystem capture/restore is not implemented or claimed.
Security/reparse payloads are bounded to 64 KiB. Stream names are validated UTF-16LE
(up to 255 code units), without NUL, path separators or colon.

## Native attribute descriptor and payload

A descriptor contains kind u32, storage u32 (0 unified archive, 1 payload stream),
payload header offset u64, payload byte size u64, SHA-256 digest (32 bytes), then
native attribute/stream name bytes. Darwin names are nonempty, NUL-free and at
most 127 bytes. Names/kinds must be unique per entry, with at most 4096 attributes.
There is no path or user-controlled temporary filename in the descriptor.

In unified PXAR, each descriptor is immediately followed by its NATIVE_PAYLOAD
record and bytes. In split PXAR, the descriptor stays in `.mpxar`; its payload
record and bytes are written into `.ppxar`, before the corresponding data fork.
The same representation supports directory and symlink attributes. Empty
attributes have a real zero-length payload record. References are monotonically
consumed for sequential restore; random access validates headers and ranges.
Large native values never occupy the metadata stream in split archives.

Metadata-only decoding does not need `.ppxar`, and random metadata lookup does
not fetch native payloads even if a payload reader is available. Size and digest
remain available for change detection. Content extraction without the payload
stream fails explicitly, rather than reading unrelated metadata as content.

## Streaming, integrity and filesystem behavior

The encoder reads authenticated application-owned streams in 64 KiB chunks. The
decoder materializes values through a payload sink, verifying declared lengths
and SHA-256 before publishing them to restoration. Local payload spools use
AES-256-GCM with a per-process random key and per-object nonce. No plaintext
spooling or archive-provided filesystem path is used. Normal PBS client encryption
and deduplication apply to the deterministic emitted archive bytes.

Native records use an overall wire payload bound of 1 TiB. Darwin's current
positional resource-fork API is limited to 4 GiB; exceeding its limit fails
explicitly. Ordinary xattrs have a separate kernel-size bound. A full backup
still reads native values to compute digests; metadata records alone do not
prove that a changing live filesystem is consistent. No APFS snapshot or iCloud
placeholder download is introduced here.

Ownership/mode, ordered UUID ACLs, birthtime, mtime and user BSD flags are restored
via held descriptors; immutable flags remain deferred. Symlink modes use
O_SYMLINK and never chmod the target. Destination alias detection remains active.
macOS-managed provenance/macl can still be rejected by the kernel, with explicit
warnings and original values retained in the archive. Unsupported cross-platform
native restoration fails rather than silently discarding metadata.

## Tests and review boundaries

`pbs-client/tests/native_pxar.rs` contains platform-independent wire regressions;
it also runs within the isolated Darwin filesystem test entrypoint. It covers
both platforms and archive variants, metadata-only traversal, random metadata
lookup, old versions, wrong versions, malformed metadata, duplicate names,
invalid timestamps/stream names, truncated streams and digest corruption.
`macos_filesystem.rs` checks actual Darwin restore for unified/split archives,
large resource forks, binary xattrs, Unicode, hardlinks, symlinks and BSD metadata.

Before upstream submission, agree on record allocation and Windows semantic
coverage, rebase on the then-current upstream revision, split the series by
repository, and obtain independent human review. The endian_trait compatibility
fork is inherited from the earlier prototype; it is not a new requirement of this
extension. Upstream plans to phase out that dependency and has not identified a
current PBS panic path for the advisory. No mail or patch series is sent by the
implementation/testing workflow.

Native attribute descriptors currently compare including their storage location,
so the metadata optimization conservatively re-encodes files carrying native
attributes instead of reusing file payload ranges from an earlier split stream.
This avoids mixing newly emitted native payloads with injected old chunk ranges;
chunk deduplication still reused 100% of the repeated synthetic archive streams.
A semantic-equality/reuse optimization must account for both kinds of payload
before enabling file-read elision. This affects performance, not restore fidelity.
