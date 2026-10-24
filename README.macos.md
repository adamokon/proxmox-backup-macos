# Proxmox Backup Client for macOS — experimental port

This is a work in progress based on the original Proxmox Backup source,
starting at PBS v4.2.8. The canonical development repository retains the complete
upstream history. GitHub uses a separate snapshot baseline because an older
upstream test blob exceeds GitHub's 100 MB limit. Full unmodified history is
distributed separately as Git bundle source archives with checksums; see
[archive notes](SOURCE-ARCHIVES.md). It is not affiliated with or
officially supported by Proxmox. There is no working macOS client release yet.

The objective is a native CLI retaining Linux backup command syntax, PBS
deduplication and client-side encryption, with explicit handling of macOS
filesystem metadata. Docker and a Linux guest are not runtime requirements.
OpenSSL and zstd for native development come from Homebrew; Darwin filesystem
and ACL operations should use the system APIs.

Implemented so far:

- Official dependency repositories pinned as submodules, with reproducible
  patches and a tracked Cargo.lock.
- Separation of server storage/configuration dependencies from client data
  formats. Linux server functionality retains its feature gate.
- Darwin system-library fixes, descriptor-based xattrs, 16 KiB page alignment
  for fixed and dynamic indexes, and native resizing of fixed-index mappings.
- Descriptor-relative hardlink parent resolution rejecting symlinks, absolute
  paths and parent traversal.
- A native Apple Silicon offline verifier using a separate non-login build UID,
  read-only source, no network, bounded logs and source/toolchain provenance.

Verified locally on native Apple Silicon macOS: 21 PBS format tests; 8 path
matching tests and 1 doctest; 3 isolated filesystem tests including a byte-exact
1 MiB Resource Fork and directory escape rejection. These are component tests.
Linux format regression is checked separately in CI. Full native backup and
restore have not passed, and no installation package is provided.

The full client currently reaches remaining Darwin errors in the archive layer.
Still required: ordered UUID-based ACLs, birthtime and flags, fork streaming and
archive representation, symlink handling, restore collision checks, placeholder
policy, packaging and native PBS integration. See [port notes](scripts/macos/README.md).
Do not use this tree to protect your only copy of any data.

The initial crates.io dependency audit flagged endian_trait and Hickory in the
client graph. This is not a release-approved dependency closure. Resolve or
document each finding before a release; do not treat successful tests as a
security assessment.

Proxmox licenses and copyright notices remain in force. Upstream contributions
should follow Proxmox's contribution and mailing-list process after independent
review and completion of the relevant tests.
