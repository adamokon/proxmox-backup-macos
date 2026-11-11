# Native macOS client port: implementation in progress

This tree starts from the complete official PBS history at v4.2.8,
`78f77d53718b351bebacfa4f56f85134616e0b02`. It is not a working macOS client yet.
Backup/restore on native macOS has not been demonstrated. Do not use it for
production backups or claim complete Apple metadata support.

Initialize the pinned official dependencies with `git submodule update --init`.
Run `python3 scripts/macos/apply-patches.py` to apply the reviewed dependency
patches. Patches remain in this repository so fresh clones do not depend on
unpublished submodule commits. The root Cargo overrides use these local sources.
The tracked Cargo.lock pins the initial dependency resolution. Invoke Cargo
from outside the source directory with an explicit `--manifest-path`: the
upstream `.cargo/config.toml` otherwise redirects crates.io to Debian's registry.

The first Darwin implementation change is in proxmox-sys xattrs. It uses the
native fd-based Darwin syscall signatures and accepts Apple's attribute names.
Resource forks can return a successful prefix when the buffer is too small, so
the reader probes size and checks it again after reading. Changes during reading
are retried at most eight times. Values over 64 MiB explicitly return E2BIG;
streaming archive support is required to lift that temporary limit. Nothing
should interpret this failure as permission to silently omit metadata.

An isolated native harness using the actual changed xattr module and original
proxmox-io sources passes its two tests, including a byte-exact 1 MiB resource
fork after renaming the still-open file. The harness uses offline crates.io
sources, a separate non-login UID, read-only source, no network and a bounded
native Cargo verifier. Linux regression and full-client compilation remain
required. This does not solve the separate 64 KiB PXAR xattr record limit.

Still required: client/server dependency separation; Darwin ACL UUID and ACE
ordering; flags and birthtime; large fork archive representation; secure restore
against symlink/hardlink attacks; sparse files; APFS case/Unicode collision
handling; placeholder policy; repeated native backup/restore and encryption
tests against PBS; supported OS and architecture matrix; packaging and upstream
submission. Keep Linux CLI options and environment variable behavior compatible.

Source/security review date: 2026-10-24. Official PBS security advisories were
checked at https://forum.proxmox.com/threads/proxmox-backup-server-security-advisories.149332/.
The selected baseline includes the published client fixes through 4.2.8. Helper
repository HEADs are pinned as Git submodule objects. Upstream commit signatures
are not available for every dependency; no blanket safety claim is made. The
new crates.io lockfile still requires a dependency vulnerability audit.
