# Source provenance and history

The original upstream baseline is PBS v4.2.8, commit
`78f77d53718b351bebacfa4f56f85134616e0b02`, from
https://git.proxmox.com/git/proxmox-backup.git.

An older upstream commit contains a test blob exceeding GitHub's 100 MB Git
object limit. GitHub rejected a direct history push. The canonical local source
repository and independent history archives have not been rewritten. GitHub
instead publishes an exact source snapshot baseline followed by the port diff.
GitHub commit IDs therefore differ from the canonical history. The publication
repository's UPSTREAM.json binds the original commit/tree and canonical port
commit to history bundle checksums. This is a publication projection, not a
replacement for the original history.

The source-history prerelease contains Git bundles for PBS and the four pinned
official dependency repositories, plus a SHA-256 manifest. It is source archival
material, not a working client release or a security endorsement. Verify the
manifest and run `git bundle verify` before restoring a bundle. Cloning the PBS
bundle restores the original history and canonical port commits.

The dependency bundles provide original histories for vendor/proxmox,
vendor/pxar, vendor/pathpatterns and vendor/proxmox-fuse. To restore offline,
initialize the submodules, set each submodule's URL to its verified local bundle,
and update using an explicitly trusted file transport, then apply the patches
with `python3 scripts/macos/apply-patches.py`. The official submodule URLs in
.gitmodules remain usable for ordinary online builds.

Cargo.lock describes registry dependencies separately. A Git bundle does not
include crates.io source archives, a Rust toolchain or Homebrew libraries. Those
require their own preserved vendor/installer artifacts and provenance manifests.
No passwords, tokens, Keychain material, production configuration or backup
contents belong in these archives.
