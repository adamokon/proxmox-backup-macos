#!/usr/bin/env python3
"""Apply reviewed Darwin dependency patches to the pinned official submodule."""
from pathlib import Path
import subprocess
import sys

root = Path(__file__).resolve().parents[2]
patches = [
    ("proxmox", "9b5bf494b1759adc0b2db477411a573edf7bce8c", name)
    for name in ("proxmox-time-darwin.patch", "proxmox-sys-darwin-xattrs.patch",
                 "proxmox-sys-darwin-platform.patch", "proxmox-compression-darwin.patch",
                 "proxmox-uuid-darwin.patch", "proxmox-sys-darwin-directories.patch", "proxmox-sys-mmap-alignment.patch")
] + [("pathpatterns", "5323cbe49ae5d592eb8a3fa2e215550e83dd7fba", "pathpatterns-darwin.patch")]
patches += [("pxar", "091a8a382d0d6fc71025351fb35c51b1f3b0074d", "pxar-darwin.patch")]
pending = []
for module, expected, name in patches:
    repository = root / "vendor" / module
    head = subprocess.check_output(["git", "-C", str(repository), "rev-parse", "HEAD"], text=True).strip()
    if head != expected:
        sys.exit("Dependency commit mismatch; review/rebase patches before applying")
    argv = ["git", "-C", str(repository), "apply"]
    patch = root / "scripts/macos" / name
    already = subprocess.run(argv + ["--reverse", "--check", str(patch)], capture_output=True)
    if already.returncode == 0:
        print(name + " is already applied")
    else:
        subprocess.run(argv + ["--check", str(patch)], check=True)
        pending.append((argv, patch))
for argv, patch in pending:
    subprocess.run(argv + [str(patch)], check=True)
    print("Applied " + patch.name)
