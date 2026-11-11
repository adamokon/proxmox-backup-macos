# Client backports reviewed on 11 November 2026

These changes apply to both the Homebrew client branch and the native PXAR
proposal. They retain the branch's existing archive representation.

- Validate plain keys before use and convert decrypted key bytes with checked
  length instead of panicking. Based on Proxmox commits `a23876b82f2c`,
  `6cd68788c200`, and the IV/tag framing discussion from 10 November. IV and tag
  lengths are separate constants, and encrypted input must contain ciphertext.
- Stop the reusable-chunk range at an equal exclusive end, following accepted
  Proxmox commit `3a7518533b2a`. The upstream boundary cases are regression tests.
- Render datastore status without percentages when total space is zero, and
  return errors for malformed numeric values. Based on Christian Ebner's
  `[PATCH proxmox-backup v2 14/43]` of 6 November. Percentage arithmetic uses u128
  intermediates so valid u64 counters cannot overflow.
- Declare Rust 1.91, required by the pinned proxmox-sys dependency's
  `PathBuf::add_extension`. CI checks this compiler in addition to the existing
  pinned 1.99.1 test toolchain.

Sources:

- <https://lore.proxmox.com/pbs-devel/20261021164112.464267-1-c.ebner@proxmox.com/T/>
- <https://lore.proxmox.com/pbs-devel/1794301542.iv0x4kkfm6.astroid@yuna.none/T/>
- <https://lore.proxmox.com/pbs-devel/20261109133900.426552-1-c.ebner@proxmox.com/T/>
- <https://lore.proxmox.com/pbs-devel/20261106172235.890542-15-c.ebner@proxmox.com/T/>
- <https://blog.rust-lang.org/2025/10/30/Rust-1.91.0/>

The original baseline remains PBS v4.2.8 (`78f77d53718b`). Official refs checked
on 11 November include v4.2.10 (`1df6dff9c0ac`) and master
`68577e65400958d9f7e76a7722669fb359b69d4b`. This is a scoped backport, rather
than a complete update to that release. Full upstream rebasing and independent
human review remain outstanding. RustSec RUSTSEC-2021-0039 still lists no
patched endian_trait release; the existing local compatibility fork is retained.
