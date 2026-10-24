class ProxmoxBackupClient < Formula
  desc "Native macOS client for Proxmox Backup Server (experimental port)"
  homepage "https://github.com/adamokon/proxmox-backup-macos"
  license "AGPL-3.0-only"
  head "https://github.com/adamokon/proxmox-backup-macos.git", branch: "codex/macos-client-port"

  depends_on "pkgconf" => :build
  depends_on "rust" => :build
  depends_on "openssl@3"
  depends_on "zstd"
  depends_on :macos

  def install
    ENV["OPENSSL_DIR"] = Formula["openssl@3"].opt_prefix
    ENV["ZSTD_SYS_USE_PKG_CONFIG"] = "1"
    system "/usr/bin/python3", "scripts/macos/apply-patches.py"
    # The upstream .cargo/config redirects to Debian's packaged registry.
    # Cargo must start outside that directory and use the explicit manifest.
    Dir.mktmpdir("pbs-cargo") do |driver|
      cd driver do
        system "cargo", "build", "--locked", "--release", "--package", "proxmox-backup-client",
               "--manifest-path", buildpath/"Cargo.toml", "--target-dir", buildpath/"native-target"
      end
    end
    bin.install "native-target/release/proxmox-backup-client"
    doc.install "README.macos.md", "docs/macos-native-metadata.md"
  end

  test do
    assert_match "proxmox-backup-client", shell_output("#{bin}/proxmox-backup-client help 2>&1")
  end
end
