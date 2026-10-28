# Machbox

**Machbox** — a tool that runs automated workflows in disposable macOS VMs, for analysis and research.

## System Requirements

- **Apple Silicon Mac**
- **macOS 13+**

## Download

```bash
brew install ac0d3r/tap/machbox
```

Prebuilt Apple Silicon binaries are also on the [GitHub Releases](https://github.com/ac0d3r/machbox/releases) page.

```bash
curl -L -o machbox https://github.com/ac0d3r/machbox/releases/latest/download/machbox-darwin-arm64
chmod +x machbox
```

> The release binary is ad-hoc signed, macOS Gatekeeper will block it until you remove the quarantine attribute with `xattr -d com.apple.quarantine`.

## Build from Source

- Go 1.27+
- Xcode, for the macOS SDK, `codesign`, `pkgbuild`, and `hdiutil`

```bash
git clone https://github.com/ac0d3r/machbox.git
cd machbox
make build
```

The compiled binary will be at `bin/machbox`.

## Usage

- [Environment Setup](./docs/environment-setup.md): prepare and import a VirtualBuddy VM baseline.
- [Plugins](./docs/plugins.md): install, run, update and remove plugins.
- [Architecture](./docs/architecture.md): how baselines, runs, the guest agent, plugins and the network work.

## Acknowledgments

- https://github.com/Code-Hex/vz
- https://github.com/insidegui/VirtualBuddy
- https://github.com/containers/gvisor-tap-vsock
