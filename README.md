# MachBox

A single-binary macOS malware analysis sandbox with integrated static and dynamic analysis, built on Apple native frameworks (`Virtualization.framework`, `EndpointSecurity.framework`, `DTrace`, etc.).

English | [中文](./docs/README_CN.md)

<img src="docs/imgs/machbox-reports.png" alt="Analysis Reports" width="680" />

## Supported Formats

- mach-o
- .app bundle
- zip archive(supports password extraction

## System Requirements

- **Apple Silicon Mac**
- **macOS 13+**

## Environment Setup

Only needs to be done once. After setup, you can run sample analysis repeatedly.

### 1. Prepare the Virtual Machine

Use [VirtualBuddy](https://github.com/insidegui/VirtualBuddy) to create a new macOS virtual machine:

1. When creating the VM, **uncheck "Install VirtualBuddy Guest App"**;

    <img src="docs/imgs/Disabled_VirtualBuddy_Guest_App.png" alt="Uncheck Guest App" width="350" />

2. After the VM is created and initial setup is complete, turn off VM SIP;
    - Enable **Boot in recovery mode** to enter recovery mode:

    <img src="docs/imgs/enable_Boot_in_recovery_mode.png" alt="Disable SIP" width="300" />

    - From the top menu bar, select Utilities → Terminal
    - Type `csrutil disable` and press Enter, then restart the VM.


### 2. Install Machbox Guest Agent

Before running MachBox in the VM for the first time, you need to install the Guest Agent:

```bash
machbox setup -m /path/to/your_Machbox.vbvm
```

- Open Finder; select `MachboxGuest` from the sidebar; install `machbox-guest.pkg`
  - Xcode Command Line Tools (`clang`) will be installed silently; they are required to enable DTrace probes.

- Once installation is complete, shut down the VM.

---

## Analyze Samples

```bash
machbox analyze -m /path/to/your_Machbox.vbvm /path/to/sample
```

Common options:

| Option | Description | Default |
|--------|-------------|---------|
| `-m, --vbvm` | **Required** Path to the VirtualBuddy VM bundle | — |
| `--timeout` | Dynamic analysis timeout (seconds) | `60` |
| `--password` | Password for encrypted archives | — |
| `--headless` | Run without a GUI window (auto-shutdown after analysis) | `true` |
| `--display` | Display resolution | `1920x1200` |
| `--network-mode` | Network mode (e.g., `NAT`) | Disabled |

## View Analysis Reports

All analysis results are automatically stored in a local database and can be viewed through the built-in Web UI:

```bash
machbox report-view
```

Open your browser and visit `http://127.0.0.1:8080` to browse the complete analysis reports.

## Acknowledgments

- https://github.com/blacktop/go-macho
- https://github.com/Code-Hex/vz
- https://github.com/insidegui/VirtualBuddy
