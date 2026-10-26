# Architecture

machbox runs macOS guests on Apple's `Virtualization.framework`. The core does three things:

- **Baseline management**: import a VirtualBuddy VM once, keep it in machbox's own bundle format.
- **Disposable runs**: every boot works on an APFS copy-on-write snapshot plus a read-only share, discarded afterwards.
- **Guest agent**: an HTTP API inside the guest, reached over virtio-vsock, that runs host-issued tasks.

```mermaid
flowchart LR
    subgraph Host["Host (~/.machbox)"]
        CLI["machbox CLI"]
        DB[("machbox.sqlite<br>baseline records")]
        GuestDMG["data/guest-SHA.dmg<br>(extracted on demand)"]
        Baseline["vms/UUID/<br>baseline bundle"]
        subgraph Run["runs/run-*/ (disposable)"]
            Snap["vm/<br>APFS snapshot"]
            Share["share/<br>read-only share"]
        end
    end

    subgraph Guest["Guest VM (macOS, SIP disabled)"]
        Agent["machbox-guest<br>HTTP over vsock :12345"]
        Proc["task processes"]
        Mount["/tmp/machbox_s*<br>virtiofs mount"]
    end

    CLI --> DB
    CLI -->|import / update-agent| GuestDMG
    GuestDMG -.->|read-only disk| Guest
    Baseline -->|clonefile| Snap
    Snap -->|boot| Guest
    Share -->|virtiofs tag 'machbox'| Mount
    CLI <-->|HTTP/1.1 over vsock| Agent
    Agent -->|exec| Proc
    Proc --> Mount
```

## Baselines

`machbox vm import <path.vbvm> <name>` reads the VirtualBuddy bundle once (`.vbdata/Config.plist`), then APFS-clones only the files machbox boots from into `~/.machbox/vms/<uuid>/`:

```
AuxiliaryStorage  HardwareModel  MachineIdentifier
Disk.img          config.json    # {"version":1,"cpu_count":…,"memory_size":…}
```

Booting never reads VirtualBuddy metadata again. Baselines imported by older versions (a whole `.vbvm` copy) are migrated in place on first load.

Import and `vm update-agent` boot the baseline with a GUI and `guest.dmg` attached. The user installs `machbox-guest.pkg` from it; the host polls the agent until a compatible `AgentVersion` answers and SIP is reported disabled. The DMG is embedded in the binary and extracted to `data/guest-<sha256[:12]>.dmg` only when needed, atomically and read-only.

## Runs

A run (`internal/vm.Run`) owns one directory, `~/.machbox/runs/run-*/`:

| Path | Purpose |
|------|---------|
| `vm/` | clones of the baseline's writable files; the baseline itself is never modified |
| `share/` | host files exposed to the guest read-only via virtiofs (`agent.ShareTag`) |
| `.lock` | exclusive `flock` held for the run's lifetime |

`Close` removes the directory. Runs whose owner died (lock acquirable) are swept by the next `NewRun`.

## Guest agent

`machbox-guest` is a LaunchDaemon in the guest, listening on vsock port `12345`. The host dials through `VZVirtioSocketDevice`; requests are plain HTTP/1.1:

| Endpoint | Description |
|----------|-------------|
| `GET /v1/info` | OS, user, SIP state, `agent_version` |
| `POST /v1/workdir` | mount the share and create a writable work dir |
| `POST /v1/exec` | run a task to completion; JSON result |
| `POST /v1/exec/stream` | stream stdout as a chunked body; exit status in `X-Task-Error` / `X-Task-Timed-Out` trailers |

Cancelling a request kills the task in the guest. A stream that hits its timeout ends normally with the output collected so far. Host and guest share `AgentVersion`; a mismatch requires `machbox vm update-agent`.

## Packages

| Package | Role |
|---------|------|
| `cmd` | CLI: `vm import/list/rename/update-agent/remove` |
| `internal/vm` | baseline lifecycle (import, update-agent, resolve) and disposable runs |
| `internal/agent` | guest agent HTTP API: server (guest) and client (host) |
| `internal/assets` | `~/.machbox` layout, embedded guest DMG |
| `internal/db` | SQLite baseline records |
| `pkg/vm` | VM instance: start/stop, state, GUI, vsock connect |
| `pkg/vm/config` | baseline bundle format, VirtualBuddy import, snapshot, `Virtualization.framework` configuration |
| `pkg/vsock` | guest-side AF_VSOCK listener |
| `guest-agent` | `machbox-guest` daemon and `.pkg` packaging |
