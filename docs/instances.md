# Instances

`machbox run` boots a disposable snapshot and discards it. An **instance** is the
opposite: a clone of a baseline that keeps its disk across shutdowns, for work that
must persist in the guest, such as a tool you sign in to once.

## Start an Instance

```bash
machbox start cc --vm <baseline> --network gateway-public --share ~/sandbox/foo   # first time: clone the baseline into "cc", then boot it
machbox start cc --gui                                                           # later: boot "cc" again, same network and shares, with the window
```

| Flag | |
|------|-|
| `--vm <uuid-or-name>` | baseline to create the instance from; only when the instance does not exist yet |
| `--network <mode>` | `none`, `nat`, `gateway` or `gateway-public`; default: the instance's last, else `none` |
| `--share <dir>` | share a host directory read-write; repeatable |
| `--share-ro <dir>` | share a host directory read-only; repeatable |
| `--no-share` | start without shares, and forget the saved ones |
| `--gui` | show the VM window |

The clone is instant and takes no extra space until it diverges from the baseline.
`--network` and the share flags are saved in the instance: a start without them uses
what it last started with. Share flags replace the saved shares as a whole, and
`--no-share` removes them. Instance names are unique across baselines.

`machbox start` stays in the foreground until the guest shuts down, the window is
closed, or you press Ctrl-C or close the terminal, which shuts the guest down cleanly through its agent
(forced off after two minutes); a second Ctrl-C forces it off at once. The host
does not idle-sleep meanwhile. With a network, the `guest ready` line shows the
guest's IP address; with `nat` the host can reach it, e.g. with `ssh` once Remote Login
is on in the guest. To keep an instance running after
you log out of the terminal, start it in `tmux` or `screen`.

## Shared Directories

Shared directories appear in the guest under `/Volumes/My Shared Files/<name>`, with
nothing to mount; `<name>` is the directory's base name, so two shares cannot have the
same one. Shares are part of the VM configuration, fixed until the instance stops.

A read-write share lets the guest change anything in it, including what the host runs
from it later: git hooks and `core.hooksPath`/`core.fsmonitor` in `.git/config`,
`.envrc`, build scripts, editor tasks. For an agent working on a project, share a
separate clone rather than your working copy, and bring changes back with `git fetch`
from it and a review of the diff.

## Manage Instances

```bash
machbox instance list          # name, baseline, network, shares, running or stopped
machbox instance remove cc     # delete a stopped instance and its disk, after asking (-y: don't ask)
```

An instance lives in its baseline's directory (`~/.machbox/vms/<uuid>/instances/<name>/`).
`machbox vm remove` lists the baseline's instances and asks before removing them
with it; it refuses while one is running.

## Isolation

`machbox run` never uses an instance, so what you sign in to in one stays out of
plugin runs. Changes to the baseline (`machbox vm setup`) do not reach existing
instances, and an instance's changes never reach the baseline. Use
`--network gateway-public` to keep the guest off your LAN and the host; with `nat`
or `gateway` it reaches whatever the host can.
