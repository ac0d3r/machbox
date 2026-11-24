# Plugins

A plugin bundles tools and workflows in `plugin.yml`; `machbox run` executes one workflow in a disposable VM. Plugins are installed from GitHub releases into `~/.machbox/plugins/<owner>/<repo>/`.

## Install

```sh
machbox plugin install https://github.com/user/machbox-plugin                  # latest release
machbox plugin install https://github.com/user/machbox-plugin --version v0.1.0 # a given release
```

Installing a repository that is already installed fails (use `plugin update`); `--force` reinstalls it.

The repository identifies a plugin. Commands below take `owner/repo`, or the plugin's name (`name` in its `plugin.yml`, here `example`) while only one installed plugin has it.

```sh
machbox plugin list
REPO                 NAME     VERSION
user/machbox-plugin  example  0.1.0
```

Set `GITHUB_TOKEN` if GitHub rate-limits the requests.

## Run

```sh
machbox run example                       # list its workflows
machbox run example analyze --help        # a workflow's inputs
machbox run example analyze ./sample.zip
```

Flags go before the plugin:

| Flag | |
|------|-|
| `-m`, `--vm <uuid-or-name>` | baseline to use (default: the only one meeting the workflow's requirements) |
| `--network <mode>` | `none`, `nat`, `gateway` or `gateway-public` ([what each reaches](./architecture.md#network)); default: the workflow's `network`, else `none` |
| `--pcap` | with a gateway network: save guest traffic to `network.pcap` in the job directory |
| `--gui` | show the VM window |
| `--show-output` | also print step output |

An installed plugin is a plain directory: edit its `plugin.yml` (`~/.machbox/plugins/<owner>/<repo>/`) to change, say, a workflow's `network`. `plugin update` replaces the edits.

The job directory, `~/.machbox/jobs/<id>/`, is printed when the job ends: step logs, outputs and `job.json`. `machbox job prune` removes the finished ones, after asking (`-y` to skip).

`<plugin>` may also be a plugin directory, which takes precedence over an installed plugin of the same name, e.g. while developing one: `machbox run ./machbox-plugin analyze ./sample.zip`.

## Update and remove

```sh
machbox plugin update user/machbox-plugin   # to the latest release, if its tag changed
machbox plugin remove user/machbox-plugin
```

## Writing a plugin

See [Plugins and jobs](./architecture.md#plugins-and-jobs) for the manifest and how steps run, and `testdata/plugins/demo` for a working example. To be installable, a release needs one `.tar.gz` asset holding `plugin.yml` and the built tools, at its root or in a single top-level directory. Downloads are checked against the SHA-256 digest GitHub reports for the asset.

[`plugin.schema.json`](./plugin.schema.json) describes the manifest for editors. Map it to `**/plugin.yml` (VS Code: `"yaml.schemas"` in settings) or start the file with `# yaml-language-server: $schema=<path to it>`; otherwise editors may apply SchemaStore's Bukkit `plugin.yml` schema and report a missing `main`.
