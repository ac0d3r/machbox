package plugin

import (
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"
)

const malwareManifest = `
manifest_version: 1
name: malware
version: 0.1.0
requires:
  macos: ">=14.0"
  sip: disabled
workflows:
  analyze:
    inputs:
      sample:  { type: file, required: true }
      timeout: { default: 5m }
    steps:
      - id: static
        run: [tools/statictool, -o, "${{ output }}", "${{ inputs.sample }}"]
        output: static.json
      - id: dynamic
        run: [tools/dynamictool, run, -ds, "${{ plugin_dir }}/DTrace/network.d", "--duration=${{ inputs.timeout }}", -o, "${{ output }}", "${{ inputs.sample }}"]
        output: dynamic.jsonl
        timeout: 10m
        continue_on_error: true
      - id: report
        when: always
        run: [tools/report, -o, "${{ output }}", "${{ steps.static.output }}", "${{ steps.dynamic.output }}"]
        output: out/report.json
`

func TestParseManifest(t *testing.T) {
	p, err := Parse([]byte(malwareManifest))
	if err != nil {
		t.Fatal(err)
	}
	wf, err := p.Workflow("analyze")
	if err != nil {
		t.Fatal(err)
	}
	if got := []string{wf.Inputs[0].Name, wf.Inputs[1].Name}; !reflect.DeepEqual(got, []string{"sample", "timeout"}) {
		t.Errorf("input order = %v", got)
	}
	if wf.Inputs[1].Type != InputString {
		t.Errorf("default input type = %q", wf.Inputs[1].Type)
	}
	if wf.Steps[0].When != WhenSuccess || wf.Steps[2].When != WhenAlways {
		t.Errorf("when = %q, %q", wf.Steps[0].When, wf.Steps[2].When)
	}
	if wf.Steps[1].TimeoutOrDefault() != 10*time.Minute || wf.Steps[0].TimeoutOrDefault() != DefaultStepTimeout {
		t.Error("timeouts not decoded")
	}

	args, err := wf.Steps[1].Args(Vars{
		Inputs:    map[string]string{"sample": "/tmp/s/inputs/sample/x.app", "timeout": "5m"},
		PluginDir: "/tmp/s/plugin",
	})
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"tools/dynamictool", "run", "-ds", "/tmp/s/plugin/DTrace/network.d", "--duration=5m",
		"-o", "dynamic.jsonl", "/tmp/s/inputs/sample/x.app"}
	if !reflect.DeepEqual(args, want) {
		t.Errorf("args = %q", args)
	}
}

func TestParseManifestErrors(t *testing.T) {
	base := "manifest_version: 1\nname: p\nworkflows:\n  w:\n"
	tests := map[string]string{
		"version":             "manifest_version: 2\nname: p\nworkflows: {w: {steps: [{id: a, run: [x]}]}}",
		"unknown field":       base + "    steps: [{id: a, run: [x], bogus: 1}]",
		"no steps":            base + "    steps: []",
		"dup id":              base + "    steps: [{id: a, run: [x]}, {id: a, run: [y]}]",
		"empty run":           base + "    steps: [{id: a, run: []}]",
		"bad output":          base + "    steps: [{id: a, run: [x], output: ../x}]",
		"dup output":          base + "    steps: [{id: a, run: [x], output: o}, {id: b, run: [x], output: o}]",
		"bad when":            base + "    steps: [{id: a, run: [x], when: sometimes}]",
		"unknown input":       base + "    steps: [{id: a, run: [x, '${{ inputs.nope }}']}]",
		"later step":          base + "    steps: [{id: a, run: [x, '${{ steps.b.output }}']}, {id: b, run: [x], output: o}]",
		"later status":        base + "    steps: [{id: a, run: [x, '${{ steps.b.status }}']}, {id: b, run: [x]}]",
		"no output":           base + "    steps: [{id: a, run: [x]}, {id: b, run: [x, '${{ steps.a.output }}']}]",
		"own output":          base + "    steps: [{id: a, run: [x, '${{ output }}']}]",
		"unknown var":         base + "    steps: [{id: a, run: [x, '${{ env.HOME }}']}]",
		"malformed":           base + "    steps: [{id: a, run: [x, '${{ inputs.a']}]",
		"file default":        base + "    inputs: {f: {type: file, default: x}}\n    steps: [{id: a, run: [x]}]",
		"unknown input field": base + "    inputs: {f: {description: a, b}}\n    steps: [{id: a, run: [x]}]",
		"bad input type":      base + "    inputs: {f: {type: int}}\n    steps: [{id: a, run: [x]}]",
		"bool default":        base + "    inputs: {f: {type: boolean, default: yes}}\n    steps: [{id: a, run: [x]}]",
		"bool required":       base + "    inputs: {f: {type: boolean, required: true}}\n    steps: [{id: a, run: [x]}]",
		"file values":         base + "    inputs: {f: {type: file, values: [a]}}\n    steps: [{id: a, run: [x]}]",
		"value default":       base + "    inputs: {f: {values: [a, b], default: c}}\n    steps: [{id: a, run: [x]}]",
		"bad constraint":      "manifest_version: 1\nname: p\nrequires: {macos: '14'}\nworkflows: {w: {steps: [{id: a, run: [x]}]}}",
		"bad env name":        base + "    env: {1BAD: x}\n    steps: [{id: a, run: [x]}]",
		"bad env tmpl":        base + "    steps: [{id: a, run: [x], env: {A: '${{ inputs.nope }}'}}]",
		"dot output":          base + "    steps: [{id: a, run: [x], output: ./.}]",
		"bad sip":             "manifest_version: 1\nname: p\nrequires: {sip: off}\nworkflows: {w: {steps: [{id: a, run: [x]}]}}",
		"bad feature":         "manifest_version: 1\nname: p\nrequires: {features: [xcode]}\nworkflows: {w: {steps: [{id: a, run: [x]}]}}",
	}
	for name, manifest := range tests {
		if _, err := Parse([]byte(manifest)); err == nil {
			t.Errorf("%s: parsed without error", name)
		}
	}
}

func TestParseArgs(t *testing.T) {
	p, err := Parse([]byte(malwareManifest))
	if err != nil {
		t.Fatal(err)
	}
	wf, _ := p.Workflow("analyze")

	tests := []struct {
		args []string
		want map[string]string
	}{
		{[]string{"x.bin"}, map[string]string{"sample": "x.bin", "timeout": "5m"}},
		{[]string{"x.bin", "--timeout", "1m"}, map[string]string{"sample": "x.bin", "timeout": "1m"}},
		{[]string{"--timeout=1m", "x.bin"}, map[string]string{"sample": "x.bin", "timeout": "1m"}},
		{[]string{"--sample", "x.bin", "2m"}, map[string]string{"sample": "x.bin", "timeout": "2m"}},
		{[]string{"--", "--odd-name"}, map[string]string{"sample": "--odd-name", "timeout": "5m"}},
	}
	for _, tt := range tests {
		got, err := wf.ParseArgs(tt.args)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseArgs(%q) = %v, %v; want %v", tt.args, got, err, tt.want)
		}
	}

	for _, args := range [][]string{{}, {"--nope", "x"}, {"x", "1m", "extra"}, {"x", "--timeout"}, {"--sample", "a", "--sample", "b"}} {
		if _, err := wf.ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%q) succeeded", args)
		}
	}
	if _, err := wf.ParseArgs([]string{"--help"}); !errors.Is(err, ErrHelp) {
		t.Errorf("--help: %v", err)
	}

	var usage strings.Builder
	wf.Usage(&usage, "machbox run malware analyze")
	if !strings.Contains(usage.String(), "[--sample] <sample> [--timeout <timeout>]") {
		t.Errorf("usage = %s", usage.String())
	}
}

func TestRequires(t *testing.T) {
	r := Requires{MacOS: ">=14.0, <16", SIP: SIPDisabled}
	for v, ok := range map[string]bool{"14.0": true, "14": true, "15.6.1": true, "13.7": false, "16.0": false, "26.1": false} {
		if err := r.CheckOS(v); (err == nil) != ok {
			t.Errorf("CheckOS(%s) = %v, want ok=%v", v, err, ok)
		}
	}
	sipOff := []string{"sip-disabled"}
	if err := r.Check("15.0", sipOff); err != nil {
		t.Error(err)
	}
	if r.Check("15.0", nil) == nil {
		t.Error("SIP enabled accepted")
	}
	if (Requires{SIP: SIPEnabled}).Check("15.0", sipOff) == nil {
		t.Error("SIP disabled accepted for sip: enabled")
	}
	if (Requires{MacOS: "==15"}).CheckOS("15.0.0") != nil {
		t.Error("==15 should match 15.0.0")
	}
	if (Requires{MacOS: ">=14"}).CheckOS("") == nil {
		t.Error("empty guest version accepted")
	}
	if (Requires{}).Check("", nil) != nil {
		t.Error("empty requirements should accept anything")
	}
	tools := Requires{Features: []string{"rosetta", "clt"}}
	if err := tools.Check("15.0", []string{"agent", "rosetta", "clt"}); err != nil {
		t.Error(err)
	}
	if err := tools.Check("15.0", []string{"rosetta"}); err == nil || !strings.Contains(err.Error(), "lacks clt") {
		t.Errorf("missing clt: err = %v", err)
	}
}

func TestWorkflowRequires(t *testing.T) {
	p, err := Parse([]byte(`
manifest_version: 1
name: p
requires: {macos: ">=14", features: [clt]}
workflows:
  a:
    steps: [{id: s, run: [x]}]
  b:
    requires: {macos: "<16", sip: disabled, features: [rosetta, clt]}
    steps: [{id: s, run: [x]}]
`))
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]Requires{
		"a": {MacOS: ">=14", Features: []string{"clt"}},
		"b": {MacOS: ">=14, <16", SIP: SIPDisabled, Features: []string{"clt", "rosetta"}},
	}
	for name, w := range want {
		if got := p.Workflows[name].Requires; !reflect.DeepEqual(got, w) {
			t.Errorf("workflow %s requires = %+v, want %+v", name, got, w)
		}
	}
	if !reflect.DeepEqual(p.Requires.Features, []string{"clt"}) {
		t.Errorf("plugin features changed: %v", p.Requires.Features)
	}
}

func TestStepEnviron(t *testing.T) {
	p, err := Parse([]byte(`
manifest_version: 1
name: p
workflows:
  w:
    inputs: {mode: {default: fast}}
    env: {PATH: /opt/homebrew/bin:/usr/bin:/bin, MODE: "${{ inputs.mode }}"}
    steps:
      - id: a
        run: [python3, tool.py]
        env: {PYTHONPATH: "${{ plugin_dir }}/lib", MODE: slow}
      - id: b
        run: [x]
`))
	if err != nil {
		t.Fatal(err)
	}
	wf, _ := p.Workflow("w")
	vars := Vars{Inputs: map[string]string{"mode": "fast"}, PluginDir: "/s/plugin"}
	env, err := wf.Steps[0].Environ(wf.Env, vars)
	if err != nil {
		t.Fatal(err)
	}
	want := []string{"MODE=slow", "PATH=/opt/homebrew/bin:/usr/bin:/bin", "PYTHONPATH=/s/plugin/lib"}
	if !reflect.DeepEqual(env, want) {
		t.Errorf("step a env = %q", env)
	}
	if env, _ := wf.Steps[1].Environ(wf.Env, vars); !reflect.DeepEqual(env, []string{"MODE=fast", "PATH=/opt/homebrew/bin:/usr/bin:/bin"}) {
		t.Errorf("step b env = %q", env)
	}
}

func TestInputTypes(t *testing.T) {
	p, err := Parse([]byte(`
manifest_version: 1
name: p
workflows:
  w:
    inputs:
      sample:   { type: file, required: true }
      disguise: { type: boolean }
      verbose:  { type: boolean, default: true }
      mode:     { values: [fast, slow], default: fast }
    steps: [{id: a, run: [x]}]
`))
	if err != nil {
		t.Fatal(err)
	}
	wf, _ := p.Workflow("w")

	tests := []struct {
		args []string
		want map[string]string
	}{
		{[]string{"x"}, map[string]string{"sample": "x", "disguise": "false", "verbose": "true", "mode": "fast"}},
		{[]string{"--disguise", "x", "--verbose=false", "--mode", "slow"},
			map[string]string{"sample": "x", "disguise": "true", "verbose": "false", "mode": "slow"}},
		{[]string{"--disguise", "true", "--verbose", "false", "x"},
			map[string]string{"sample": "x", "disguise": "true", "verbose": "false", "mode": "fast"}},
	}
	for _, tt := range tests {
		got, err := wf.ParseArgs(tt.args)
		if err != nil || !reflect.DeepEqual(got, tt.want) {
			t.Errorf("ParseArgs(%q) = %v, %v; want %v", tt.args, got, err, tt.want)
		}
	}
	for _, args := range [][]string{{"x", "--disguise=on"}, {"x", "--mode", "medium"}, {"x", "true"}} {
		if _, err := wf.ParseArgs(args); err == nil {
			t.Errorf("ParseArgs(%q) succeeded", args)
		}
	}

	var usage strings.Builder
	wf.Usage(&usage, "run")
	for _, s := range []string{"[--disguise]", "string (fast|slow)"} {
		if !strings.Contains(usage.String(), s) {
			t.Errorf("usage lacks %q:\n%s", s, usage.String())
		}
	}
}

func TestWorkflowNetwork(t *testing.T) {
	manifest := func(network string) string {
		return "manifest_version: 1\nname: p\nworkflows:\n  w:\n    network: " + network + "\n    steps:\n      - id: a\n        run: [x]\n"
	}
	for in, want := range map[string]string{"Gateway-Public": "gateway-public", "gateway": "gateway", "NAT": "nat", "none": "", `""`: ""} {
		p, err := Parse([]byte(manifest(in)))
		if err != nil {
			t.Fatalf("network %s: %v", in, err)
		}
		if got := p.Workflows["w"].Network; got != want {
			t.Errorf("network %s = %q, want %q", in, got, want)
		}
	}
	if _, err := Parse([]byte(manifest("internet"))); err == nil {
		t.Error("unknown network accepted")
	}
}

func TestWorkflowKeep(t *testing.T) {
	p, err := Parse([]byte("manifest_version: 1\nname: p\nworkflows:\n  w:\n    keep: true\n" +
		"    steps: [{id: a, run: [x]}]\n  v:\n    steps: [{id: a, run: [x]}]\n"))
	if err != nil {
		t.Fatal(err)
	}
	if !p.Workflows["w"].Keep || p.Workflows["v"].Keep {
		t.Errorf("keep = %v, %v; want true, false", p.Workflows["w"].Keep, p.Workflows["v"].Keep)
	}
}
