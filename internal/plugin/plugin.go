// Package plugin loads machbox plugins: a directory with a plugin.yml
// manifest describing workflows, and the command-line tools those workflows
// run inside the guest.
package plugin

import (
	"bytes"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	// ManifestName is the manifest file at the root of a plugin directory.
	ManifestName = "plugin.yml"
	// ManifestVersion is the plugin contract (manifest schema, template
	// variables, guest layout) this machbox implements.
	ManifestVersion = 1

	// DefaultStepTimeout applies to steps without a timeout.
	DefaultStepTimeout = 10 * time.Minute
)

var (
	identRe  = regexp.MustCompile(`^[a-z][a-z0-9_-]*$`)
	envKeyRe = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
)

// Plugin is a loaded and validated plugin.
type Plugin struct {
	// Dir is the plugin directory on the host.
	Dir string `yaml:"-"`

	ManifestVersion int                  `yaml:"manifest_version"`
	Name            string               `yaml:"name"`
	Version         string               `yaml:"version"`
	Requires        Requires             `yaml:"requires"`
	Workflows       map[string]*Workflow `yaml:"workflows"`
}

// Workflow is a named sequence of steps run in one guest.
type Workflow struct {
	Name   string `yaml:"-"`
	Inputs Inputs `yaml:"inputs"`
	// Env is set for every step; a step's own env overrides it.
	Env   map[string]string `yaml:"env"`
	Steps []*Step           `yaml:"steps"`
}

// InputType is the kind of value an input takes.
type InputType string

const (
	// InputString is passed to tools as is.
	InputString InputType = "string"
	// InputFile is a host path; the file or directory is copied into the
	// guest workdir and tools receive its path relative to it.
	InputFile InputType = "file"
)

// Input is a workflow parameter.
type Input struct {
	Name        string    `yaml:"-"`
	Type        InputType `yaml:"type"`
	Required    bool      `yaml:"required"`
	Default     string    `yaml:"default"`
	Description string    `yaml:"description"`
}

// Inputs keeps the declaration order of the inputs mapping; positional
// arguments are assigned in that order.
type Inputs []*Input

// UnmarshalYAML decodes a mapping of input name to Input.
func (in *Inputs) UnmarshalYAML(node *yaml.Node) error {
	if node.Kind != yaml.MappingNode {
		return fmt.Errorf("line %d: inputs must be a mapping", node.Line)
	}
	for i := 0; i < len(node.Content); i += 2 {
		input := &Input{}
		if err := node.Content[i+1].Decode(input); err != nil {
			return err
		}
		input.Name = node.Content[i].Value
		*in = append(*in, input)
	}
	return nil
}

// Lookup returns the input called name, or nil.
func (in Inputs) Lookup(name string) *Input {
	for _, input := range in {
		if input.Name == name {
			return input
		}
	}
	return nil
}

// When selects which job state a step runs in.
type When string

const (
	// WhenSuccess runs the step only if no earlier step failed (default).
	WhenSuccess When = "success"
	// WhenFailure runs the step only after an earlier step failed.
	WhenFailure When = "failure"
	// WhenAlways runs the step regardless.
	WhenAlways When = "always"
)

// Runs reports whether a step with this condition runs given whether an
// earlier step has failed.
func (w When) Runs(failed bool) bool {
	switch w {
	case WhenAlways:
		return true
	case WhenFailure:
		return failed
	default:
		return !failed
	}
}

// Step runs one command in the guest workdir.
type Step struct {
	ID string `yaml:"id"`
	// Run is the argv; templates are expanded in every element. A relative
	// command containing a slash (tools/x) is resolved in the plugin
	// directory, a bare name is looked up in the guest PATH.
	Run []string `yaml:"run"`
	// Output is a file the step writes, relative to the workdir. It is
	// copied back to the job directory after the step.
	Output string `yaml:"output"`
	// Env values are templates like run arguments.
	Env             map[string]string `yaml:"env"`
	Timeout         time.Duration     `yaml:"timeout"`
	ContinueOnError bool              `yaml:"continue_on_error"`
	When            When              `yaml:"when"`
}

// Load reads and validates the plugin in dir.
func Load(dir string) (*Plugin, error) {
	dir, err := filepath.Abs(dir)
	if err != nil {
		return nil, err
	}
	// #nosec G304 -- the user chooses which plugin to load.
	data, err := os.ReadFile(filepath.Join(dir, ManifestName))
	if err != nil {
		return nil, fmt.Errorf("read plugin manifest: %w", err)
	}
	p, err := Parse(data)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", filepath.Join(dir, ManifestName), err)
	}
	p.Dir = dir
	return p, nil
}

// Parse decodes and validates a manifest.
func Parse(data []byte) (*Plugin, error) {
	dec := yaml.NewDecoder(bytes.NewReader(data))
	dec.KnownFields(true)
	var p Plugin
	if err := dec.Decode(&p); err != nil {
		return nil, err
	}
	if err := p.validate(); err != nil {
		return nil, err
	}
	return &p, nil
}

// Workflow returns the workflow called name.
func (p *Plugin) Workflow(name string) (*Workflow, error) {
	wf, ok := p.Workflows[name]
	if !ok {
		return nil, fmt.Errorf("plugin %s has no workflow %q", p.Name, name)
	}
	return wf, nil
}

func (p *Plugin) validate() error {
	if p.ManifestVersion != ManifestVersion {
		return fmt.Errorf("manifest_version %d is not supported (machbox implements manifest_version %d)",
			p.ManifestVersion, ManifestVersion)
	}
	if !identRe.MatchString(p.Name) {
		return fmt.Errorf("name %q must match %s", p.Name, identRe)
	}
	if err := p.Requires.validate(); err != nil {
		return fmt.Errorf("requires: %w", err)
	}
	if len(p.Workflows) == 0 {
		return errors.New("no workflows")
	}
	for name, wf := range p.Workflows {
		if !identRe.MatchString(name) {
			return fmt.Errorf("workflow name %q must match %s", name, identRe)
		}
		if wf == nil {
			return fmt.Errorf("workflow %s is empty", name)
		}
		wf.Name = name
		if err := wf.validate(); err != nil {
			return fmt.Errorf("workflow %s: %w", name, err)
		}
	}
	return nil
}

func (wf *Workflow) validate() error {
	seen := map[string]bool{}
	for _, in := range wf.Inputs {
		if !identRe.MatchString(in.Name) {
			return fmt.Errorf("input name %q must match %s", in.Name, identRe)
		}
		if seen[in.Name] {
			return fmt.Errorf("duplicate input %s", in.Name)
		}
		seen[in.Name] = true
		switch in.Type {
		case "":
			in.Type = InputString
		case InputString, InputFile:
		default:
			return fmt.Errorf("input %s: unknown type %q", in.Name, in.Type)
		}
		if in.Type == InputFile && in.Default != "" {
			return fmt.Errorf("input %s: file inputs cannot have a default", in.Name)
		}
	}

	if err := validateEnv(wf.Env); err != nil {
		return err
	}
	if len(wf.Steps) == 0 {
		return errors.New("no steps")
	}
	ids := map[string]*Step{}
	outputs := map[string]string{}
	for i, st := range wf.Steps {
		if st == nil {
			return fmt.Errorf("step %d is empty", i+1)
		}
		if !identRe.MatchString(st.ID) {
			return fmt.Errorf("step %d: id %q must match %s", i+1, st.ID, identRe)
		}
		if ids[st.ID] != nil {
			return fmt.Errorf("duplicate step id %s", st.ID)
		}
		if err := st.validate(wf, ids); err != nil {
			return fmt.Errorf("step %s: %w", st.ID, err)
		}
		if st.Output != "" {
			if other, ok := outputs[st.Output]; ok {
				return fmt.Errorf("steps %s and %s write the same output %s", other, st.ID, st.Output)
			}
			outputs[st.Output] = st.ID
		}
		ids[st.ID] = st
	}
	return nil
}

func (st *Step) validate(wf *Workflow, earlier map[string]*Step) error {
	if len(st.Run) == 0 || st.Run[0] == "" {
		return errors.New("run is empty")
	}
	if st.Output != "" && (!filepath.IsLocal(st.Output) || filepath.Clean(st.Output) == ".") {
		return fmt.Errorf("output %q must be a relative path inside the workdir", st.Output)
	}
	if st.Timeout < 0 {
		return errors.New("timeout must not be negative")
	}
	switch st.When {
	case "":
		st.When = WhenSuccess
	case WhenSuccess, WhenFailure, WhenAlways:
	default:
		return fmt.Errorf("unknown when %q (success, failure, always)", st.When)
	}

	// Expanding against placeholder values checks every reference.
	vars := Vars{Inputs: map[string]string{}, Outputs: map[string]string{}}
	for _, in := range wf.Inputs {
		vars.Inputs[in.Name] = ""
	}
	for id, prev := range earlier {
		if prev.Output != "" {
			vars.Outputs[id] = prev.Output
		}
	}
	if err := validateEnv(st.Env); err != nil {
		return err
	}
	if _, err := st.Args(vars); err != nil {
		return err
	}
	_, err := st.Environ(wf.Env, vars)
	return err
}

func validateEnv(env map[string]string) error {
	for k := range env {
		if !envKeyRe.MatchString(k) {
			return fmt.Errorf("env name %q must match %s", k, envKeyRe)
		}
	}
	return nil
}

// TimeoutOrDefault returns the step timeout, or DefaultStepTimeout.
func (st *Step) TimeoutOrDefault() time.Duration {
	if st.Timeout > 0 {
		return st.Timeout
	}
	return DefaultStepTimeout
}
