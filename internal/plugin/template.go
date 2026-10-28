package plugin

import (
	"fmt"
	"maps"
	"regexp"
	"slices"
	"strings"
)

// exprRe matches ${{ ref }}. Templates only substitute values; there are no
// operators or functions.
var exprRe = regexp.MustCompile(`\$\{\{\s*([^{}]*?)\s*\}\}`)

// Vars are the values templates expand to when a step runs. Paths are
// guest paths; relative ones are relative to the workdir (the step's cwd).
//
//	${{ inputs.<name> }}       input value (file inputs: relative path)
//	${{ output }}              this step's output
//	${{ steps.<id>.output }}   an earlier step's output
//	${{ plugin_dir }}          read-only plugin directory
type Vars struct {
	Inputs    map[string]string
	Outputs   map[string]string // step id → output, for steps that declare one
	PluginDir string
}

// Args expands the step's run templates.
func (st *Step) Args(v Vars) ([]string, error) {
	args := make([]string, len(st.Run))
	for i, arg := range st.Run {
		s, err := expand(arg, func(ref string) (string, error) { return v.resolve(st, ref) })
		if err != nil {
			return nil, err
		}
		args[i] = s
	}
	return args, nil
}

// Environ merges the workflow env with the step's own (which wins),
// expands templates, and returns sorted KEY=VALUE entries.
func (st *Step) Environ(workflowEnv map[string]string, v Vars) ([]string, error) {
	env := maps.Clone(workflowEnv)
	if env == nil {
		env = map[string]string{}
	}
	maps.Copy(env, st.Env)
	out := make([]string, 0, len(env))
	for _, k := range slices.Sorted(maps.Keys(env)) {
		val, err := expand(env[k], func(ref string) (string, error) { return v.resolve(st, ref) })
		if err != nil {
			return nil, fmt.Errorf("env %s: %w", k, err)
		}
		out = append(out, k+"="+val)
	}
	return out, nil
}

func (v Vars) resolve(st *Step, ref string) (string, error) {
	parts := strings.Split(ref, ".")
	switch {
	case ref == "output":
		if st.Output == "" {
			return "", fmt.Errorf("${{ output }} used but step %s declares no output", st.ID)
		}
		return st.Output, nil
	case ref == "plugin_dir":
		return v.PluginDir, nil
	case len(parts) == 2 && parts[0] == "inputs":
		val, ok := v.Inputs[parts[1]]
		if !ok {
			return "", fmt.Errorf("unknown input %q", parts[1])
		}
		return val, nil
	case len(parts) == 3 && parts[0] == "steps" && parts[2] == "output":
		val, ok := v.Outputs[parts[1]]
		if !ok {
			return "", fmt.Errorf("%s: no earlier step %q with an output", ref, parts[1])
		}
		return val, nil
	}
	return "", fmt.Errorf("unknown template variable %q", ref)
}

func expand(s string, lookup func(ref string) (string, error)) (string, error) {
	var firstErr error
	out := exprRe.ReplaceAllStringFunc(s, func(m string) string {
		val, err := lookup(exprRe.FindStringSubmatch(m)[1])
		if err != nil && firstErr == nil {
			firstErr = err
		}
		return val
	})
	if firstErr != nil {
		return "", firstErr
	}
	if strings.Contains(out, "${{") {
		return "", fmt.Errorf("malformed template in %q", s)
	}
	return out, nil
}
