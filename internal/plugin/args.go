package plugin

import (
	"errors"
	"fmt"
	"io"
	"strings"
	"text/tabwriter"
)

// ErrHelp is returned by ParseArgs for -h/--help.
var ErrHelp = errors.New("help requested")

// ParseArgs maps command-line arguments to input values. Inputs are given
// as --name value or --name=value; positional arguments fill the inputs not
// set by name, in declaration order. Defaults apply afterwards.
func (wf *Workflow) ParseArgs(args []string) (map[string]string, error) {
	values := map[string]string{}
	var positional []string
	for len(args) > 0 {
		arg := args[0]
		args = args[1:]
		switch {
		case arg == "--":
			positional = append(positional, args...)
			args = nil
			continue
		case arg == "-h" || arg == "--help":
			return nil, ErrHelp
		case !strings.HasPrefix(arg, "--"):
			positional = append(positional, arg)
			continue
		}

		name, val, hasVal := strings.Cut(strings.TrimPrefix(arg, "--"), "=")
		if wf.Inputs.Lookup(name) == nil {
			return nil, fmt.Errorf("workflow %s has no input %q", wf.Name, name)
		}
		if !hasVal {
			if len(args) == 0 {
				return nil, fmt.Errorf("--%s needs a value", name)
			}
			val, args = args[0], args[1:]
		}
		if _, dup := values[name]; dup {
			return nil, fmt.Errorf("input %s given more than once", name)
		}
		values[name] = val
	}

	for _, in := range wf.Inputs {
		if _, set := values[in.Name]; set || len(positional) == 0 {
			continue
		}
		values[in.Name] = positional[0]
		positional = positional[1:]
	}
	if len(positional) > 0 {
		return nil, fmt.Errorf("unexpected arguments: %s", strings.Join(positional, " "))
	}

	for _, in := range wf.Inputs {
		if _, set := values[in.Name]; set {
			continue
		}
		switch {
		case in.Required:
			return nil, fmt.Errorf("missing required input %s", in.Name)
		default:
			values[in.Name] = in.Default
		}
	}
	return values, nil
}

// Usage describes the workflow's inputs.
func (wf *Workflow) Usage(w io.Writer, prefix string) {
	var synopsis []string
	for _, in := range wf.Inputs {
		if in.Required {
			synopsis = append(synopsis, fmt.Sprintf("[--%s] <%s>", in.Name, in.Name))
		} else {
			synopsis = append(synopsis, fmt.Sprintf("[--%s <%s>]", in.Name, in.Name))
		}
	}
	fmt.Fprintf(w, "Usage: %s %s\n", prefix, strings.Join(synopsis, " "))
	if len(wf.Inputs) == 0 {
		return
	}
	fmt.Fprintln(w, "\nInputs (positional arguments fill them in this order):")
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	for _, in := range wf.Inputs {
		attrs := string(in.Type)
		switch {
		case in.Required:
			attrs += ", required"
		case in.Default != "":
			attrs += ", default " + in.Default
		}
		fmt.Fprintf(tw, "  %s\t%s\t%s\n", in.Name, attrs, in.Description)
	}
	_ = tw.Flush()
}
