package vm

import "strconv"

// ErrAmbiguousName is returned when a name matches more than one baseline.
type ErrAmbiguousName struct {
	Name string
}

func (e *ErrAmbiguousName) Error() string {
	return "name " + strconv.Quote(e.Name) + " matches multiple baselines, use the UUID instead"
}

// ErrBaselineNotFound is returned when neither the UUID nor a unique name
// resolves to a baseline.
type ErrBaselineNotFound struct {
	Identifier string
}

func (e *ErrBaselineNotFound) Error() string {
	return "no baseline found for " + strconv.Quote(e.Identifier)
}
