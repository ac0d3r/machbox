package job

import (
	"errors"
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"time"
)

func TestPrune(t *testing.T) {
	root := t.TempDir()
	old := time.Now().Add(-time.Hour)
	mkjob := func(id string, age time.Time) string {
		dir := filepath.Join(root, id)
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chtimes(dir, age, age); err != nil {
			t.Fatal(err)
		}
		return dir
	}

	mkjob("a-legacy", old) // no lock file
	mkjob("b-new", time.Now())
	if f, err := lock(mkjob("c-done", old)); err != nil {
		t.Fatal(err)
	} else {
		f.Close()
	}
	running, err := lock(mkjob("d-running", old))
	if err != nil {
		t.Fatal(err)
	}
	defer running.Close()
	for _, id := range []string{"a-legacy", "c-done", "d-running"} {
		_ = os.Chtimes(filepath.Join(root, id), old, old)
	}

	ids, err := finished(root)
	if err != nil {
		t.Fatal(err)
	}
	if want := []string{"a-legacy", "c-done"}; !reflect.DeepEqual(ids, want) {
		t.Errorf("finished = %v, want %v", ids, want)
	}
	for _, id := range ids {
		if err := remove(root, id); err != nil {
			t.Error(err)
		}
	}
	if err := remove(root, "d-running"); !errors.Is(err, ErrRunning) {
		t.Errorf("remove running job: %v", err)
	}
	if err := remove(root, "../x"); err == nil {
		t.Error("removed outside the jobs directory")
	}
	left, _ := os.ReadDir(root)
	if len(left) != 2 {
		t.Errorf("%d jobs left, want b-new and d-running", len(left))
	}
}
