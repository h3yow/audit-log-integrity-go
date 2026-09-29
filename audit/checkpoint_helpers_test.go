package audit

import (
	"os"
	"path/filepath"
	"testing"
)

func removeCheckpoint(t *testing.T, dir string) error {
	t.Helper()
	return os.Remove(filepath.Join(dir, "checkpoint.json"))
}
