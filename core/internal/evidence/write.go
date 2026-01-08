package evidence

import (
	"os"
	"path/filepath"
)

func EnsureParent(path string) error {
	return os.MkdirAll(filepath.Dir(path), 0o755)
}

func WriteFileAtomic(path string, data []byte, perm os.FileMode) error {
	if err := EnsureParent(path); err != nil {
		return err
	}

	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, perm); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}
