package evidence

import (
	"crypto/sha256"
	"encoding/hex"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
)

func SHA256File(path string) (string, int64, error) {
	if h, n, ok := sha256FileFastHash(path); ok {
		return h, n, nil
	}

	f, err := os.Open(path)
	if err != nil {
		return "", 0, err
	}
	defer f.Close()

	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return "", 0, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

func sha256FileFastHash(path string) (string, int64, bool) {
	if _, err := exec.LookPath("fast-hash"); err != nil {
		return "", 0, false
	}

	out, err := exec.Command("fast-hash", "sha256", path).Output()
	if err != nil {
		return "", 0, false
	}

	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		return "", 0, false
	}

	h := fields[0]
	n, err := strconv.ParseInt(fields[1], 10, 64)
	if err != nil {
		return "", 0, false
	}
	return h, n, true
}
