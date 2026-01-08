package system

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type OSReleaseCollector struct{}

func NewOSReleaseCollector() *OSReleaseCollector { return &OSReleaseCollector{} }

func (c *OSReleaseCollector) Name() string { return "os_release" }

func (c *OSReleaseCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	_ = ctx

	paths := []string{"/etc/os-release", "/usr/lib/os-release"}
	var data []byte
	var err error
	for _, p := range paths {
		data, err = os.ReadFile(p)
		if err == nil {
			break
		}
	}
	if err != nil {
		return nil, err
	}

	rel := filepath.ToSlash(filepath.Join("system", "os-release.txt"))
	out := filepath.Join(rc.OutputDir, rel)
	if err := evidence.WriteFileAtomic(out, data, 0o600); err != nil {
		return nil, err
	}

	sha, size, err := evidence.SHA256File(out)
	if err != nil {
		return nil, err
	}

	return []collectors.Artifact{{
		RelativePath: rel,
		Collector:    c.Name(),
		CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		SizeBytes:    size,
		SHA256:       sha,
	}}, nil
}
