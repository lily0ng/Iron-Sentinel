package system

import (
	"context"
	"encoding/json"
	"path/filepath"
	"runtime"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type HostInfoCollector struct{}

func NewHostInfoCollector() *HostInfoCollector { return &HostInfoCollector{} }

func (c *HostInfoCollector) Name() string { return "host_info" }

func (c *HostInfoCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	_ = ctx

	data := map[string]string{
		"goos":   runtime.GOOS,
		"goarch": runtime.GOARCH,
	}
	b, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return nil, err
	}

	rel := filepath.ToSlash(filepath.Join("system", "host_info.json"))
	path := filepath.Join(rc.OutputDir, rel)
	if err := evidence.WriteFileAtomic(path, b, 0o600); err != nil {
		return nil, err
	}
	sha, size, err := evidence.SHA256File(path)
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
