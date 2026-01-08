package linux

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type ProcSummaryCollector struct{}

func NewProcSummaryCollector() *ProcSummaryCollector { return &ProcSummaryCollector{} }

func (c *ProcSummaryCollector) Name() string { return "proc_summary" }

func (c *ProcSummaryCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	files := []string{
		"/proc/meminfo",
		"/proc/cpuinfo",
		"/proc/uptime",
		"/proc/loadavg",
		"/proc/version",
	}

	var artifacts []collectors.Artifact
	for _, src := range files {
		b, err := os.ReadFile(src)
		if err != nil {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("proc", filepath.Base(src)))
		dst := filepath.Join(rc.OutputDir, rel)
		if err := evidence.WriteFileAtomic(dst, b, 0o600); err != nil {
			return nil, err
		}
		sha, size, err := evidence.SHA256File(dst)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, collectors.Artifact{
			RelativePath: rel,
			Collector:    c.Name(),
			CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			SizeBytes:    size,
			SHA256:       sha,
			Metadata:     map[string]string{"source": src},
		})
	}

	if len(artifacts) == 0 {
		b, err := runCmd(ctx, "ps", "aux")
		if err == nil {
			rel := filepath.ToSlash(filepath.Join("proc", "ps_aux.txt"))
			dst := filepath.Join(rc.OutputDir, rel)
			if err := evidence.WriteFileAtomic(dst, b, 0o600); err != nil {
				return nil, err
			}
			sha, size, err := evidence.SHA256File(dst)
			if err != nil {
				return nil, err
			}
			artifacts = append(artifacts, collectors.Artifact{
				RelativePath: rel,
				Collector:    c.Name(),
				CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				SizeBytes:    size,
				SHA256:       sha,
			})
		}
	}

	return artifacts, nil
}
