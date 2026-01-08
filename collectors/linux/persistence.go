package linux

import (
	"context"
	"os"
	"path/filepath"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type PersistenceCollector struct{}

func NewPersistenceCollector() *PersistenceCollector { return &PersistenceCollector{} }

func (c *PersistenceCollector) Name() string { return "persistence" }

func (c *PersistenceCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	_ = ctx

	paths := []string{
		"/etc/crontab",
		"/etc/cron.d",
		"/etc/cron.daily",
		"/etc/cron.hourly",
		"/etc/cron.weekly",
		"/etc/cron.monthly",
		"/etc/systemd/system",
		"/lib/systemd/system",
	}

	var artifacts []collectors.Artifact
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			continue
		}

		if info.IsDir() {
			entries, err := os.ReadDir(p)
			if err != nil {
				continue
			}
			var listing []byte
			for _, e := range entries {
				listing = append(listing, []byte(e.Name()+"\n")...)
			}
			rel := filepath.ToSlash(filepath.Join("persistence", filepath.Base(p)+"_listing.txt"))
			out := filepath.Join(rc.OutputDir, rel)
			if err := evidence.WriteFileAtomic(out, listing, 0o600); err != nil {
				return nil, err
			}
			sha, size, err := evidence.SHA256File(out)
			if err != nil {
				return nil, err
			}
			artifacts = append(artifacts, collectors.Artifact{
				RelativePath: rel,
				Collector:    c.Name(),
				CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				SizeBytes:    size,
				SHA256:       sha,
				Metadata:     map[string]string{"source": p},
			})
			continue
		}

		b, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("persistence", filepath.Base(p)))
		out := filepath.Join(rc.OutputDir, rel)
		if err := evidence.WriteFileAtomic(out, b, 0o600); err != nil {
			return nil, err
		}
		sha, size, err := evidence.SHA256File(out)
		if err != nil {
			return nil, err
		}
		artifacts = append(artifacts, collectors.Artifact{
			RelativePath: rel,
			Collector:    c.Name(),
			CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			SizeBytes:    size,
			SHA256:       sha,
			Metadata:     map[string]string{"source": p},
		})
	}

	return artifacts, nil
}
