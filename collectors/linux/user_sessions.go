package linux

import (
	"context"
	"fmt"
	"path/filepath"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type UserSessionsCollector struct{}

func NewUserSessionsCollector() *UserSessionsCollector { return &UserSessionsCollector{} }

func (c *UserSessionsCollector) Name() string { return "user_sessions" }

func (c *UserSessionsCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	cands := []struct {
		name string
		args []string
		out  string
	}{
		{name: "who", args: []string{"-a"}, out: "who_a.txt"},
		{name: "w", args: []string{}, out: "w.txt"},
		{name: "users", args: []string{}, out: "users.txt"},
		{name: "last", args: []string{"-F", "-n", "50"}, out: "last_50.txt"},
	}

	var artifacts []collectors.Artifact
	for _, cand := range cands {
		b, err := runCmd(ctx, cand.name, cand.args...)
		if err != nil {
			continue
		}

		rel := filepath.ToSlash(filepath.Join("sessions", cand.out))
		path := filepath.Join(rc.OutputDir, rel)
		if err := evidence.WriteFileAtomic(path, b, 0o600); err != nil {
			return nil, err
		}

		sha, size, err := evidence.SHA256File(path)
		if err != nil {
			return nil, err
		}

		artifacts = append(artifacts, collectors.Artifact{
			RelativePath: rel,
			Collector:    c.Name(),
			CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
			SizeBytes:    size,
			SHA256:       sha,
			Metadata:     map[string]string{"cmd": fmt.Sprintf("%s %v", cand.name, cand.args)},
		})
	}

	if len(artifacts) == 0 {
		return nil, fmt.Errorf("no user/session commands succeeded")
	}
	return artifacts, nil
}
