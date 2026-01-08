package linux

import (
	"context"
	"path/filepath"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type NetworkSummaryCollector struct{}

func NewNetworkSummaryCollector() *NetworkSummaryCollector { return &NetworkSummaryCollector{} }

func (c *NetworkSummaryCollector) Name() string { return "network_summary" }

func (c *NetworkSummaryCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	cands := []struct {
		name string
		args []string
		out  string
	}{
		{name: "ss", args: []string{"-tulpen"}, out: "ss_tulpen.txt"},
		{name: "netstat", args: []string{"-anp"}, out: "netstat_anp.txt"},
		{name: "ip", args: []string{"addr"}, out: "ip_addr.txt"},
		{name: "ifconfig", args: []string{}, out: "ifconfig.txt"},
	}

	var artifacts []collectors.Artifact
	for _, cand := range cands {
		b, err := runCmd(ctx, cand.name, cand.args...)
		if err != nil {
			continue
		}
		rel := filepath.ToSlash(filepath.Join("network", cand.out))
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
			Metadata:     map[string]string{"cmd": cand.name},
		})
	}
	return artifacts, nil
}
