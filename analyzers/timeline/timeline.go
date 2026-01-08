package timeline

import (
	"bufio"
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"time"

	"iron-sentinel/collectors"
)

type Event struct {
	Time        string            `json:"time"`
	Type        string            `json:"type"`
	Artifact    string            `json:"artifact,omitempty"`
	Collector   string            `json:"collector,omitempty"`
	SHA256      string            `json:"sha256,omitempty"`
	SizeBytes   int64             `json:"size_bytes,omitempty"`
	Metadata    map[string]string `json:"metadata,omitempty"`
	CollectedAt string            `json:"collected_at,omitempty"`
}

type Options struct {
	CaseID    string
	StartedAt time.Time
}

func WriteJSONL(ctx context.Context, outputDir string, artifacts []collectors.Artifact, opts Options) (string, error) {
	_ = ctx

	rel := filepath.ToSlash(filepath.Join("analysis", "timeline.jsonl"))
	path := filepath.Join(outputDir, rel)
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return "", err
	}

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	w := bufio.NewWriter(f)
	enc := json.NewEncoder(w)

	started := opts.StartedAt
	if started.IsZero() {
		started = time.Now().UTC()
	}

	_ = enc.Encode(Event{
		Time: started.UTC().Format(time.RFC3339Nano),
		Type: "triage_started",
		Metadata: map[string]string{
			"case_id": opts.CaseID,
		},
	})

	for _, a := range artifacts {
		_ = enc.Encode(Event{
			Time:        a.CollectedAt,
			Type:        "artifact_collected",
			Artifact:    a.RelativePath,
			Collector:   a.Collector,
			SHA256:      a.SHA256,
			SizeBytes:   a.SizeBytes,
			Metadata:    a.Metadata,
			CollectedAt: a.CollectedAt,
		})
	}

	_ = enc.Encode(Event{
		Time: time.Now().UTC().Format(time.RFC3339Nano),
		Type: "triage_finished",
		Metadata: map[string]string{
			"case_id":   opts.CaseID,
			"artifacts": fmtInt(len(artifacts)),
		},
	})

	if err := w.Flush(); err != nil {
		return "", err
	}
	return rel, nil
}

func fmtInt(i int) string {
	b := make([]byte, 0, 24)
	neg := i < 0
	if neg {
		i = -i
	}
	for {
		b = append(b, byte('0'+(i%10)))
		i /= 10
		if i == 0 {
			break
		}
	}
	if neg {
		b = append(b, '-')
	}
	for l, r := 0, len(b)-1; l < r; l, r = l+1, r-1 {
		b[l], b[r] = b[r], b[l]
	}
	return string(b)
}
