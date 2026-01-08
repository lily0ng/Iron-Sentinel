package collectors

import "context"

type Artifact struct {
	RelativePath string            `json:"relative_path"`
	Collector    string            `json:"collector"`
	CollectedAt  string            `json:"collected_at"`
	SizeBytes    int64             `json:"size_bytes"`
	SHA256       string            `json:"sha256"`
	Metadata     map[string]string `json:"metadata,omitempty"`
}

type RunContext struct {
	CaseID    string
	OutputDir string
}

type Collector interface {
	Name() string
	Collect(ctx context.Context, rc RunContext) ([]Artifact, error)
}
