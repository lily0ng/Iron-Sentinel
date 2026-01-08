package evidence

import (
	"encoding/json"
	"os"
	"path/filepath"

	"iron-sentinel/collectors"
)

type Manifest struct {
	CaseID    string                `json:"case_id"`
	CreatedAt string                `json:"created_at"`
	Artifacts []collectors.Artifact `json:"artifacts"`
	Metadata  map[string]string     `json:"metadata,omitempty"`
}

func WriteManifest(outputDir string, m Manifest) error {
	b, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	path := filepath.Join(outputDir, "manifest.json")
	return os.WriteFile(path, b, 0o600)
}
