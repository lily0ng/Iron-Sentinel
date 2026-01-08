package triage

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"iron-sentinel/analyzers/ioc"
	"iron-sentinel/analyzers/timeline"
	"iron-sentinel/collectors"
	"iron-sentinel/collectors/linux"
	"iron-sentinel/collectors/system"
	"iron-sentinel/evidence"
)

type Options struct {
	CaseID                string
	Output                string
	IOCFile               string
	SnapshotPaths         []string
	SnapshotMode          string
	SnapshotHashFiles     bool
	SnapshotMaxFileBytes  int64
	SnapshotMaxTotalBytes int64
	SnapshotMaxFiles      int
	StartedAt             time.Time
}

type Result struct {
	CaseID    string
	OutputDir string
	Artifacts []collectors.Artifact
}

func Run(ctx context.Context, opts Options) (Result, error) {
	outDir := filepath.Join(opts.Output, opts.CaseID)
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return Result{}, err
	}

	rc := collectors.RunContext{CaseID: opts.CaseID, OutputDir: outDir}

	cols := []collectors.Collector{
		system.NewHostInfoCollector(),
		system.NewOSReleaseCollector(),
	}

	if len(opts.SnapshotPaths) > 0 {
		cols = append(cols, linux.NewFilesystemSnapshotCollector(linux.SnapshotOptions{
			Paths:         opts.SnapshotPaths,
			Mode:          linux.SnapshotMode(opts.SnapshotMode),
			HashFiles:     opts.SnapshotHashFiles,
			MaxFileBytes:  opts.SnapshotMaxFileBytes,
			MaxTotalBytes: opts.SnapshotMaxTotalBytes,
			MaxFiles:      opts.SnapshotMaxFiles,
		}))
	}

	cols = append(cols,
		linux.NewProcSummaryCollector(),
		linux.NewNetworkSummaryCollector(),
		linux.NewUserSessionsCollector(),
		linux.NewPersistenceCollector(),
	)

	var artifacts []collectors.Artifact
	for _, c := range cols {
		select {
		case <-ctx.Done():
			return Result{}, ctx.Err()
		default:
		}

		arts, err := c.Collect(ctx, rc)
		if err != nil {
			artifacts = append(artifacts, collectors.Artifact{
				RelativePath: filepath.ToSlash(filepath.Join("errors", c.Name()+".txt")),
				Collector:    c.Name(),
				CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				Metadata:     map[string]string{"error": err.Error()},
			})
			errPath := filepath.Join(outDir, "errors")
			_ = os.MkdirAll(errPath, 0o755)
			_ = os.WriteFile(filepath.Join(errPath, c.Name()+".txt"), []byte(err.Error()+"\n"), 0o600)
			continue
		}
		artifacts = append(artifacts, arts...)
	}

	manifest := evidence.Manifest{
		CaseID:    opts.CaseID,
		CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
		Artifacts: artifacts,
	}

	analysisDir := filepath.Join(outDir, "analysis")
	_ = os.MkdirAll(analysisDir, 0o755)

	if opts.IOCFile != "" {
		iocRes, err := ioc.ScanArtifacts(ctx, outDir, artifacts, ioc.Options{IOCFile: opts.IOCFile})
		if err == nil {
			b, _ := json.MarshalIndent(iocRes, "", "  ")
			p := filepath.Join(analysisDir, "ioc_scan.json")
			_ = os.WriteFile(p, b, 0o600)
			sha, size, herr := evidence.SHA256File(p)
			if herr == nil {
				manifest.Artifacts = append(manifest.Artifacts, collectors.Artifact{
					RelativePath: filepath.ToSlash(filepath.Join("analysis", "ioc_scan.json")),
					Collector:    "ioc_scan",
					CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
					SizeBytes:    size,
					SHA256:       sha,
				})
			}
			manifest.Metadata = map[string]string{
				"ioc_matches": fmt.Sprintf("%d", len(iocRes.Matches)),
			}
		}
	}

	if rel, err := timeline.WriteJSONL(ctx, outDir, manifest.Artifacts, timeline.Options{CaseID: opts.CaseID, StartedAt: opts.StartedAt}); err == nil {
		p := filepath.Join(outDir, filepath.FromSlash(rel))
		sha, size, herr := evidence.SHA256File(p)
		if herr == nil {
			manifest.Artifacts = append(manifest.Artifacts, collectors.Artifact{
				RelativePath: rel,
				Collector:    "timeline",
				CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				SizeBytes:    size,
				SHA256:       sha,
			})
		}
	}

	if err := evidence.WriteManifest(outDir, manifest); err != nil {
		return Result{}, err
	}

	return Result{CaseID: opts.CaseID, OutputDir: outDir, Artifacts: artifacts}, nil
}
