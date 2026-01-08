package ioc

import (
	"bufio"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"time"

	"iron-sentinel/collectors"
)

type Options struct {
	IOCFile string
}

type Match struct {
	Pattern     string `json:"pattern"`
	Artifact    string `json:"artifact"`
	FirstLine   string `json:"first_line,omitempty"`
	CollectedAt string `json:"collected_at"`
}

type Result struct {
	IOCFile  string  `json:"ioc_file"`
	Matches  []Match `json:"matches"`
	Scanned  int     `json:"scanned"`
	Finished string  `json:"finished"`
}

func loadPatterns(path string) ([]string, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var patterns []string
	s := bufio.NewScanner(f)
	for s.Scan() {
		line := strings.TrimSpace(s.Text())
		if line == "" {
			continue
		}
		patterns = append(patterns, line)
	}
	if err := s.Err(); err != nil {
		return nil, err
	}
	if len(patterns) == 0 {
		return nil, errors.New("IOC file contained no patterns")
	}
	return patterns, nil
}

func ScanArtifacts(ctx context.Context, outDir string, artifacts []collectors.Artifact, opts Options) (Result, error) {
	_ = ctx

	patterns, err := loadPatterns(opts.IOCFile)
	if err != nil {
		return Result{}, err
	}

	var matches []Match
	scanned := 0
	for _, a := range artifacts {
		path := filepath.Join(outDir, filepath.FromSlash(a.RelativePath))
		b, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		scanned++
		content := string(b)
		for _, p := range patterns {
			if strings.Contains(content, p) {
				line := ""
				for _, l := range strings.Split(content, "\n") {
					if strings.Contains(l, p) {
						line = l
						break
					}
				}
				matches = append(matches, Match{
					Pattern:     p,
					Artifact:    a.RelativePath,
					FirstLine:   line,
					CollectedAt: time.Now().UTC().Format(time.RFC3339Nano),
				})
			}
		}
	}

	return Result{
		IOCFile:  opts.IOCFile,
		Matches:  matches,
		Scanned:  scanned,
		Finished: time.Now().UTC().Format(time.RFC3339Nano),
	}, nil
}
