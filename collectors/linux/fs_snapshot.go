package linux

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"iron-sentinel/collectors"
	"iron-sentinel/evidence"
)

type SnapshotMode string

const (
	SnapshotMetadataOnly SnapshotMode = "metadata"
	SnapshotCopyFiles    SnapshotMode = "copy"
)

type SnapshotOptions struct {
	Paths         []string
	Mode          SnapshotMode
	HashFiles     bool
	MaxFileBytes  int64
	MaxTotalBytes int64
	MaxFiles      int
}

type FilesystemSnapshotCollector struct {
	opts SnapshotOptions
}

func NewFilesystemSnapshotCollector(opts SnapshotOptions) *FilesystemSnapshotCollector {
	return &FilesystemSnapshotCollector{opts: opts}
}

func (c *FilesystemSnapshotCollector) Name() string { return "fs_snapshot" }

type snapshotEntry struct {
	Path       string `json:"path"`
	Type       string `json:"type"`
	SizeBytes  int64  `json:"size_bytes"`
	Mode       string `json:"mode"`
	ModTime    string `json:"mod_time"`
	UID        int    `json:"uid,omitempty"`
	GID        int    `json:"gid,omitempty"`
	SHA256     string `json:"sha256,omitempty"`
	Copied     bool   `json:"copied"`
	CopyReason string `json:"copy_reason,omitempty"`
}

func isExcluded(path string) bool {
	p := filepath.Clean(path)
	ex := []string{"/proc", "/sys", "/dev", "/run"}
	for _, e := range ex {
		if p == e || strings.HasPrefix(p, e+string(os.PathSeparator)) {
			return true
		}
	}
	return false
}

func sha256Path(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

func (c *FilesystemSnapshotCollector) Collect(ctx context.Context, rc collectors.RunContext) ([]collectors.Artifact, error) {
	if len(c.opts.Paths) == 0 {
		return nil, errors.New("no snapshot paths configured")
	}

	mode := c.opts.Mode
	if mode == "" {
		mode = SnapshotMetadataOnly
	}
	if mode != SnapshotMetadataOnly && mode != SnapshotCopyFiles {
		return nil, errors.New("invalid snapshot mode")
	}

	maxFiles := c.opts.MaxFiles
	if maxFiles <= 0 {
		maxFiles = 20000
	}
	maxFileBytes := c.opts.MaxFileBytes
	if maxFileBytes <= 0 {
		maxFileBytes = 25 * 1024 * 1024
	}
	maxTotalBytes := c.opts.MaxTotalBytes
	if maxTotalBytes <= 0 {
		maxTotalBytes = 250 * 1024 * 1024
	}

	metaRel := filepath.ToSlash(filepath.Join("snapshot", "metadata.jsonl"))
	metaPath := filepath.Join(rc.OutputDir, metaRel)
	if err := evidence.EnsureParent(metaPath); err != nil {
		return nil, err
	}
	metaF, err := os.Create(metaPath)
	if err != nil {
		return nil, err
	}
	defer metaF.Close()

	metaW := json.NewEncoder(metaF)

	var tgzRel string
	var tgzPath string
	var tgzF *os.File
	var gzW *gzip.Writer
	var tarW *tar.Writer

	openTar := func() error {
		if mode != SnapshotCopyFiles {
			return nil
		}
		if tarW != nil {
			return nil
		}
		tgzRel = filepath.ToSlash(filepath.Join("snapshot", "files.tar.gz"))
		tgzPath = filepath.Join(rc.OutputDir, tgzRel)
		if err := evidence.EnsureParent(tgzPath); err != nil {
			return err
		}
		f, err := os.Create(tgzPath)
		if err != nil {
			return err
		}
		tgzF = f
		gzW = gzip.NewWriter(tgzF)
		tarW = tar.NewWriter(gzW)
		return nil
	}

	closeTar := func() {
		if tarW != nil {
			_ = tarW.Close()
		}
		if gzW != nil {
			_ = gzW.Close()
		}
		if tgzF != nil {
			_ = tgzF.Close()
		}
	}
	defer closeTar()

	errStopWalk := errors.New("stop_walk")
	filesSeen := 0
	var totalCopied int64

	for _, root := range c.opts.Paths {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}

		if root == "" {
			continue
		}
		if isExcluded(root) {
			continue
		}

		err := filepath.WalkDir(root, func(path string, d fs.DirEntry, walkErr error) error {
			if walkErr != nil {
				return nil
			}
			if isExcluded(path) {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}

			if filesSeen >= maxFiles {
				if d.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			filesSeen++

			info, err := d.Info()
			if err != nil {
				return nil
			}

			entry := snapshotEntry{
				Path:      path,
				SizeBytes: info.Size(),
				Mode:      info.Mode().String(),
				ModTime:   info.ModTime().UTC().Format(time.RFC3339Nano),
				Copied:    false,
			}

			if info.Mode()&os.ModeSymlink != 0 {
				entry.Type = "symlink"
				_ = metaW.Encode(entry)
				return nil
			}
			if info.IsDir() {
				entry.Type = "dir"
				_ = metaW.Encode(entry)
				return nil
			}
			if !info.Mode().IsRegular() {
				entry.Type = "other"
				_ = metaW.Encode(entry)
				return nil
			}
			entry.Type = "file"

			if c.opts.HashFiles {
				if info.Size() <= maxFileBytes {
					h, herr := sha256Path(path)
					if herr == nil {
						entry.SHA256 = h
					}
				}
			}

			if mode == SnapshotCopyFiles {
				if info.Size() > maxFileBytes {
					entry.CopyReason = "file_too_large"
					_ = metaW.Encode(entry)
					return nil
				}
				if totalCopied+info.Size() > maxTotalBytes {
					entry.CopyReason = "total_limit"
					_ = metaW.Encode(entry)
					return errStopWalk
				}
				if err := openTar(); err != nil {
					return err
				}

				f, err := os.Open(path)
				if err != nil {
					_ = metaW.Encode(entry)
					return nil
				}
				defer f.Close()

				name := strings.TrimPrefix(filepath.Clean(path), string(os.PathSeparator))
				hdr := &tar.Header{
					Name:    name,
					Mode:    int64(info.Mode().Perm()),
					Size:    info.Size(),
					ModTime: info.ModTime(),
				}
				if err := tarW.WriteHeader(hdr); err != nil {
					_ = metaW.Encode(entry)
					return nil
				}
				if _, err := io.Copy(tarW, f); err == nil {
					entry.Copied = true
					totalCopied += info.Size()
				}
			}

			_ = metaW.Encode(entry)
			return nil
		})
		if err != nil {
			if errors.Is(err, errStopWalk) {
				break
			}
			return nil, err
		}
	}

	if filesSeen == 0 {
		return nil, errors.New("snapshot produced no entries")
	}

	sha, size, err := evidence.SHA256File(metaPath)
	if err != nil {
		return nil, err
	}

	artifacts := []collectors.Artifact{{
		RelativePath: metaRel,
		Collector:    c.Name(),
		CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
		SizeBytes:    size,
		SHA256:       sha,
		Metadata: map[string]string{
			"mode":            string(mode),
			"paths":           strings.Join(c.opts.Paths, ","),
			"files_seen":      intToString(filesSeen),
			"total_copied":    int64ToString(totalCopied),
			"hash_files":      boolToString(c.opts.HashFiles),
			"max_file_bytes":  int64ToString(maxFileBytes),
			"max_total_bytes": int64ToString(maxTotalBytes),
		},
	}}

	if tgzPath != "" {
		sha2, size2, err2 := evidence.SHA256File(tgzPath)
		if err2 == nil {
			artifacts = append(artifacts, collectors.Artifact{
				RelativePath: tgzRel,
				Collector:    c.Name(),
				CollectedAt:  time.Now().UTC().Format(time.RFC3339Nano),
				SizeBytes:    size2,
				SHA256:       sha2,
			})
		}
	}

	return artifacts, nil
}

func boolToString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

func intToString(i int) string {
	return int64ToString(int64(i))
}

func int64ToString(i int64) string {
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
