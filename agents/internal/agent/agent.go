package agent

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ServerURL   string
	PSK         string
	InsecureTLS bool
	PollEvery   time.Duration
	TriageBin   string
	OutputBase  string
}

type enrollRequest struct {
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
}

type enrollResponse struct {
	AgentID string `json:"agent_id"`
	Token   string `json:"token"`
}

type job struct {
	JobID   string            `json:"job_id"`
	AgentID string            `json:"agent_id"`
	Type    string            `json:"type"`
	Args    map[string]string `json:"args,omitempty"`
}

var errUnauthorized = errors.New("unauthorized")

func Run(cfg Config) error {
	if cfg.ServerURL == "" {
		return fmt.Errorf("server URL is required")
	}
	if cfg.PollEvery <= 0 {
		cfg.PollEvery = 10 * time.Second
	}
	if cfg.TriageBin == "" {
		cfg.TriageBin = "iron-sentinel"
	}
	if cfg.OutputBase == "" {
		cfg.OutputBase = "./agent-evidence"
	}

	host, _ := os.Hostname()
	client := &http.Client{Timeout: 60 * time.Second}
	if strings.HasPrefix(strings.ToLower(cfg.ServerURL), "https://") {
		tr := &http.Transport{TLSClientConfig: &tls.Config{InsecureSkipVerify: cfg.InsecureTLS}}
		client.Transport = tr
	}

	auth, ok := loadAuth(cfg.ServerURL)
	if !ok {
		var err error
		auth, err = enroll(client, cfg, enrollRequest{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH})
		if err != nil {
			return err
		}
		_ = saveAuth(cfg.ServerURL, auth)
	}

	for {
		j, err := nextJob(client, cfg, auth)
		if err != nil {
			if errors.Is(err, errUnauthorized) {
				auth2, e2 := enroll(client, cfg, enrollRequest{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH})
				if e2 == nil {
					auth = auth2
					_ = saveAuth(cfg.ServerURL, auth)
				}
				time.Sleep(cfg.PollEvery)
				continue
			}
			time.Sleep(cfg.PollEvery)
			continue
		}
		if j.JobID == "" {
			time.Sleep(cfg.PollEvery)
			continue
		}
		if err := handleJob(client, cfg, auth, j); err != nil {
			if errors.Is(err, errUnauthorized) {
				auth2, e2 := enroll(client, cfg, enrollRequest{Hostname: host, OS: runtime.GOOS, Arch: runtime.GOARCH})
				if e2 == nil {
					auth = auth2
					_ = saveAuth(cfg.ServerURL, auth)
				}
			}
			// best-effort; keep polling
		}
	}
}

type authState struct {
	AgentID string
	Token   string
}

func enroll(client *http.Client, cfg Config, req enrollRequest) (authState, error) {
	b, _ := json.Marshal(req)
	url := strings.TrimRight(cfg.ServerURL, "/") + "/v1/enroll"
	hreq, _ := http.NewRequest(http.MethodPost, url, bytes.NewReader(b))
	hreq.Header.Set("Content-Type", "application/json")
	if cfg.PSK != "" {
		hreq.Header.Set("X-PSK", cfg.PSK)
	}

	resp, err := client.Do(hreq)
	if err != nil {
		return authState{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return authState{}, fmt.Errorf("enroll failed: %s", resp.Status)
	}

	var out enrollResponse
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		return authState{}, err
	}
	return authState{AgentID: out.AgentID, Token: out.Token}, nil
}

func nextJob(client *http.Client, cfg Config, auth authState) (job, error) {
	url := strings.TrimRight(cfg.ServerURL, "/") + "/v1/jobs/next?agent_id=" + auth.AgentID + "&token=" + auth.Token
	req, _ := http.NewRequest(http.MethodGet, url, nil)
	resp, err := client.Do(req)
	if err != nil {
		return job{}, err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return job{}, errUnauthorized
	}
	if resp.StatusCode == http.StatusNoContent {
		return job{}, nil
	}
	if resp.StatusCode != http.StatusOK {
		return job{}, fmt.Errorf("jobs next failed: %s", resp.Status)
	}
	var j job
	if err := json.NewDecoder(resp.Body).Decode(&j); err != nil {
		return job{}, err
	}
	return j, nil
}

func handleJob(client *http.Client, cfg Config, auth authState, j job) error {
	if j.Type != "triage" {
		return nil
	}

	timeout := 30 * time.Minute
	if j.Args != nil {
		if s := strings.TrimSpace(j.Args["timeout"]); s != "" {
			if d, err := time.ParseDuration(s); err == nil {
				timeout = d
			}
		}
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	outDir := filepath.Join(cfg.OutputBase)
	_ = os.MkdirAll(outDir, 0o755)

	args, err := buildTriageArgs(outDir, j)
	if err != nil {
		return err
	}
	cmd := exec.CommandContext(ctx, cfg.TriageBin, args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return err
	}

	caseDir, err := newestDir(outDir)
	if err != nil {
		return err
	}

	archivePath := filepath.Join(outDir, j.JobID+".tar.gz")
	if err := tarGzDir(caseDir, archivePath); err != nil {
		return err
	}

	if err := uploadResult(client, cfg, auth, j.JobID, archivePath); err != nil {
		return err
	}

	return nil
}

func newestDir(base string) (string, error) {
	entries, err := os.ReadDir(base)
	if err != nil {
		return "", err
	}
	var newest string
	var newestTime time.Time
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		info, err := e.Info()
		if err != nil {
			continue
		}
		if newest == "" || info.ModTime().After(newestTime) {
			newest = filepath.Join(base, e.Name())
			newestTime = info.ModTime()
		}
	}
	if newest == "" {
		return "", errors.New("no case directory found")
	}
	return newest, nil
}

func tarGzDir(srcDir string, dstFile string) error {
	f, err := os.Create(dstFile)
	if err != nil {
		return err
	}
	defer f.Close()

	gz := gzip.NewWriter(f)
	defer gz.Close()

	tarw := tar.NewWriter(gz)
	defer tarw.Close()

	root := filepath.Clean(srcDir)
	return filepath.WalkDir(root, func(path string, d os.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := d.Info()
		if err != nil {
			return nil
		}
		rel, _ := filepath.Rel(root, path)
		name := filepath.ToSlash(rel)
		if name == "." {
			name = filepath.Base(root)
		} else {
			name = filepath.ToSlash(filepath.Join(filepath.Base(root), rel))
		}

		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return nil
		}
		hdr.Name = name
		if err := tarw.WriteHeader(hdr); err != nil {
			return nil
		}
		if info.IsDir() {
			return nil
		}
		if !info.Mode().IsRegular() {
			return nil
		}
		in, err := os.Open(path)
		if err != nil {
			return nil
		}
		defer in.Close()
		_, _ = io.Copy(tarw, in)
		return nil
	})
}

func uploadResult(client *http.Client, cfg Config, auth authState, jobID string, archivePath string) error {
	url := strings.TrimRight(cfg.ServerURL, "/") + "/v1/jobs/" + jobID + "/results?agent_id=" + auth.AgentID + "&token=" + auth.Token

	body := &bytes.Buffer{}
	mw := multipart.NewWriter(body)
	fw, err := mw.CreateFormFile("file", filepath.Base(archivePath))
	if err != nil {
		return err
	}
	f, err := os.Open(archivePath)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := io.Copy(fw, f); err != nil {
		return err
	}
	_ = mw.Close()

	req, _ := http.NewRequest(http.MethodPost, url, body)
	req.Header.Set("Content-Type", mw.FormDataContentType())
	resp, err := client.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode == http.StatusUnauthorized {
		return errUnauthorized
	}
	if resp.StatusCode != http.StatusOK {
		b, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("upload failed: %s %s", resp.Status, string(b))
	}
	return nil
}

func buildTriageArgs(outputBase string, j job) ([]string, error) {
	args := []string{"triage", "--output", outputBase}
	if j.Args == nil {
		return args, nil
	}

	if v := strings.TrimSpace(j.Args["ioc_file"]); v != "" {
		args = append(args, "--ioc-file", v)
	}
	if v := j.Args["ioc"]; strings.TrimSpace(v) != "" {
		p := filepath.Join(outputBase, "iocs_"+j.JobID+".txt")
		if err := os.WriteFile(p, []byte(v), 0o600); err != nil {
			return nil, err
		}
		args = append(args, "--ioc-file", p)
	}

	if v := strings.TrimSpace(j.Args["snapshot_paths"]); v != "" {
		for _, p := range strings.Split(v, ",") {
			p = strings.TrimSpace(p)
			if p == "" {
				continue
			}
			args = append(args, "--snapshot-path", p)
		}
	}
	if v := strings.TrimSpace(j.Args["snapshot_mode"]); v != "" {
		args = append(args, "--snapshot-mode", v)
	}
	if v := strings.TrimSpace(j.Args["snapshot_hash"]); v != "" {
		b, _ := strconv.ParseBool(v)
		args = append(args, "--snapshot-hash="+boolString(b))
	}
	if v := strings.TrimSpace(j.Args["snapshot_max_file_bytes"]); v != "" {
		args = append(args, "--snapshot-max-file-bytes", v)
	}
	if v := strings.TrimSpace(j.Args["snapshot_max_total_bytes"]); v != "" {
		args = append(args, "--snapshot-max-total-bytes", v)
	}
	if v := strings.TrimSpace(j.Args["snapshot_max_files"]); v != "" {
		args = append(args, "--snapshot-max-files", v)
	}
	if v := strings.TrimSpace(j.Args["timeout"]); v != "" {
		args = append(args, "--timeout", v)
	}

	return args, nil
}

func boolString(b bool) string {
	if b {
		return "true"
	}
	return "false"
}

type authCache struct {
	ServerURL string `json:"server_url"`
	AgentID   string `json:"agent_id"`
	Token     string `json:"token"`
}

func loadAuth(serverURL string) (authState, bool) {
	path, err := cachePath(serverURL)
	if err != nil {
		return authState{}, false
	}
	b, err := os.ReadFile(path)
	if err != nil {
		return authState{}, false
	}
	var c authCache
	if err := json.Unmarshal(b, &c); err != nil {
		return authState{}, false
	}
	if c.AgentID == "" || c.Token == "" {
		return authState{}, false
	}
	return authState{AgentID: c.AgentID, Token: c.Token}, true
}

func saveAuth(serverURL string, a authState) error {
	path, err := cachePath(serverURL)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(authCache{ServerURL: serverURL, AgentID: a.AgentID, Token: a.Token}, "", "  ")
	return os.WriteFile(path, b, 0o600)
}

func cachePath(serverURL string) (string, error) {
	dir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(serverURL))))
	key := hex.EncodeToString(h[:])
	return filepath.Join(dir, "iron-sentinel", "agent_"+key+".json"), nil
}
