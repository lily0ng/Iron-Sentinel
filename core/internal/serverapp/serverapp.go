package serverapp

import (
	"crypto/subtle"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"mime/multipart"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/google/uuid"
)

type Config struct {
	DataDir string
	PSK     string
}

type Server struct {
	cfg Config

	mu     sync.Mutex
	agents map[string]Agent
	jobs   []Job
}

type Agent struct {
	AgentID  string `json:"agent_id"`
	Hostname string `json:"hostname"`
	OS       string `json:"os"`
	Arch     string `json:"arch"`
	Enrolled string `json:"enrolled"`
	LastSeen string `json:"last_seen"`
	Token    string `json:"token"`
}

type Job struct {
	JobID     string            `json:"job_id"`
	AgentID   string            `json:"agent_id"`
	Type      string            `json:"type"`
	Args      map[string]string `json:"args,omitempty"`
	CreatedAt string            `json:"created_at"`
	ClaimedAt string            `json:"claimed_at,omitempty"`
	DoneAt    string            `json:"done_at,omitempty"`
	Status    string            `json:"status"` // queued|claimed|done
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

type enqueueJobRequest struct {
	AgentID string            `json:"agent_id"`
	Type    string            `json:"type"`
	Args    map[string]string `json:"args,omitempty"`
}

func New(cfg Config) *Server {
	return &Server{
		cfg:    cfg,
		agents: make(map[string]Agent),
		jobs:   nil,
	}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("/healthz", s.handleHealth)
	mux.HandleFunc("/v1/enroll", s.handleEnroll)
	mux.HandleFunc("/v1/jobs", s.handleJobs)
	mux.HandleFunc("/v1/jobs/next", s.handleJobsNext)
	mux.HandleFunc("/v1/jobs/", s.handleJobResults) // /v1/jobs/{job_id}/results
	return mux
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	_ = json.NewEncoder(w).Encode(map[string]string{"status": "ok"})
}

func (s *Server) requirePSK(r *http.Request) bool {
	if s.cfg.PSK == "" {
		return true
	}
	psk := r.Header.Get("X-PSK")
	return subtle.ConstantTimeCompare([]byte(psk), []byte(s.cfg.PSK)) == 1
}

func (s *Server) authenticateAgent(r *http.Request) (Agent, bool) {
	agentID := r.URL.Query().Get("agent_id")
	token := r.URL.Query().Get("token")
	if agentID == "" || token == "" {
		return Agent{}, false
	}

	s.mu.Lock()
	defer s.mu.Unlock()
	a, ok := s.agents[agentID]
	if !ok {
		return Agent{}, false
	}
	if subtle.ConstantTimeCompare([]byte(token), []byte(a.Token)) != 1 {
		return Agent{}, false
	}
	a.LastSeen = time.Now().UTC().Format(time.RFC3339Nano)
	s.agents[agentID] = a
	_ = s.persistLocked()
	return a, true
}

func (s *Server) handleEnroll(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !s.requirePSK(r) {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	var req enrollRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	agentID := uuid.NewString()
	token := uuid.NewString()

	a := Agent{
		AgentID:  agentID,
		Hostname: req.Hostname,
		OS:       req.OS,
		Arch:     req.Arch,
		Enrolled: time.Now().UTC().Format(time.RFC3339Nano),
		LastSeen: time.Now().UTC().Format(time.RFC3339Nano),
		Token:    token,
	}

	s.mu.Lock()
	s.agents[agentID] = a
	_ = s.persistLocked()
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(enrollResponse{AgentID: agentID, Token: token})
}

func (s *Server) handleJobs(w http.ResponseWriter, r *http.Request) {
	switch r.Method {
	case http.MethodPost:
		if !s.requirePSK(r) {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		var req enqueueJobRequest
		if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.AgentID == "" {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if req.Type == "" {
			req.Type = "triage"
		}

		job := Job{
			JobID:     uuid.NewString(),
			AgentID:   req.AgentID,
			Type:      req.Type,
			Args:      req.Args,
			CreatedAt: time.Now().UTC().Format(time.RFC3339Nano),
			Status:    "queued",
		}

		s.mu.Lock()
		s.jobs = append(s.jobs, job)
		_ = s.persistLocked()
		s.mu.Unlock()

		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
		return
	default:
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
}

func (s *Server) handleJobsNext(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	_, ok := s.authenticateAgent(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	agentID := r.URL.Query().Get("agent_id")

	s.mu.Lock()
	defer s.mu.Unlock()

	for i := range s.jobs {
		if s.jobs[i].AgentID != agentID {
			continue
		}
		if s.jobs[i].Status != "queued" {
			continue
		}
		s.jobs[i].Status = "claimed"
		s.jobs[i].ClaimedAt = time.Now().UTC().Format(time.RFC3339Nano)
		job := s.jobs[i]
		_ = s.persistLocked()
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(job)
		return
	}

	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) handleJobResults(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		w.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if !strings.HasSuffix(r.URL.Path, "/results") {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	// /v1/jobs/{job_id}/results
	parts := strings.Split(strings.Trim(r.URL.Path, "/"), "/")
	if len(parts) != 4 {
		w.WriteHeader(http.StatusNotFound)
		return
	}
	jobID := parts[2]

	_, ok := s.authenticateAgent(r)
	if !ok {
		w.WriteHeader(http.StatusUnauthorized)
		return
	}

	mr, err := r.MultipartReader()
	if err != nil {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	var saved string
	for {
		part, err := mr.NextPart()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if part.FormName() != "file" {
			continue
		}
		saved, err = s.saveUpload(jobID, part)
		if err != nil {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		break
	}

	if saved == "" {
		w.WriteHeader(http.StatusBadRequest)
		return
	}

	s.mu.Lock()
	for i := range s.jobs {
		if s.jobs[i].JobID == jobID {
			s.jobs[i].Status = "done"
			s.jobs[i].DoneAt = time.Now().UTC().Format(time.RFC3339Nano)
			break
		}
	}
	_ = s.persistLocked()
	s.mu.Unlock()

	w.Header().Set("Content-Type", "application/json")
	_ = json.NewEncoder(w).Encode(map[string]string{"saved": saved})
}

func (s *Server) saveUpload(jobID string, part *multipart.Part) (string, error) {
	name := part.FileName()
	if name == "" {
		name = "case.tar.gz"
	}

	base := filepath.Join(s.cfg.DataDir, "uploads", jobID)
	if err := os.MkdirAll(base, 0o755); err != nil {
		return "", err
	}
	path := filepath.Join(base, filepath.Base(name))

	f, err := os.Create(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	if _, err := io.Copy(f, part); err != nil {
		return "", err
	}
	return path, nil
}

func (s *Server) LoadFromDisk() error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.loadLocked()
}

func (s *Server) loadLocked() error {
	if s.cfg.DataDir == "" {
		return fmt.Errorf("data dir is required")
	}
	_ = os.MkdirAll(s.cfg.DataDir, 0o755)

	agentsPath := filepath.Join(s.cfg.DataDir, "agents.json")
	jobsPath := filepath.Join(s.cfg.DataDir, "jobs.json")

	if b, err := os.ReadFile(agentsPath); err == nil {
		_ = json.Unmarshal(b, &s.agents)
	}
	if b, err := os.ReadFile(jobsPath); err == nil {
		_ = json.Unmarshal(b, &s.jobs)
	}
	return nil
}

func (s *Server) persistLocked() error {
	if s.cfg.DataDir == "" {
		return nil
	}
	_ = os.MkdirAll(s.cfg.DataDir, 0o755)

	agentsPath := filepath.Join(s.cfg.DataDir, "agents.json")
	jobsPath := filepath.Join(s.cfg.DataDir, "jobs.json")

	ab, _ := json.MarshalIndent(s.agents, "", "  ")
	jb, _ := json.MarshalIndent(s.jobs, "", "  ")

	if err := os.WriteFile(agentsPath, ab, 0o600); err != nil {
		return err
	}
	if err := os.WriteFile(jobsPath, jb, 0o600); err != nil {
		return err
	}
	return nil
}
