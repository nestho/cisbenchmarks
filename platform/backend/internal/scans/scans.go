package scans

import (
	"sync"
	"time"

	"github.com/nestho/hardenx/platform/backend/internal/runner"
)

type Job struct {
	ID          string                 `json:"id"`
	BenchmarkID string                 `json:"benchmark_id"`
	Profile     string                 `json:"profile"`
	Status      string                 `json:"status"`
	Asset       map[string]any         `json:"asset"`
	Results     []runner.Result        `json:"results,omitempty"`
	CreatedAt   time.Time              `json:"created_at"`
	FinishedAt  *time.Time             `json:"finished_at,omitempty"`
}

type Store struct {
	mu   sync.RWMutex
	jobs map[string]*Job
}

func NewStore() *Store { return &Store{jobs: map[string]*Job{}} }

func (s *Store) Create(j *Job) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.jobs[j.ID] = j
}

func (s *Store) Get(id string) (*Job, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	j, ok := s.jobs[id]
	return j, ok
}

func (s *Store) Update(id string, fn func(*Job)) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if j, ok := s.jobs[id]; ok {
		fn(j)
	}
}

func (s *Store) List() []*Job {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]*Job, 0, len(s.jobs))
	for _, j := range s.jobs {
		out = append(out, j)
	}
	return out
}