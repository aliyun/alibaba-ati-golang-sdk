package a2a

import (
	"crypto/rand"
	"encoding/hex"
	"sync"
	"time"
)

type TaskStore struct {
	mu    sync.RWMutex
	tasks map[string]*taskEntry
	ttl   time.Duration
}

type taskEntry struct {
	task      *Task
	createdAt time.Time
}

func NewTaskStore(ttl time.Duration) *TaskStore {
	s := &TaskStore{
		tasks: make(map[string]*taskEntry),
		ttl:   ttl,
	}
	go s.evictLoop()
	return s
}

func (s *TaskStore) Create(contextID string) *Task {
	t := &Task{
		ID:        randomID(),
		ContextID: contextID,
		Status:    TaskStatus{State: TaskStateSubmitted},
	}
	s.mu.Lock()
	s.tasks[t.ID] = &taskEntry{task: t, createdAt: time.Now()}
	s.mu.Unlock()
	return t
}

func (s *TaskStore) Get(taskID string) (*Task, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.tasks[taskID]
	if !ok {
		return nil, false
	}
	return e.task, true
}

func (s *TaskStore) Update(taskID string, fn func(*Task)) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.tasks[taskID]
	if !ok {
		return false
	}
	fn(e.task)
	return true
}

func (s *TaskStore) List(contextID string) []*Task {
	s.mu.RLock()
	defer s.mu.RUnlock()
	var result []*Task
	for _, e := range s.tasks {
		if contextID == "" || e.task.ContextID == contextID {
			result = append(result, e.task)
		}
	}
	return result
}

func (s *TaskStore) evictLoop() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		s.mu.Lock()
		now := time.Now()
		for id, e := range s.tasks {
			if now.Sub(e.createdAt) > s.ttl {
				delete(s.tasks, id)
			}
		}
		s.mu.Unlock()
	}
}

func randomID() string {
	b := make([]byte, 16)
	rand.Read(b)
	return hex.EncodeToString(b)
}
