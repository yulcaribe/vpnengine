package core

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
)

type Store struct {
	path string
	mu   sync.Mutex
}

func NewStore(dir string) *Store { return &Store{path: filepath.Join(dir, "state.json")} }
func (s *Store) Read() (Database, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.read()
}
func (s *Store) read() (Database, error) {
	db := NewDB()
	b, e := os.ReadFile(s.path)
	if errors.Is(e, os.ErrNotExist) {
		return db, nil
	}
	if e != nil {
		return db, e
	}
	if err := json.Unmarshal(b, &db); err != nil {
		return db, fmt.Errorf("read database: %w", err)
	}
	db.Normalize()
	return db, nil
}
func (s *Store) Update(f func(*Database) error) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	db, err := s.read()
	if err != nil {
		return err
	}
	if err = f(&db); err != nil {
		return err
	}
	return s.write(db)
}
func (s *Store) write(db Database) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0700); err != nil {
		return err
	}
	b, err := json.MarshalIndent(db, "", "  ")
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(s.path), ".state-*")
	if err != nil {
		return err
	}
	defer os.Remove(tmp.Name())
	if err = tmp.Chmod(0600); err != nil {
		tmp.Close()
		return err
	}
	if _, err = tmp.Write(b); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Sync(); err != nil {
		tmp.Close()
		return err
	}
	if err = tmp.Close(); err != nil {
		return err
	}
	if err = os.Rename(tmp.Name(), s.path); err != nil {
		return err
	}
	// Persist the directory entry as well as the file contents before setup
	// consumes its one-time code or an API reports a durable update.
	dir, err := os.Open(filepath.Dir(s.path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
