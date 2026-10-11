package core

import (
	"errors"
	"os"
	"path/filepath"
	"syscall"
)

var ErrSetupComplete = errors.New("setup is already complete")

// SetupAdmin atomically creates the first administrator. A filesystem lock
// prevents two separate panel processes from claiming the same installation.
func (s *Store) SetupAdmin(configure func(*Database) error) error {
	if configure == nil {
		return errors.New("setup configuration callback is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	dir := filepath.Dir(s.path)
	if err := os.MkdirAll(dir, 0700); err != nil {
		return err
	}
	lockPath := filepath.Join(dir, "setup.lock")
	fd, err := syscall.Open(lockPath, syscall.O_CREAT|syscall.O_RDWR|syscall.O_CLOEXEC|syscall.O_NOFOLLOW, 0600)
	if err != nil {
		return err
	}
	file := os.NewFile(uintptr(fd), lockPath)
	defer file.Close()
	if err = file.Chmod(0600); err != nil {
		return err
	}
	for {
		err = syscall.Flock(fd, syscall.LOCK_EX)
		if err != syscall.EINTR {
			break
		}
	}
	if err != nil {
		return err
	}
	defer syscall.Flock(fd, syscall.LOCK_UN)

	db, err := s.read()
	if err != nil {
		return err
	}
	if db.Config.SetupComplete {
		return ErrSetupComplete
	}
	if err := configure(&db); err != nil {
		return err
	}
	if !db.Config.SetupComplete {
		return errors.New("setup callback did not complete setup")
	}
	if err := s.write(db); err != nil {
		return err
	}
	// Delete obsolete setup-code material from pre-1.1.8 installations.
	_ = os.Remove(filepath.Join(dir, "bootstrap.json"))
	return nil
}
