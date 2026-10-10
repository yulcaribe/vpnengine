package core

import (
	"errors"
	"os"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
)

func finishAdminSetup(db *Database) error {
	db.Config.SetupComplete = true
	db.Config.AdminUser = "admin"
	db.Config.PasswordHash = "hash"
	return nil
}

func TestSetupAdminIsSingleUseAcrossStores(t *testing.T) {
	dir := t.TempDir()
	const requests = 12
	var wg sync.WaitGroup
	var claimed atomic.Int32
	var configured atomic.Int32
	for i := 0; i < requests; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := NewStore(dir).SetupAdmin(func(db *Database) error {
				configured.Add(1)
				return finishAdminSetup(db)
			})
			if err == nil {
				claimed.Add(1)
			} else if !errors.Is(err, ErrSetupComplete) {
				t.Errorf("setup raced unexpectedly: %v", err)
			}
		}()
	}
	wg.Wait()
	if claimed.Load() != 1 || configured.Load() != 1 {
		t.Fatalf("claimed=%d configured=%d", claimed.Load(), configured.Load())
	}
	db, err := NewStore(dir).Read()
	if err != nil || !db.Config.SetupComplete || db.Config.AdminUser != "admin" {
		t.Fatalf("first admin was not saved: %v %+v", err, db.Config)
	}
}

func TestSetupAdminValidationAndLegacyCleanup(t *testing.T) {
	dir := t.TempDir()
	s := NewStore(dir)
	failure := errors.New("no valid password")
	if err := s.SetupAdmin(func(*Database) error { return failure }); !errors.Is(err, failure) {
		t.Fatalf("validation error lost: %v", err)
	}
	db, err := s.Read()
	if err != nil || db.Config.SetupComplete {
		t.Fatalf("failed setup initialized account: %v", err)
	}
	if err := s.SetupAdmin(func(*Database) error { return nil }); err == nil {
		t.Fatal("setup could commit with incomplete credentials")
	}
	if err := os.WriteFile(filepath.Join(dir, "bootstrap.json"), []byte("obsolete"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := s.SetupAdmin(finishAdminSetup); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, "bootstrap.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("obsolete setup-code state retained: %v", err)
	}
	if err := s.SetupAdmin(finishAdminSetup); !errors.Is(err, ErrSetupComplete) {
		t.Fatalf("repeated setup not rejected: %v", err)
	}
}
