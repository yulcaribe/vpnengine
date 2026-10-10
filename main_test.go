package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
	"github.com/yulcaribe/vpnengine/internal/engine"
)

func setupRequest(_ *testing.T, _ *app) string {
	return `{"username":"admin","password":"secret12345"}`
}

type testVPN struct {
	engine.Manager
	sync      func(core.Service, []core.User, bool) error
	revoke    func(core.Service, core.User) error
	configure func(core.Service, bool, []core.User, func(core.Service) error) (core.Service, error)
	prepare   func() error
}

func (m testVPN) SyncWireGuard(_ context.Context, s core.Service, users []core.User) error {
	return m.sync(s, users, false)
}
func (m testVPN) SyncWireGuardRevoked(_ context.Context, s core.Service, users []core.User) error {
	return m.sync(s, users, true)
}
func (m testVPN) SyncIKEv2(_ context.Context, s core.Service, users []core.User) error {
	return m.sync(s, users, true)
}
func (m testVPN) RevokeUser(_ context.Context, s core.Service, user core.User) error {
	return m.revoke(s, user)
}
func (m testVPN) ConfigureIPv6(_ context.Context, s core.Service, enabled bool, users []core.User, _ engine.Log, save func(core.Service) error) (core.Service, error) {
	return m.configure(s, enabled, users, save)
}
func (m testVPN) EnsureOpenVPNManagement(context.Context) error { return m.prepare() }

func vpnTestApp(t *testing.T, protocol string, enabled bool) (*app, http.Handler, *http.Cookie) {
	t.Helper()
	now := time.Now()
	a := &app{store: core.NewStore(t.TempDir()), sessions: map[string]session{"test": {Until: now.Add(sessionLifetime), LastActivity: now}}, jobs: map[string]*Task{}}
	s := engine.Defaults(protocol)
	s.Installed, s.Interface, s.Endpoint = true, "eth0", "203.0.113.10"
	if err := a.store.Update(func(db *core.Database) error {
		db.Config.SetupComplete = true
		db.Services[protocol] = s
		db.Users = []core.User{
			{ID: "target", Name: "alice", Service: protocol, Enabled: enabled, PasswordHash: "previous", IKESecret: "oldpassword123", PrivateKey: "preserved-private", PublicKey: "preserved-public", Address: "10.66.66.2"},
			{ID: "other", Name: "bob", Service: protocol, Enabled: true, PasswordHash: "other-hash", IKESecret: "otherpassword123"},
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	mux := http.NewServeMux()
	a.routes(mux)
	return a, mux, &http.Cookie{Name: "vpnengine_sid_http", Value: "test"}
}

func TestVPNRevocationFailuresKeepSavedAccessChanges(t *testing.T) {
	for _, protocol := range []string{core.WireGuard, core.OpenVPN, core.IKEv2} {
		for _, action := range []string{"toggle", "delete", "password"} {
			if protocol == core.WireGuard && action == "password" {
				continue
			}
			t.Run(protocol+"/"+action, func(t *testing.T) {
				a, handler, cookie := vpnTestApp(t, protocol, true)
				var synchronized, revoked bool
				a.mgr = testVPN{
					sync: func(s core.Service, users []core.User, failClosed bool) error {
						synchronized = true
						if !failClosed {
							t.Error("revocation used a rollback-on-error synchronization")
						}
						for _, u := range users {
							if u.ID == "target" && ((action == "toggle" && u.Enabled) || (action == "password" && u.IKESecret == "oldpassword123" && protocol == core.IKEv2)) {
								t.Error("synchronized the old access state")
							}
						}
						return errors.New("live synchronization failed")
					},
					revoke: func(s core.Service, u core.User) error {
						revoked = true
						if u.ID != "target" || u.Name != "alice" || s.ID != protocol {
							t.Error("wrong revocation target")
						}
						return errors.New("disconnect verification failed")
					},
				}
				method, path, body := "POST", "/api/users/target/"+action, `{}`
				if action == "delete" {
					method, path = "DELETE", "/api/users/target"
				}
				if action == "password" {
					body = `{"password":"replacement123"}`
				}
				w := req(t, handler, method, path, body, cookie)
				if w.Code != 500 || !strings.Contains(w.Body.String(), "access changes were saved") || !revoked {
					t.Fatalf("revocation not attempted/reported: %d %s", w.Code, w.Body.String())
				}
				if protocol != core.OpenVPN && !synchronized {
					t.Fatal("runtime access synchronization was skipped")
				}
				db, err := a.store.Read()
				if err != nil {
					t.Fatal(err)
				}
				for _, u := range db.Users {
					if u.ID == "other" && (!u.Enabled || u.PasswordHash != "other-hash") {
						t.Fatal("unrelated account changed")
					}
					if u.ID != "target" {
						continue
					}
					switch action {
					case "delete":
						t.Fatal("deleted user was restored after disconnect failure")
					case "toggle":
						if u.Enabled {
							t.Fatal("disabled user was re-enabled")
						}
					case "password":
						if protocol == core.OpenVPN && !core.VerifyPassword(u.PasswordHash, "replacement123") {
							t.Fatal("password change was rolled back")
						}
						if protocol == core.IKEv2 && u.IKESecret != "replacement123" {
							t.Fatal("IKEv2 password change was rolled back")
						}
					}
				}
			})
		}
	}
}

func TestFailedVPNGrantsRemovePartiallyAppliedAccess(t *testing.T) {
	for _, create := range []bool{false, true} {
		t.Run(fmt.Sprintf("create=%t", create), func(t *testing.T) {
			a, handler, cookie := vpnTestApp(t, core.IKEv2, false)
			calls, revoked := 0, false
			a.mgr = testVPN{
				sync: func(_ core.Service, users []core.User, _ bool) error {
					calls++
					if calls == 1 {
						return errors.New("partly loaded credentials")
					}
					for _, u := range users {
						if u.Name == "newuser" || (u.ID == "target" && u.Enabled) {
							t.Error("recovery retained a failed access grant")
						}
					}
					return nil
				},
				revoke: func(_ core.Service, u core.User) error {
					revoked = true
					want := "alice"
					if create {
						want = "newuser"
					}
					if u.Name != want {
						t.Error("disconnected unrelated account")
					}
					return nil
				},
			}
			path, body := "/api/users/target/toggle", `{}`
			if create {
				path, body = "/api/users", `{"service":"ikev2","name":"newuser","password":"secret12345"}`
			}
			w := req(t, handler, "POST", path, body, cookie)
			if w.Code != 500 || calls != 2 || !revoked {
				t.Fatalf("partial grant not cleaned: %d calls=%d revoked=%t %s", w.Code, calls, revoked, w.Body.String())
			}
			db, err := a.store.Read()
			if err != nil {
				t.Fatal(err)
			}
			if len(db.Users) != 2 || db.Users[0].Enabled || !db.Users[1].Enabled {
				t.Fatal("failed grant changed saved accounts")
			}
		})
	}
}

func TestOpenVPNRejectsCredentialsChangedDuringVerification(t *testing.T) {
	for _, change := range []string{"disable", "delete", "password", "service removal"} {
		t.Run(change, func(t *testing.T) {
			a, _, _ := vpnTestApp(t, core.OpenVPN, true)
			accepted := verifyOpenVPNUser(a.store, "alice", "old-password", func(string, string) bool {
				if err := a.store.Update(func(db *core.Database) error {
					switch change {
					case "disable":
						db.Users[0].Enabled = false
					case "delete":
						db.Users = withoutUser(db.Users, "target")
					case "password":
						db.Users[0].PasswordHash = "new-password-hash"
					case "service removal":
						delete(db.Services, core.OpenVPN)
					}
					return nil
				}); err != nil {
					t.Fatal(err)
				}
				return true
			})
			if accepted {
				t.Fatal("accepted a stale authentication result")
			}
		})
	}
}

func TestIPv6TaskPreservesExistingUsersAndServiceSettings(t *testing.T) {
	a, handler, cookie := vpnTestApp(t, core.WireGuard, true)
	if err := a.store.Update(func(db *core.Database) error {
		s := db.Services[core.WireGuard]
		s.IPv6 = true
		db.Services[core.WireGuard] = s
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	a.mgr = testVPN{configure: func(previous core.Service, enabled bool, users []core.User, save func(core.Service) error) (core.Service, error) {
		if !previous.IPv6 || enabled || len(users) != 2 || users[0].PrivateKey != "preserved-private" {
			t.Error("IPv6 task changed account material")
		}
		updated := previous
		updated.IPv6 = enabled
		return updated, save(updated)
	}}
	w := req(t, handler, "POST", "/api/services/wireguard/ipv6", `{"enabled":false}`, cookie)
	if w.Code != 202 {
		t.Fatalf("queue IPv6: %d %s", w.Code, w.Body.String())
	}
	var queued struct {
		ID string `json:"taskId"`
	}
	if err := json.Unmarshal(w.Body.Bytes(), &queued); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(3 * time.Second)
	for {
		a.mu.Lock()
		task := taskSnapshot(a.jobs[queued.ID])
		a.mu.Unlock()
		if task.Status != "running" {
			if task.Status != "done" {
				t.Fatalf("IPv6 task: %+v", task)
			}
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("IPv6 task did not finish")
		}
		time.Sleep(time.Millisecond)
	}
	db, err := a.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	s := db.Services[core.WireGuard]
	if s.IPv6 || s.CIDR != "10.66.66.0/24" || s.Port != 123 || len(db.Users) != 2 || db.Users[0].PrivateKey != "preserved-private" {
		t.Fatal("IPv6 task altered unrelated state")
	}
}

func TestStartupPreparationWarningsPreserveExistingState(t *testing.T) {
	a, _, _ := vpnTestApp(t, core.OpenVPN, true)
	db, err := a.store.Read()
	if err != nil {
		t.Fatal(err)
	}
	ike := engine.Defaults(core.IKEv2)
	ike.Installed = true
	db.Services[core.IKEv2] = ike
	calls := 0
	a.mgr = testVPN{prepare: func() error { calls++; return errors.New("local management unavailable") }, sync: func(core.Service, []core.User, bool) error { calls++; return errors.New("VICI unavailable") }}
	a.prepareServices(db)
	if calls != 2 || len(a.warnings) != 2 {
		t.Fatalf("missing startup controls/warnings: calls=%d warnings=%v", calls, a.warnings)
	}
	persisted, err := a.store.Read()
	if err != nil || len(persisted.Users) != 2 || !persisted.Users[0].Enabled {
		t.Fatal("failed preparation changed existing accounts")
	}
}

func req(t *testing.T, h http.Handler, method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
	t.Helper()
	r := httptest.NewRequest(method, "http://localhost:51821"+path, strings.NewReader(body))
	r.Header.Set("Content-Type", "application/json")
	if method == "POST" {
		r.Header.Set("Origin", "http://localhost:51821")
	}
	if cookie != nil {
		r.AddCookie(cookie)
	}
	w := httptest.NewRecorder()
	h.ServeHTTP(w, r)
	return w
}
func TestSetupAndAdminLogin(t *testing.T) {
	a := &app{store: core.NewStore(t.TempDir()), sessions: map[string]session{}, loginAttempts: map[string]attempts{}, jobs: map[string]*Task{}}
	mux := http.NewServeMux()
	a.routes(mux)
	w := req(t, mux, "GET", "/api/overview", "", nil)
	if w.Code != 401 {
		t.Fatalf("expected auth gate, got %d", w.Code)
	}
	w = req(t, mux, "POST", "/api/setup", setupRequest(t, a), nil)
	if w.Code != 200 {
		t.Fatalf("setup: %d %s", w.Code, w.Body.String())
	}
	w = req(t, mux, "POST", "/api/setup", `{"username":"evil","password":"secret12345"}`, nil)
	if w.Code != 409 {
		t.Fatalf("setup repeated: %d", w.Code)
	}
	w = req(t, mux, "POST", "/api/login", `{"username":"admin","password":"wrong"}`, nil)
	if w.Code != 401 {
		t.Fatalf("wrong password %d", w.Code)
	}
	w = req(t, mux, "POST", "/api/login", `{"username":"admin","password":"secret12345"}`, nil)
	if w.Code != 200 {
		t.Fatalf("login %d %s", w.Code, w.Body.String())
	}
	cookie := w.Result().Cookies()[0]
	if cookie.Name != "vpnengine_sid_http" || cookie.Value == "" || !cookie.HttpOnly || cookie.Secure {
		t.Fatal("invalid session cookie")
	}
	w = req(t, mux, "GET", "/api/overview", "", cookie)
	if w.Code != 200 {
		t.Fatalf("overview %d %s", w.Code, w.Body.String())
	}
	var data struct {
		Services []any `json:"services"`
		Users    []any `json:"users"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &data); e != nil {
		t.Fatal(e)
	}
	if len(data.Services) != 3 || len(data.Users) != 0 {
		t.Fatal("installer preinstalled services or users")
	}
	w = req(t, mux, "POST", "/api/logout", "{}", cookie)
	if w.Code != 200 {
		t.Fatal("logout failed")
	}
	w = req(t, mux, "GET", "/api/overview", "", cookie)
	if w.Code != 401 {
		t.Fatal("session remained valid after logout")
	}
}

func TestHTTPSProxyTrustAndSecureCookie(t *testing.T) {
	a := &app{store: core.NewStore(t.TempDir()), sessions: map[string]session{}, loginAttempts: map[string]attempts{}, jobs: map[string]*Task{}}
	mux := http.NewServeMux()
	a.routes(mux)

	proxyRequest := func(method, path, body string, cookie *http.Cookie) *httptest.ResponseRecorder {
		r := httptest.NewRequest(method, "http://203.0.113.10"+path, strings.NewReader(body))
		r.Host = "203.0.113.10"
		r.RemoteAddr = "127.0.0.1:41000"
		r.Header.Set("Content-Type", "application/json")
		r.Header.Set("X-Forwarded-Proto", "https")
		r.Header.Set("X-Real-IP", "198.51.100.25")
		if method == http.MethodPost {
			r.Header.Set("Origin", "https://203.0.113.10")
		}
		if cookie != nil {
			r.AddCookie(cookie)
		}
		w := httptest.NewRecorder()
		mux.ServeHTTP(w, r)
		return w
	}

	w := proxyRequest(http.MethodPost, "/api/setup", setupRequest(t, a), nil)
	if w.Code != http.StatusOK {
		t.Fatalf("https proxy setup: %d %s", w.Code, w.Body.String())
	}
	w = proxyRequest(http.MethodPost, "/api/login", `{"username":"admin","password":"secret12345"}`, nil)
	if w.Code != http.StatusOK {
		t.Fatalf("https proxy login: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].Secure || cookies[0].Name != "vpnengine_sid" {
		t.Fatal("HTTPS proxy session cookie is not Secure")
	}
	if got := remoteIP(httptest.NewRequest(http.MethodGet, "http://localhost/", nil)); got == "198.51.100.25" {
		t.Fatal("trusted a forwarded address from a non-proxy request")
	}

	spoofed := httptest.NewRequest(http.MethodPost, "http://203.0.113.10/api/login", strings.NewReader(`{}`))
	spoofed.Host = "203.0.113.10"
	spoofed.RemoteAddr = "198.51.100.10:42000"
	spoofed.Header.Set("Origin", "https://203.0.113.10")
	spoofed.Header.Set("X-Forwarded-Proto", "https")
	if originOK(spoofed) {
		t.Fatal("trusted X-Forwarded-Proto from a non-loopback client")
	}
}

func TestTaskSnapshotKeepsProgressAndCopiesMessages(t *testing.T) {
	original := &Task{
		ID:       "task-1",
		Service:  core.OpenVPN,
		Action:   "install",
		Status:   "running",
		Progress: 60,
		Stage:    "Creating VPN configuration",
		Messages: []string{"one"},
	}
	snap := taskSnapshot(original)
	if snap.Progress != 60 || snap.Stage != "Creating VPN configuration" {
		t.Fatal("task progress was not preserved")
	}
	snap.Messages[0] = "changed"
	if original.Messages[0] != "one" {
		t.Fatal("task snapshot shares message storage")
	}
}

type authTestClock struct {
	mu   sync.Mutex
	time time.Time
}

func (c *authTestClock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.time
}

func (c *authTestClock) Advance(d time.Duration) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.time = c.time.Add(d)
}

func adminTestApp(t *testing.T) (*app, *authTestClock) {
	t.Helper()
	c := &authTestClock{time: time.Date(2026, 10, 9, 12, 0, 0, 0, time.UTC)}
	a := &app{store: core.NewStore(t.TempDir()), sessions: map[string]session{}, loginAttempts: map[string]attempts{}, jobs: map[string]*Task{}, now: c.Now}
	hash, err := core.HashPassword("secret12345")
	if err != nil {
		t.Fatal(err)
	}
	if err = a.store.Update(func(db *core.Database) error {
		db.Config = core.Config{SetupComplete: true, AdminUser: "admin", PasswordHash: hash, PanelPort: 51821}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	return a, c
}

func loginTestRequest(a *app, ip, password string) *httptest.ResponseRecorder {
	body, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	r := httptest.NewRequest(http.MethodPost, "http://localhost:51821/api/login", strings.NewReader(string(body)))
	r.Header.Set("Content-Type", "application/json")
	r.RemoteAddr = ip + ":1234"
	w := httptest.NewRecorder()
	a.login(w, r)
	return w
}

func TestHTTPSetupWithoutConfirmation(t *testing.T) {
	a := &app{store: core.NewStore(t.TempDir())}
	w := req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", `{"username":"admin","password":"secret12345"}`, nil)
	if w.Code != 200 {
		t.Fatalf("HTTP setup required an extra confirmation: %d %s", w.Code, w.Body.String())
	}
	db, err := a.store.Read()
	if err != nil || !db.Config.SetupComplete || db.Config.AdminUser != "admin" {
		t.Fatalf("HTTP admin setup not saved: %v", err)
	}
	w = req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", `{"username":"second","password":"secret12345"}`, nil)
	if w.Code != 409 {
		t.Fatalf("first admin setup was not single-use: %d", w.Code)
	}
}

func TestHTTPSSetupWithoutConfirmation(t *testing.T) {
	a := &app{store: core.NewStore(t.TempDir())}
	r := httptest.NewRequest(http.MethodPost, "https://example.com/api/setup", strings.NewReader(`{"username":"admin","password":"secret12345"}`))
	r.Header.Set("Content-Type", "application/json")
	r.Header.Set("Origin", "https://example.com")
	w := httptest.NewRecorder()
	a.setup(w, r)
	if w.Code != 200 {
		t.Fatalf("HTTPS setup failed: %d %s", w.Code, w.Body.String())
	}
}

func TestSetupWithoutCodeRejectsInvalidInputAndBusyHash(t *testing.T) {
	a := &app{store: core.NewStore(t.TempDir())}
	w := req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", `{"username":"bad user","password":"secret12345"}`, nil)
	if w.Code != 400 {
		t.Fatalf("invalid username accepted: %d %s", w.Code, w.Body.String())
	}
	w = req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", `{"username":"admin","password":"short"}`, nil)
	if w.Code != 400 {
		t.Fatalf("invalid password accepted: %d %s", w.Code, w.Body.String())
	}
	if !a.acquirePasswordSlot() || !a.acquirePasswordSlot() {
		t.Fatal("could not occupy hash slots")
	}
	body := `{"username":"admin","password":"secret12345"}`
	w = req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", body, nil)
	if w.Code != 429 {
		t.Fatalf("busy setup status %d", w.Code)
	}
	<-a.hashSlots
	<-a.hashSlots
	db, err := a.store.Read()
	if err != nil || db.Config.SetupComplete {
		t.Fatalf("busy setup changed state: %v", err)
	}
	w = req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", body, nil)
	if w.Code != 200 {
		t.Fatalf("setup after retry failed: %d %s", w.Code, w.Body.String())
	}
	w = req(t, http.HandlerFunc(a.setup), "POST", "/api/setup", "not JSON", nil)
	if w.Code != 409 {
		t.Fatalf("initialized setup reprocessed invalid data: %d", w.Code)
	}
}

func TestHTTPLoginUsesSeparateCookieFromOldHTTPSCookie(t *testing.T) {
	a, _ := adminTestApp(t)
	w := loginTestRequest(a, "198.51.100.10", "secret12345")
	if w.Code != 200 {
		t.Fatalf("HTTP login failed: %d %s", w.Code, w.Body.String())
	}
	cookies := w.Result().Cookies()
	if len(cookies) != 1 || cookies[0].Name != "vpnengine_sid_http" || cookies[0].Secure {
		t.Fatalf("HTTP login must use a distinct non-Secure cookie: %v", cookies)
	}
	w = req(t, http.HandlerFunc(a.requireAuth(a.overview)), "GET", "/api/overview", "", &http.Cookie{Name: "vpnengine_sid", Value: "stale-https"})
	if w.Code != 401 {
		t.Fatalf("stale HTTPS cookie authenticated on HTTP: %d", w.Code)
	}
	w = req(t, http.HandlerFunc(a.requireAuth(a.overview)), "GET", "/api/overview", "", cookies[0])
	if w.Code != 200 {
		t.Fatalf("new HTTP cookie was rejected: %d", w.Code)
	}
}

func TestConcurrentLoginReservesAttemptBudget(t *testing.T) {
	a, clock := adminTestApp(t)
	// Raise only the hash gate in this test to isolate the per-IP admission
	// limit. Production hash parallelism is tested separately below.
	a.hashSlots = make(chan struct{}, 32)
	entered := make(chan struct{}, 16)
	release := make(chan struct{})
	a.passwordVerifier = func(string, string) bool { entered <- struct{}{}; <-release; return false }
	var wg sync.WaitGroup
	results := make(chan int, 16)
	for i := 0; i < 16; i++ {
		wg.Add(1)
		go func() { defer wg.Done(); results <- loginTestRequest(a, "198.51.100.7", "wrong-password").Code }()
	}
	for i := 0; i < 8; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("verification did not start")
		}
	}
	for i := 0; i < 8; i++ {
		select {
		case code := <-results:
			if code != 429 {
				close(release)
				t.Fatalf("excess pending login got %d", code)
			}
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("excess requests were not rejected")
		}
	}
	close(release)
	wg.Wait()
	for i := 0; i < 8; i++ {
		if code := <-results; code != 401 {
			t.Fatalf("admitted bad login got %d", code)
		}
	}
	a.mu.Lock()
	at := a.loginAttempts["198.51.100.7"]
	a.mu.Unlock()
	if at.Count != 8 || at.Pending != 0 || !at.LockedUntil.Equal(clock.Now().Add(loginLock)) {
		t.Fatalf("incorrect final limit state: %#v", at)
	}
	if len(entered) != 0 {
		t.Fatal("more than eight expensive verifications started")
	}
}

func TestGlobalPasswordHashBudget(t *testing.T) {
	a, _ := adminTestApp(t)
	entered := make(chan struct{}, 2)
	release := make(chan struct{})
	var active, maximum atomic.Int32
	a.passwordVerifier = func(string, string) bool {
		n := active.Add(1)
		for old := maximum.Load(); n > old && !maximum.CompareAndSwap(old, n); old = maximum.Load() {
		}
		entered <- struct{}{}
		<-release
		active.Add(-1)
		return false
	}
	results := make(chan int, 2)
	for _, ip := range []string{"198.51.100.1", "198.51.100.2"} {
		go func(ip string) { results <- loginTestRequest(a, ip, "wrong-password").Code }(ip)
	}
	for i := 0; i < 2; i++ {
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
			close(release)
			t.Fatal("hash slots did not fill")
		}
	}
	w := loginTestRequest(a, "198.51.100.3", "wrong-password")
	if w.Code != 429 {
		close(release)
		t.Fatalf("third IP escaped global hash budget: %d", w.Code)
	}
	a.mu.Lock()
	_, recorded := a.loginAttempts["198.51.100.3"]
	a.mu.Unlock()
	close(release)
	for i := 0; i < 2; i++ {
		if code := <-results; code != 401 {
			t.Fatalf("admitted login got %d", code)
		}
	}
	if recorded || maximum.Load() != 2 {
		t.Fatalf("busy requests consumed attempts or excessive concurrency: recorded=%t maximum=%d", recorded, maximum.Load())
	}
}

func TestLoginLockExpiresWithoutExtension(t *testing.T) {
	a, clock := adminTestApp(t)
	a.passwordVerifier = func(_ string, password string) bool { return password == "secret12345" }
	for i := 0; i < 8; i++ {
		if w := loginTestRequest(a, "198.51.100.4", "wrong-password"); w.Code != 401 {
			t.Fatalf("bad attempt %d status %d", i+1, w.Code)
		}
	}
	a.mu.Lock()
	deadline := a.loginAttempts["198.51.100.4"].LockedUntil
	a.mu.Unlock()
	clock.Advance(4 * time.Minute)
	if w := loginTestRequest(a, "198.51.100.4", "secret12345"); w.Code != 429 {
		t.Fatalf("locked login status %d", w.Code)
	}
	a.mu.Lock()
	unchanged := a.loginAttempts["198.51.100.4"].LockedUntil.Equal(deadline)
	a.mu.Unlock()
	if !unchanged {
		t.Fatal("blocked requests extended the lock")
	}
	clock.Advance(time.Minute)
	if w := loginTestRequest(a, "198.51.100.4", "secret12345"); w.Code != 200 {
		t.Fatalf("login at exact unlock boundary status %d", w.Code)
	}
}

func protectedTestRequest(a *app, path, token string) int {
	r := httptest.NewRequest(http.MethodGet, "http://localhost:51821"+path, nil)
	r.AddCookie(&http.Cookie{Name: "vpnengine_sid_http", Value: token})
	w := httptest.NewRecorder()
	a.requireAuth(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(204) })(w, r)
	return w.Code
}

func TestTaskPollingDoesNotExtendIdleSession(t *testing.T) {
	a, clock := adminTestApp(t)
	started := clock.Now()
	a.sessions["token"] = session{Until: started.Add(sessionLifetime), LastActivity: started}
	a.jobs["running"] = &Task{ID: "running", Status: "running"}
	for i := 0; i < 2; i++ {
		clock.Advance(10 * time.Minute)
		if code := protectedTestRequest(a, "/api/tasks/active", "token"); code != 204 {
			t.Fatalf("premature idle expiry: %d", code)
		}
	}
	clock.Advance(10 * time.Minute)
	if code := protectedTestRequest(a, "/api/tasks/running", "token"); code != 401 {
		t.Fatalf("task polling kept idle session alive: %d", code)
	}
	if a.jobs["running"].Status != "running" {
		t.Fatal("expiring session stopped background task")
	}
}

func TestActivityRenewsIdleButNotAbsoluteLifetime(t *testing.T) {
	a, clock := adminTestApp(t)
	started := clock.Now()
	a.sessions["token"] = session{Until: started.Add(sessionLifetime), LastActivity: started}
	for i := 0; i < 35; i++ {
		clock.Advance(20 * time.Minute)
		if code := protectedTestRequest(a, "/api/overview", "token"); code != 204 {
			t.Fatalf("active session expired at step %d: %d", i, code)
		}
		if !a.sessions["token"].Until.Equal(started.Add(sessionLifetime)) {
			t.Fatal("activity extended absolute deadline")
		}
	}
	clock.Advance(20 * time.Minute)
	if code := protectedTestRequest(a, "/api/overview", "token"); code != 401 {
		t.Fatalf("session survived exact 12-hour boundary: %d", code)
	}
	// A session at exactly its idle limit cannot be resurrected by activity.
	now := clock.Now()
	a.sessions["idle"] = session{Until: now.Add(sessionLifetime), LastActivity: now}
	clock.Advance(sessionIdle)
	if code := protectedTestRequest(a, "/api/overview", "idle"); code != 401 {
		t.Fatalf("activity resurrected expired session: %d", code)
	}
}

func TestCredentialChangeRejectsInflightLogin(t *testing.T) {
	for _, change := range []string{"password", "username"} {
		t.Run(change, func(t *testing.T) {
			a, clock := adminTestApp(t)
			a.sessions["existing"] = session{Until: clock.Now().Add(sessionLifetime), LastActivity: clock.Now()}
			entered := make(chan struct{})
			release := make(chan struct{})
			a.passwordVerifier = func(hash, password string) bool {
				close(entered)
				<-release
				return core.VerifyPassword(hash, password)
			}
			result := make(chan *httptest.ResponseRecorder, 1)
			go func() { result <- loginTestRequest(a, "198.51.100.5", "secret12345") }()
			select {
			case <-entered:
			case <-time.After(5 * time.Second):
				close(release)
				t.Fatal("login did not start")
			}
			username, password := "admin", "replacement123"
			if change == "username" {
				username, password = "renamed", ""
			}
			body, _ := json.Marshal(map[string]any{"username": username, "newPassword": password, "panelPort": 51821})
			w := req(t, http.HandlerFunc(a.requireAuth(a.settings)), "POST", "/api/settings", string(body), &http.Cookie{Name: "vpnengine_sid_http", Value: "existing"})
			if w.Code != 200 {
				close(release)
				t.Fatalf("credential change failed: %d %s", w.Code, w.Body.String())
			}
			close(release)
			login := <-result
			if login.Code != 401 || len(login.Result().Cookies()) != 0 || len(a.sessions) != 0 {
				t.Fatalf("old in-flight login recreated session: status=%d sessions=%d", login.Code, len(a.sessions))
			}
			if code := protectedTestRequest(a, "/api/overview", "existing"); code != 401 {
				t.Fatalf("existing session remained valid: %d", code)
			}
			a.passwordVerifier = nil
			if password == "" {
				password = "secret12345"
			}
			loginBody, _ := json.Marshal(map[string]string{"username": username, "password": password})
			w = req(t, http.HandlerFunc(a.login), "POST", "/api/login", string(loginBody), nil)
			if w.Code != 200 {
				t.Fatalf("new credentials do not work: %d %s", w.Code, w.Body.String())
			}
		})
	}
}

func TestAuthMapBoundsAndExpiredCleanup(t *testing.T) {
	a, clock := adminTestApp(t)
	a.passwordVerifier = func(string, string) bool { return true }
	for i := 0; i < maxLoginIPs; i++ {
		a.loginAttempts[fmt.Sprint(i)] = attempts{Count: 1, Since: clock.Now()}
	}
	if w := loginTestRequest(a, "198.51.100.6", "secret12345"); w.Code != 429 {
		t.Fatalf("full IP map admitted more entries: %d", w.Code)
	}
	if len(a.loginAttempts) != maxLoginIPs {
		t.Fatal("IP map exceeded bound")
	}
	clock.Advance(loginLock)
	if w := loginTestRequest(a, "198.51.100.6", "secret12345"); w.Code != 200 {
		t.Fatalf("expired entries not cleaned up: %d", w.Code)
	}
	if len(a.loginAttempts) != 0 {
		t.Fatalf("expired attempts retained: %d", len(a.loginAttempts))
	}
	now := clock.Now()
	a.sessions = map[string]session{}
	for i := 0; i < maxSessions; i++ {
		a.sessions[fmt.Sprint(i)] = session{Until: now.Add(sessionLifetime), LastActivity: now}
	}
	if w := loginTestRequest(a, "198.51.100.6", "secret12345"); w.Code != 503 {
		t.Fatalf("full session map admitted more entries: %d", w.Code)
	}
	if len(a.sessions) != maxSessions {
		t.Fatal("session map exceeded bound")
	}
	clock.Advance(sessionIdle)
	if w := loginTestRequest(a, "198.51.100.6", "secret12345"); w.Code != 200 {
		t.Fatalf("expired sessions not cleaned up: %d", w.Code)
	}
	if len(a.sessions) != 1 {
		t.Fatalf("expired sessions retained: %d", len(a.sessions))
	}
}
