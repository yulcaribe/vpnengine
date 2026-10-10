package main

import (
	"context"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"github.com/yulcaribe/vpnengine/internal/core"
	"github.com/yulcaribe/vpnengine/internal/engine"
)

var version = "1.1.12"

const (
	maxBody         = 32 << 10
	sessionIdle     = 30 * time.Minute
	sessionLifetime = 12 * time.Hour
	loginLock       = 5 * time.Minute
	maxLoginIPs     = 4096
	maxSessions     = 1024
)

var errPasswordBusy = errors.New("authentication is busy; try again shortly")

//go:embed web/*
var webFiles embed.FS

type session struct {
	Until        time.Time
	LastActivity time.Time
}
type attempts struct {
	Count       int
	Pending     int
	Since       time.Time
	LockedUntil time.Time
}
type Task struct {
	ID       string    `json:"id"`
	Service  string    `json:"service"`
	Action   string    `json:"action"`
	Status   string    `json:"status"`
	Progress int       `json:"progress"`
	Stage    string    `json:"stage"`
	Messages []string  `json:"messages"`
	Error    string    `json:"error,omitempty"`
	Started  time.Time `json:"started"`
}
type vpnManager interface {
	Install(context.Context, core.Service, map[string]core.Service, engine.Log, engine.Progress) error
	Remove(context.Context, string, engine.Log) error
	Control(context.Context, string, string, engine.Log) error
	SyncWireGuard(context.Context, core.Service, []core.User) error
	SyncWireGuardRevoked(context.Context, core.Service, []core.User) error
	SyncIKEv2(context.Context, core.Service, []core.User) error
	RevokeUser(context.Context, core.Service, core.User) error
	EnsureOpenVPNManagement(context.Context) error
	ConfigureIPv6(context.Context, core.Service, bool, []core.User, engine.Log, func(core.Service) error) (core.Service, error)
}
type app struct {
	store            *core.Store
	mgr              vpnManager
	mu               sync.Mutex
	sessions         map[string]session
	loginAttempts    map[string]attempts
	jobs             map[string]*Task
	opMu             sync.Mutex
	authGeneration   uint64
	now              func() time.Time
	passwordVerifier func(string, string) bool
	hashOnce         sync.Once
	hashSlots        chan struct{}
	warnings         []string
}

func (a *app) vpn() vpnManager {
	if a.mgr != nil {
		return a.mgr
	}
	return engine.Manager{}
}

func (a *app) prepareServices(db core.Database) {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	if db.Services[core.OpenVPN].Installed {
		if err := a.vpn().EnsureOpenVPNManagement(ctx); err != nil {
			a.warnings = append(a.warnings, "OpenVPN connection controls could not be prepared: "+err.Error())
		}
	}
	if service := db.Services[core.IKEv2]; service.Installed {
		if err := a.vpn().SyncIKEv2(ctx, service, db.Users); err != nil {
			a.warnings = append(a.warnings, "IKEv2 account controls could not be refreshed: "+err.Error())
		}
	}
	for _, warning := range a.warnings {
		log.Println(warning)
	}
}

func main() {
	if len(os.Args) > 1 {
		switch os.Args[1] {
		case "--version":
			fmt.Println("VPN Engine", version)
			return
		case "auth":
			if len(os.Args) == 4 && os.Args[2] == "openvpn" && authOpenVPN(os.Args[3]) {
				return
			}
			os.Exit(1)
		case "net":
			// OpenVPN appends interface/address arguments to --up/--down commands.
			// The first four arguments identify the VPN Engine action; any trailing
			// OpenVPN-supplied arguments are intentionally ignored.
			if len(os.Args) >= 4 && (os.Args[2] == "up" || os.Args[2] == "down") && core.IsService(os.Args[3]) {
				if err := (engine.Manager{}).Net(context.Background(), os.Args[3], os.Args[2] == "up"); err == nil {
					return
				} else {
					log.Println(err)
				}
			}
			os.Exit(1)
		}
	}
	if os.Geteuid() != 0 {
		log.Fatal("VPN Engine must run as root")
	}
	a := &app{store: core.NewStore(engine.DataDir), sessions: map[string]session{}, loginAttempts: map[string]attempts{}, jobs: map[string]*Task{}}
	db, err := a.store.Read()
	if err != nil {
		log.Fatal(err)
	}
	a.prepareServices(db)
	port := db.Config.PanelPort
	if port == 0 {
		port = 51821
		if v := os.Getenv("VPN_ENGINE_PORT"); v != "" {
			if x, err := strconv.Atoi(v); err == nil && x > 0 && x < 65536 {
				port = x
			}
		}
	}
	mux := http.NewServeMux()
	a.routes(mux)
	addr := fmt.Sprintf(":%d", port)
	if proxyMode() {
		addr = fmt.Sprintf("127.0.0.1:%d", port)
	}
	server := &http.Server{Addr: addr, Handler: securityHeaders(mux), ReadHeaderTimeout: 10 * time.Second, ReadTimeout: 30 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 90 * time.Second}
	log.Printf("VPN Engine %s backend available at http://%s", version, addr)
	log.Fatal(server.ListenAndServe())
}
func authOpenVPN(filename string) bool {
	// OpenVPN passes a temporary two-line username/password file via via-file.
	f, err := os.Open(filename)
	if err != nil {
		return false
	}
	defer f.Close()
	raw, err := io.ReadAll(io.LimitReader(f, 4096))
	if err != nil {
		return false
	}
	lines := strings.SplitN(string(raw), "\n", 3)
	if len(lines) < 2 {
		return false
	}
	user := strings.TrimSuffix(lines[0], "\r")
	pass := strings.TrimSuffix(strings.TrimSuffix(lines[1], "\r"), "\n")
	return verifyOpenVPNUser(core.NewStore(engine.DataDir), user, pass, core.VerifyPassword)
}

func verifyOpenVPNUser(store *core.Store, user, pass string, verify func(string, string) bool) bool {
	db, err := store.Read()
	if err != nil || !db.Services[core.OpenVPN].Installed {
		return false
	}
	for _, u := range db.Users {
		if u.Service == core.OpenVPN && u.Enabled && u.Name == user {
			if !verify(u.PasswordHash, pass) {
				return false
			}
			// Verification can overlap a disable, deletion or password change.
			// Reject the old credentials once the current state has changed.
			latest, err := store.Read()
			if err != nil || !latest.Services[core.OpenVPN].Installed {
				return false
			}
			for _, current := range latest.Users {
				if current.ID == u.ID && current.Service == core.OpenVPN && current.Name == user {
					return current.Enabled && current.PasswordHash == u.PasswordHash
				}
			}
			return false
		}
	}
	return false
}
func securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Cache-Control", "no-store")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; style-src 'self'; script-src 'self'; img-src 'self' data:; connect-src 'self'; base-uri 'none'; frame-ancestors 'none'")
		next.ServeHTTP(w, r)
	})
}
func proxyMode() bool { return os.Getenv("VPN_ENGINE_PROXY_MODE") == "1" }

func localProxy(r *http.Request) bool {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		host = r.RemoteAddr
	}
	ip := net.ParseIP(strings.Trim(host, "[]"))
	return ip != nil && ip.IsLoopback()
}

func requestScheme(r *http.Request) string {
	if r.TLS != nil {
		return "https"
	}
	if localProxy(r) {
		proto := strings.TrimSpace(strings.Split(r.Header.Get("X-Forwarded-Proto"), ",")[0])
		if strings.EqualFold(proto, "https") {
			return "https"
		}
	}
	return "http"
}

func originOK(r *http.Request) bool {
	o := r.Header.Get("Origin")
	return o == "" || o == requestScheme(r)+"://"+r.Host
}
func jsonReply(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}
func fail(w http.ResponseWriter, status int, msg string) {
	jsonReply(w, status, map[string]string{"error": msg})
}
func readJSON(r *http.Request, d any) error {
	if r.Header.Get("Content-Type") != "application/json" && !strings.HasPrefix(r.Header.Get("Content-Type"), "application/json;") {
		return errors.New("expected application/json")
	}
	dec := json.NewDecoder(io.LimitReader(r.Body, maxBody))
	dec.DisallowUnknownFields()
	if err := dec.Decode(d); err != nil {
		return err
	}
	var extra any
	if dec.Decode(&extra) != io.EOF {
		return errors.New("unexpected trailing JSON")
	}
	return nil
}
func (a *app) routes(mux *http.ServeMux) {
	mux.HandleFunc("/api/state", a.state)
	mux.HandleFunc("/api/setup", a.setup)
	mux.HandleFunc("/api/login", a.login)
	mux.HandleFunc("/api/logout", a.requireAuth(a.logout))
	mux.HandleFunc("/api/overview", a.requireAuth(a.overview))
	mux.HandleFunc("/api/settings", a.requireAuth(a.settings))
	mux.HandleFunc("/api/services/", a.requireAuth(a.services))
	mux.HandleFunc("/api/users", a.requireAuth(a.users))
	mux.HandleFunc("/api/users/", a.requireAuth(a.userItem))
	mux.HandleFunc("/api/tasks/active", a.requireAuth(a.activeTask))
	mux.HandleFunc("/api/tasks/", a.requireAuth(a.task))
	sub, _ := fs.Sub(webFiles, "web")
	mux.Handle("/", http.FileServer(http.FS(sub)))
}
func sessionCookieName(r *http.Request) string {
	if requestScheme(r) == "https" {
		return "vpnengine_sid"
	}
	// HTTPS Secure cookies cannot be overwritten on an HTTP fallback.
	return "vpnengine_sid_http"
}

func (a *app) requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet && r.Method != http.MethodHead && !originOK(r) {
			fail(w, 403, "origin check failed")
			return
		}
		c, err := r.Cookie(sessionCookieName(r))
		if err != nil {
			fail(w, 401, "login required")
			return
		}
		a.mu.Lock()
		now := a.timeNow()
		a.cleanupAuthLocked(now)
		s, ok := a.sessions[c.Value]
		if ok && (!now.Before(s.Until) || !now.Before(s.LastActivity.Add(sessionIdle))) {
			delete(a.sessions, c.Value)
			ok = false
		}
		// Task progress is polled automatically. It must not keep an unattended
		// browser signed in, and expiring its cookie must not stop the task.
		if ok && r.Method != http.MethodHead && !strings.HasPrefix(r.URL.Path, "/api/tasks/") {
			s.LastActivity = now
			a.sessions[c.Value] = s
		}
		a.mu.Unlock()
		if !ok {
			// Clear RAM-backed sessions that expired or disappeared on restart.
			http.SetCookie(w, &http.Cookie{Name: sessionCookieName(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: requestScheme(r) == "https", SameSite: http.SameSiteStrictMode})
			fail(w, 401, "login required")
			return
		}
		next(w, r)
	}
}

func (a *app) timeNow() time.Time {
	if a.now != nil {
		return a.now()
	}
	return time.Now()
}

// Called with a.mu held. Both maps have admission limits, so cleanup work and
// memory stay bounded even when attackers rotate addresses.
func (a *app) cleanupAuthLocked(now time.Time) {
	for token, s := range a.sessions {
		if !now.Before(s.Until) || !now.Before(s.LastActivity.Add(sessionIdle)) {
			delete(a.sessions, token)
		}
	}
	for ip, at := range a.loginAttempts {
		if at.Pending != 0 {
			continue
		}
		if (!at.LockedUntil.IsZero() && !now.Before(at.LockedUntil)) ||
			(at.LockedUntil.IsZero() && (at.Count == 0 || !now.Before(at.Since.Add(loginLock)))) {
			delete(a.loginAttempts, ip)
		}
	}
}

func (a *app) acquirePasswordSlot() bool {
	a.hashOnce.Do(func() {
		if a.hashSlots == nil {
			a.hashSlots = make(chan struct{}, 2)
		}
	})
	select {
	case a.hashSlots <- struct{}{}:
		return true
	default:
		return false
	}
}

func (a *app) hashPassword(password string) (string, error) {
	if !a.acquirePasswordSlot() {
		return "", errPasswordBusy
	}
	defer func() { <-a.hashSlots }()
	return core.HashPassword(password)
}

// An admitted request reserves one attempt before verification. Reservations
// prevent concurrent requests from all observing the same remaining budget.
func (a *app) finishLoginLocked(ip string, now time.Time, bad, success bool) {
	at := a.loginAttempts[ip]
	if at.Pending > 0 {
		at.Pending--
	}
	if success {
		at.Count, at.Since, at.LockedUntil = 0, now, time.Time{}
	} else if bad {
		at.Count++
		if at.Count >= 8 && at.LockedUntil.IsZero() {
			at.LockedUntil = now.Add(loginLock)
		}
	}
	if at.Count == 0 && at.Pending == 0 {
		delete(a.loginAttempts, ip)
	} else {
		a.loginAttempts[ip] = at
	}
}

func passwordError(w http.ResponseWriter, err error) {
	status := http.StatusBadRequest
	if errors.Is(err, errPasswordBusy) {
		status = http.StatusTooManyRequests
	}
	fail(w, status, err.Error())
}
func method(w http.ResponseWriter, r *http.Request, want string) bool {
	if r.Method != want {
		fail(w, 405, "method not allowed")
		return false
	}
	return true
}
func (a *app) state(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	db, err := a.store.Read()
	if err != nil {
		fail(w, 500, "could not load settings")
		return
	}
	host, _, err := net.SplitHostPort(r.Host)
	if err != nil {
		host = r.Host
	}
	host = strings.Trim(host, "[]")
	jsonReply(w, 200, map[string]any{"version": version, "setupComplete": db.Config.SetupComplete, "suggestedHost": host, "suggestedInterface": engine.DetectInterface()})
}
func cleanUsername(s string) string { return strings.TrimSpace(s) }
func (a *app) setup(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !originOK(r) {
		fail(w, 403, "origin check failed")
		return
	}
	// Reject initialized installations before parsing or hashing a password.
	// SetupAdmin checks again under a cross-process lock before saving.
	db, err := a.store.Read()
	if err != nil {
		fail(w, 500, "could not load settings")
		return
	}
	if db.Config.SetupComplete {
		fail(w, 409, "setup already completed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, "invalid setup request")
		return
	}
	req.Username = cleanUsername(req.Username)
	if !engine.ValidUsername(req.Username) {
		fail(w, 400, "invalid admin username")
		return
	}
	port := 51821
	if db.Config.PanelPort > 0 {
		port = db.Config.PanelPort
	} else if v := os.Getenv("VPN_ENGINE_PORT"); v != "" {
		if n, e := strconv.Atoi(v); e == nil && n > 0 && n < 65536 {
			port = n
		}
	}
	err = a.store.SetupAdmin(func(db *core.Database) error {
		hash, err := a.hashPassword(req.Password)
		if err != nil {
			return err
		}
		db.Config.SetupComplete = true
		db.Config.AdminUser = req.Username
		db.Config.PasswordHash = hash
		db.Config.PanelPort = port
		return nil
	})
	if err != nil {
		status := http.StatusBadRequest
		switch {
		case errors.Is(err, core.ErrSetupComplete):
			status = http.StatusConflict
		case errors.Is(err, errPasswordBusy):
			status = http.StatusTooManyRequests
		default:
			if !errors.Is(err, core.ErrPasswordLength) {
				fail(w, 500, "could not save setup")
				return
			}
		}
		fail(w, status, err.Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func remoteIP(r *http.Request) string {
	if localProxy(r) {
		if forwarded := strings.TrimSpace(r.Header.Get("X-Real-IP")); forwarded != "" {
			if ip := net.ParseIP(forwarded); ip != nil {
				return ip.String()
			}
		}
	}
	h, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return h
	}
	return r.RemoteAddr
}
func (a *app) login(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !originOK(r) {
		fail(w, 403, "origin check failed")
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, "invalid login request")
		return
	}
	ip := remoteIP(r)
	a.mu.Lock()
	now := a.timeNow()
	a.cleanupAuthLocked(now)
	db, err := a.store.Read()
	if err != nil || !db.Config.SetupComplete {
		a.mu.Unlock()
		fail(w, 400, "setup not complete")
		return
	}
	at, exists := a.loginAttempts[ip]
	if !at.LockedUntil.IsZero() && !now.Before(at.LockedUntil) {
		at.Count, at.Since, at.LockedUntil = 0, now, time.Time{}
	}
	if at.LockedUntil.IsZero() && !at.Since.IsZero() && !now.Before(at.Since.Add(loginLock)) {
		at.Count, at.Since = 0, now
	}
	if now.Before(at.LockedUntil) || at.Count+at.Pending >= 8 || (!exists && len(a.loginAttempts) >= maxLoginIPs) {
		a.mu.Unlock()
		fail(w, 429, "too many attempts; try again in 5 minutes")
		return
	}
	if at.Since.IsZero() {
		at.Since = now
	}
	at.Pending++
	a.loginAttempts[ip] = at
	generation := a.authGeneration
	a.mu.Unlock()

	if !a.acquirePasswordSlot() {
		a.mu.Lock()
		if generation == a.authGeneration {
			a.finishLoginLocked(ip, a.timeNow(), false, false)
		}
		a.mu.Unlock()
		fail(w, 429, errPasswordBusy.Error())
		return
	}
	valid := false
	if req.Username == db.Config.AdminUser && len(req.Password) <= 256 {
		verify := a.passwordVerifier
		if verify == nil {
			verify = core.VerifyPassword
		}
		valid = verify(db.Config.PasswordHash, req.Password)
	}
	<-a.hashSlots
	var token string
	if valid {
		token, err = core.RandomToken(32)
	}
	a.mu.Lock()
	now = a.timeNow()
	// The credential snapshot and generation must still be current when the
	// session is committed. settings holds this same lock while saving and
	// revoking, so an old in-flight verification cannot recreate a session.
	latest, readErr := a.store.Read()
	if generation != a.authGeneration || readErr != nil || latest.Config.AdminUser != db.Config.AdminUser || latest.Config.PasswordHash != db.Config.PasswordHash {
		if generation == a.authGeneration {
			a.finishLoginLocked(ip, now, false, false)
		}
		a.mu.Unlock()
		fail(w, 401, "credentials changed; sign in again")
		return
	}
	if !valid {
		a.finishLoginLocked(ip, now, true, false)
		a.mu.Unlock()
		fail(w, 401, "wrong username or password")
		return
	}
	a.cleanupAuthLocked(now)
	if err != nil || len(a.sessions) >= maxSessions {
		a.finishLoginLocked(ip, now, false, false)
		a.mu.Unlock()
		fail(w, 503, "could not create login session; try again shortly")
		return
	}
	a.finishLoginLocked(ip, now, false, true)
	a.sessions[token] = session{Until: now.Add(sessionLifetime), LastActivity: now}
	a.mu.Unlock()
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName(r), Value: token, Path: "/", HttpOnly: true, Secure: requestScheme(r) == "https", SameSite: http.SameSiteStrictMode, MaxAge: 43200})
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func (a *app) logout(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if c, e := r.Cookie(sessionCookieName(r)); e == nil {
		a.mu.Lock()
		delete(a.sessions, c.Value)
		a.mu.Unlock()
	}
	http.SetCookie(w, &http.Cookie{Name: sessionCookieName(r), Path: "/", MaxAge: -1, HttpOnly: true, Secure: requestScheme(r) == "https", SameSite: http.SameSiteStrictMode})
	jsonReply(w, 200, map[string]bool{"ok": true})
}
func publicUser(u core.User) map[string]any {
	return map[string]any{"id": u.ID, "service": u.Service, "name": u.Name, "enabled": u.Enabled, "address": u.Address, "ipv6Address": u.IPv6Address, "createdAt": u.CreatedAt}
}
func (a *app) overview(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	db, err := a.store.Read()
	if err != nil {
		fail(w, 500, "read failed")
		return
	}
	if !db.Config.SetupComplete {
		fail(w, 403, "setup required")
		return
	}
	services := make([]map[string]any, 0, 3)
	for _, id := range []string{core.WireGuard, core.OpenVPN, core.IKEv2} {
		s, ok := db.Services[id]
		if !ok {
			s = engine.Defaults(id)
		}
		services = append(services, map[string]any{"id": id, "config": s, "installed": s.Installed, "status": engine.Status(id)})
	}
	users := make([]map[string]any, 0, len(db.Users))
	for _, u := range db.Users {
		users = append(users, publicUser(u))
	}
	jsonReply(w, 200, map[string]any{"adminUser": db.Config.AdminUser, "panelPort": db.Config.PanelPort, "https": requestScheme(r) == "https", "services": services, "users": users, "outgoingInterface": engine.DetectInterface(), "version": version, "ipv6Available": engine.IPv6Available(r.Context()), "warnings": a.warnings})
}
func (a *app) settings(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !a.opMu.TryLock() {
		fail(w, 409, "another operation is running")
		return
	}
	defer a.opMu.Unlock()
	var req struct {
		Username    string `json:"username"`
		NewPassword string `json:"newPassword"`
		PanelPort   int    `json:"panelPort"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, "invalid request")
		return
	}
	req.Username = cleanUsername(req.Username)
	if !engine.ValidUsername(req.Username) {
		fail(w, 400, "invalid admin username")
		return
	}
	if req.PanelPort < 1 || req.PanelPort > 65535 {
		fail(w, 400, "invalid panel port")
		return
	}
	db, err := a.store.Read()
	if err != nil {
		fail(w, 500, "read failed")
		return
	}
	if proxyMode() && req.PanelPort != db.Config.PanelPort {
		fail(w, 409, "panel port is managed internally while HTTPS is enabled")
		return
	}
	changed := req.PanelPort != db.Config.PanelPort
	if changed {
		ln, e := net.Listen("tcp", fmt.Sprintf(":%d", req.PanelPort))
		if e != nil {
			fail(w, 409, "TCP port is occupied")
			return
		}
		ln.Close()
	}
	hash := db.Config.PasswordHash
	if req.NewPassword != "" {
		hash, err = a.hashPassword(req.NewPassword)
		if err != nil {
			passwordError(w, err)
			return
		}
	}
	credentialsChanged := req.NewPassword != "" || req.Username != db.Config.AdminUser
	a.mu.Lock()
	err = a.store.Update(func(db *core.Database) error {
		db.Config.AdminUser = req.Username
		db.Config.PasswordHash = hash
		db.Config.PanelPort = req.PanelPort
		return nil
	})
	// A failure after atomic rename can mean the new credentials were already
	// committed but directory durability could not be confirmed. Revoke on any
	// credential-write attempt, so an uncertain save never leaves old sessions.
	if credentialsChanged {
		a.authGeneration++
		a.sessions = map[string]session{}
		a.loginAttempts = map[string]attempts{}
	}
	a.mu.Unlock()
	if err != nil {
		fail(w, 500, "save failed")
		return
	}
	jsonReply(w, 200, map[string]any{"ok": true, "restart": changed, "panelPort": req.PanelPort})
	if changed {
		go func() {
			time.Sleep(900 * time.Millisecond)
			if err := syscall.Exec(os.Args[0], os.Args, os.Environ()); err != nil {
				log.Printf("restart: %v", err)
				os.Exit(74)
			}
		}()
	}
}
func (a *app) services(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/services/"), "/")
	if len(parts) != 2 || !core.IsService(parts[0]) {
		fail(w, 404, "unknown service action")
		return
	}
	id, action := parts[0], parts[1]
	if r.Method == http.MethodGet {
		switch action {
		case "logs":
			jsonReply(w, 200, map[string]any{"logs": engine.Logs(id)})
			return
		case "ca":
			if id != core.IKEv2 {
				break
			}
			p := engine.PKIPaths(id)
			b, err := os.ReadFile(p.CA)
			if err != nil {
				fail(w, 404, "certificate not found")
				return
			}
			w.Header().Set("Content-Type", "application/x-x509-ca-cert")
			w.Header().Set("Content-Disposition", "attachment; filename=vpne-ikev2-ca.crt")
			_, _ = w.Write(b)
			return
		}
		fail(w, 404, "unknown download")
		return
	}
	if !method(w, r, http.MethodPost) {
		return
	}
	if action != "install" && action != "start" && action != "stop" && action != "restart" && action != "remove" && action != "ipv6" {
		fail(w, 404, "unknown action")
		return
	}
	var requested core.Service
	var ipv6Request struct {
		Enabled bool `json:"enabled"`
	}
	if action == "install" {
		if err := readJSON(r, &requested); err != nil {
			fail(w, 400, "invalid install configuration")
			return
		}
		requested.ID = id
		if requested.IPv6CIDR == "" {
			requested.IPv6CIDR = engine.Defaults(id).IPv6CIDR
		}
		// The server resolves the IPv6 egress interface; clients cannot select it.
		requested.IPv6Interface = ""
	} else if action == "ipv6" {
		if err := readJSON(r, &ipv6Request); err != nil {
			fail(w, 400, "invalid IPv6 settings")
			return
		}
	}
	if !a.opMu.TryLock() {
		fail(w, 409, "another operation is running")
		return
	}
	db, err := a.store.Read()
	if err != nil {
		a.opMu.Unlock()
		fail(w, 500, "read failed")
		return
	}
	current, installed := db.Services[id]
	if !installed || !current.Installed {
		installed = false
	}
	if action == "install" {
		if installed {
			a.opMu.Unlock()
			fail(w, 409, "service already installed")
			return
		}
		if err = engine.Preflight(requested, db.Services); err != nil {
			a.opMu.Unlock()
			fail(w, 400, err.Error())
			return
		}
	} else if !installed {
		a.opMu.Unlock()
		fail(w, 409, "service not installed")
		return
	}
	if action == "ipv6" {
		requested = current
		requested.IPv6 = ipv6Request.Enabled
		if requested.IPv6CIDR == "" {
			requested.IPv6CIDR = engine.Defaults(id).IPv6CIDR
		}
		if err := engine.Validate(requested, db.Services); err != nil {
			a.opMu.Unlock()
			fail(w, 400, err.Error())
			return
		}
	}
	taskID, err := core.RandomToken(18)
	if err != nil {
		a.opMu.Unlock()
		fail(w, 500, "cannot queue action")
		return
	}
	task := &Task{ID: taskID, Service: id, Action: action, Status: "running", Messages: []string{}, Started: time.Now()}
	if action == "install" {
		task.Progress = 5
		task.Stage = "Preparing installation"
	}
	a.mu.Lock()
	if len(a.jobs) > 60 {
		for k, x := range a.jobs {
			if x.Status != "running" {
				delete(a.jobs, k)
			}
		}
	}
	a.jobs[taskID] = task
	a.mu.Unlock()
	go func() {
		defer a.opMu.Unlock()
		ctx, cancel := context.WithTimeout(context.Background(), 12*time.Minute)
		defer cancel()
		logf := func(s string) {
			a.mu.Lock()
			if len(task.Messages) >= 400 {
				task.Messages = task.Messages[1:]
			}
			task.Messages = append(task.Messages, s)
			a.mu.Unlock()
		}
		progressf := func(percent int, stage string) {
			a.mu.Lock()
			if percent > task.Progress {
				task.Progress = percent
			}
			if stage != "" {
				task.Stage = stage
			}
			a.mu.Unlock()
		}
		var e error
		switch action {
		case "install":
			e = a.vpn().Install(ctx, requested, db.Services, logf, progressf)
			if e == nil {
				progressf(98, "Saving installation")
				requested.Installed = true
				requested.InstalledAt = time.Now()
				e = a.store.Update(func(d *core.Database) error { d.Services[id] = requested; return nil })
			}
		case "remove":
			e = a.vpn().Remove(ctx, id, logf)
			if e == nil {
				e = a.store.Update(func(d *core.Database) error {
					delete(d.Services, id)
					kept := d.Users[:0]
					for _, u := range d.Users {
						if u.Service != id {
							kept = append(kept, u)
						}
					}
					d.Users = kept
					return nil
				})
			}
		case "ipv6":
			_, e = a.vpn().ConfigureIPv6(ctx, current, ipv6Request.Enabled, db.Users, logf, func(updated core.Service) error {
				if saveErr := a.store.Update(func(d *core.Database) error { d.Services[id] = updated; return nil }); saveErr != nil {
					// The rename may have succeeded before a durability error.
					// Restore state while ConfigureIPv6 restores its captured runtime.
					return errors.Join(saveErr, a.store.Update(func(d *core.Database) error { d.Services[id] = current; return nil }))
				}
				return nil
			})
		default:
			e = a.vpn().Control(ctx, id, action, logf)
		}
		a.mu.Lock()
		if e != nil {
			task.Status = "error"
			task.Error = e.Error()
			if action == "install" {
				task.Stage = "Installation failed"
			}
		} else {
			task.Status = "done"
			if action == "install" {
				task.Progress = 100
				task.Stage = "Completed"
			}
		}
		a.mu.Unlock()
	}()
	jsonReply(w, 202, map[string]string{"taskId": taskID})
}
func taskSnapshot(t *Task) Task {
	snap := *t
	snap.Messages = append([]string(nil), t.Messages...)
	return snap
}
func (a *app) activeTask(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	a.mu.Lock()
	var current *Task
	for _, t := range a.jobs {
		if t.Status == "running" && (current == nil || t.Started.After(current.Started)) {
			current = t
		}
	}
	if current == nil {
		a.mu.Unlock()
		jsonReply(w, 200, map[string]any{"task": nil})
		return
	}
	snap := taskSnapshot(current)
	a.mu.Unlock()
	jsonReply(w, 200, map[string]any{"task": snap})
}
func (a *app) task(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodGet) {
		return
	}
	id := strings.TrimPrefix(r.URL.Path, "/api/tasks/")
	a.mu.Lock()
	t, ok := a.jobs[id]
	if !ok {
		a.mu.Unlock()
		fail(w, 404, "task not found")
		return
	}
	snap := taskSnapshot(t)
	a.mu.Unlock()
	jsonReply(w, 200, snap)
}
func (a *app) users(w http.ResponseWriter, r *http.Request) {
	if !method(w, r, http.MethodPost) {
		return
	}
	if !a.opMu.TryLock() {
		fail(w, 409, "another operation is running")
		return
	}
	defer a.opMu.Unlock()
	var req struct {
		Service  string `json:"service"`
		Name     string `json:"name"`
		Password string `json:"password"`
	}
	if err := readJSON(r, &req); err != nil {
		fail(w, 400, "invalid user request")
		return
	}
	if !core.IsService(req.Service) || !engine.ValidUsername(req.Name) {
		fail(w, 400, "invalid service or username")
		return
	}
	db, err := a.store.Read()
	if err != nil {
		fail(w, 500, "read failed")
		return
	}
	s, exists := db.Services[req.Service]
	if !exists || !s.Installed {
		fail(w, 409, "install the service first")
		return
	}
	for _, u := range db.Users {
		if u.Service == req.Service && u.Name == req.Name {
			fail(w, 409, "name already used in this service")
			return
		}
	}
	id, err := core.RandomToken(18)
	if err != nil {
		fail(w, 500, "could not generate user ID")
		return
	}
	u := core.User{ID: id, Service: req.Service, Name: req.Name, Enabled: true, CreatedAt: time.Now()}
	switch req.Service {
	case core.WireGuard:
		u, err = engine.NewWireGuardUser(req.Name, db.Users, s)
		u.ID = id
		u.CreatedAt = time.Now()
	case core.OpenVPN:
		u.PasswordHash, err = a.hashPassword(req.Password)
	case core.IKEv2:
		if !engine.ValidIKEPassword(req.Password) {
			fail(w, 400, "IKEv2 password must be 8-72 characters: letters, digits, @ . _ ! + - = # %")
			return
		}
		u.IKESecret = req.Password
	}
	if err != nil {
		passwordError(w, err)
		return
	}
	err = a.store.Update(func(db *core.Database) error { db.Users = append(db.Users, u); return nil })
	if err == nil {
		err = a.applyUsers(s)
	}
	if err != nil {
		rollbackErr := a.store.Update(func(d *core.Database) error { d.Users = withoutUser(d.Users, id); return nil })
		rollbackErr = errors.Join(rollbackErr, a.syncUsers(s, db.Users, true))
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		rollbackErr = errors.Join(rollbackErr, a.vpn().RevokeUser(ctx, s, u))
		cancel()
		fail(w, 500, "could not create VPN user: "+errors.Join(err, rollbackErr).Error())
		return
	}
	jsonReply(w, 201, map[string]any{"user": publicUser(u)})
}
func withoutUser(all []core.User, id string) []core.User {
	result := make([]core.User, 0, len(all))
	for _, u := range all {
		if u.ID != id {
			result = append(result, u)
		}
	}
	return result
}
func (a *app) applyUsers(s core.Service) error {
	return a.applyUsersPolicy(s, false)
}
func (a *app) applyUsersPolicy(s core.Service, revoking bool) error {
	db, err := a.store.Read()
	if err != nil {
		return err
	}
	return a.syncUsers(s, db.Users, revoking)
}
func (a *app) syncUsers(s core.Service, users []core.User, revoking bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
	defer cancel()
	switch s.ID {
	case core.WireGuard:
		if revoking {
			return a.vpn().SyncWireGuardRevoked(ctx, s, users)
		}
		return a.vpn().SyncWireGuard(ctx, s, users)
	case core.IKEv2:
		return a.vpn().SyncIKEv2(ctx, s, users)
	}
	return nil
}
func (a *app) userItem(w http.ResponseWriter, r *http.Request) {
	parts := strings.Split(strings.TrimPrefix(r.URL.Path, "/api/users/"), "/")
	if len(parts) < 1 || len(parts) > 2 {
		fail(w, 404, "not found")
		return
	}
	id := parts[0]
	action := ""
	if len(parts) == 2 {
		action = parts[1]
	}
	mutating := r.Method == http.MethodPost || r.Method == http.MethodDelete
	if mutating {
		if !a.opMu.TryLock() {
			fail(w, 409, "another operation is running")
			return
		}
		defer a.opMu.Unlock()
	}
	db, err := a.store.Read()
	if err != nil {
		fail(w, 500, "read failed")
		return
	}
	var user core.User
	found := false
	for _, u := range db.Users {
		if u.ID == id {
			user = u
			found = true
			break
		}
	}
	if !found {
		fail(w, 404, "user not found")
		return
	}
	svc, ok := db.Services[user.Service]
	if !ok || !svc.Installed {
		fail(w, 409, "service is not installed")
		return
	}
	if r.Method == http.MethodGet {
		switch action {
		case "profile":
			if user.Service == core.IKEv2 {
				jsonReply(w, 200, map[string]string{"type": "IKEv2/IPsec EAP-MSCHAPv2", "server": svc.Endpoint, "remoteId": svc.Endpoint, "username": user.Name, "hint": "Install the VPN Engine CA certificate, then add an IKEv2/IPsec MSCHAPv2 profile in your device VPN settings."})
				return
			}
			filename := "vpn-engine.ovpn"
			var data string
			if user.Service == core.WireGuard {
				filename = user.Name + ".conf"
				data, err = engine.WGProfile(svc, user)
			} else {
				filename = user.Name + ".ovpn"
				data, err = engine.OpenVPNProfile(svc)
			}
			if err != nil {
				fail(w, 500, "profile unavailable: "+err.Error())
				return
			}
			w.Header().Set("Content-Type", "application/octet-stream")
			w.Header().Set("Content-Disposition", fmt.Sprintf("attachment; filename=%q", filename))
			_, _ = io.WriteString(w, data)
			return
		case "qr":
			if user.Service != core.WireGuard {
				fail(w, 400, "QR only supported for WireGuard")
				return
			}
			data, e := engine.WGProfile(svc, user)
			if e != nil {
				fail(w, 500, e.Error())
				return
			}
			cmd := exec.Command("qrencode", "-t", "PNG", "-o", "-")
			cmd.Stdin = strings.NewReader(data)
			b, e := cmd.Output()
			if e != nil {
				fail(w, 500, "could not generate QR code")
				return
			}
			w.Header().Set("Content-Type", "image/png")
			_, _ = w.Write(b)
			return
		}
		fail(w, 404, "unknown download")
		return
	}
	if r.Method != http.MethodDelete && r.Method != http.MethodPost {
		fail(w, 405, "method not allowed")
		return
	}
	if r.Method == http.MethodDelete && action != "" {
		fail(w, 404, "unknown action")
		return
	}
	previous := user
	switch {
	case r.Method == http.MethodDelete:
		err = a.store.Update(func(db *core.Database) error { db.Users = withoutUser(db.Users, id); return nil })
	case action == "toggle":
		err = a.store.Update(func(db *core.Database) error {
			for i := range db.Users {
				if db.Users[i].ID == id {
					db.Users[i].Enabled = !db.Users[i].Enabled
				}
			}
			return nil
		})
	case action == "password":
		if user.Service == core.WireGuard {
			fail(w, 400, "WireGuard uses keys rather than a password")
			return
		}
		var req struct {
			Password string `json:"password"`
		}
		if e := readJSON(r, &req); e != nil {
			fail(w, 400, "invalid password request")
			return
		}
		hash := ""
		if user.Service == core.OpenVPN {
			hash, err = a.hashPassword(req.Password)
			if err != nil {
				passwordError(w, err)
				return
			}
		} else if !engine.ValidIKEPassword(req.Password) {
			fail(w, 400, "invalid IKEv2 password characters or length")
			return
		}
		err = a.store.Update(func(db *core.Database) error {
			for i := range db.Users {
				if db.Users[i].ID == id {
					if user.Service == core.OpenVPN {
						db.Users[i].PasswordHash = hash
					} else {
						db.Users[i].IKESecret = req.Password
					}
				}
			}
			return nil
		})
	default:
		fail(w, 404, "unknown action")
		return
	}
	revoking := r.Method == http.MethodDelete || action == "password" || (action == "toggle" && previous.Enabled)
	saveErr := err
	if err == nil || revoking {
		err = errors.Join(err, a.applyUsersPolicy(svc, revoking))
	}
	if revoking {
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		revokeErr := a.vpn().RevokeUser(ctx, svc, previous)
		cancel()
		if err = errors.Join(err, revokeErr); err != nil {
			message := "access changes were saved, but active disconnection could not be verified: "
			if saveErr != nil {
				message = "could not confirm saved access changes or active disconnection: "
			}
			fail(w, 500, message+err.Error())
			return
		}
	} else if err != nil {
		rollbackErr := a.store.Update(func(db *core.Database) error {
			found := false
			for i := range db.Users {
				if db.Users[i].ID == id {
					db.Users[i] = previous
					found = true
				}
			}
			if !found {
				db.Users = append(db.Users, previous)
			}
			return nil
		})
		recoveryErr := a.syncUsers(svc, db.Users, true)
		ctx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
		revokeErr := a.vpn().RevokeUser(ctx, svc, previous)
		cancel()
		message := "change reverted: "
		if rollbackErr != nil {
			message = "could not confirm the reverted change: "
		}
		fail(w, 500, message+errors.Join(err, rollbackErr, recoveryErr, revokeErr).Error())
		return
	}
	jsonReply(w, 200, map[string]bool{"ok": true})
}
