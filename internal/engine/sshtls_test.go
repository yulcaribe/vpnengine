package engine

import (
 "strings"
 "testing"

 "github.com/yulcaribe/vpnengine/internal/core"
)

func TestSSHTLSValidation(t *testing.T) {
 if !core.IsService(core.SSHTLS) { t.Fatal("SSH-TLS service type unavailable") }
 s := Defaults(core.SSHTLS)
 if s.Port != 8443 { t.Fatalf("default SSH-TLS port = %d", s.Port) }
 s.Endpoint = "198.51.100.10"
 if err := Validate(s, nil); err != nil { t.Fatalf("SSH-TLS should accept a TCP port: %v", err) }
 s.Port = 443
 if err := Validate(s, nil); err == nil { t.Fatal("panel HTTPS port must be reserved") }
 s.Port = 22
 if err := Validate(s, nil); err == nil { t.Fatal("administrator SSH port must be reserved") }
 s.Port = 8443
 s.Endpoint = "bad name"
 if err := Validate(s, nil); err == nil { t.Fatal("invalid server host accepted") }
}

func TestSSHTLSClientAccounts(t *testing.T) {
 for _, name := range []string{"alice","John_1","user-2"} {
  got, err := SSHTLSLogin(name)
  if err != nil || got != name { t.Fatalf("login %q: %q %v",name,got,err) }
 }
 for _, name := range []string{"", ".hidden", "bad name",strings.Repeat("z",28)} {
  if _, err := SSHTLSLogin(name); err == nil { t.Fatalf("accepted invalid user %q",name) }
 }
 for _, pass := range []string{"bad", "contains:colon","line\nbreaks"} {
  if ValidSSHTLSPassword(pass) { t.Fatalf("accepted invalid password %q",pass) }
 }
 if !ValidSSHTLSPassword("correct horse battery staple") { t.Fatal("safe password rejected") }
}

func TestSSHTLSServiceIsolation(t *testing.T) {
 files:=sshTLSFiles(8443)
 stunnel:=files[sshTLSConf]
 for _, required:=range []string{"accept = 0.0.0.0:8443","connect = 127.0.0.1:2222"} {
  if !strings.Contains(stunnel,required){t.Fatalf("missing tunnel setting %q",required)}
 }
 if strings.Contains(strings.ToLower(stunnel),"sni =") { t.Fatal("server must not force client SNI") }
 sshd:=files[sshTLSDir+"/sshd_config"]
 for _, required:=range []string{"ListenAddress 127.0.0.1","MaxSessions 0","AllowTcpForwarding local","PermitTTY no","AllowGroups "+sshTLSGroup,"Subsystem sftp /bin/false"} {
  if !strings.Contains(sshd,required){t.Fatalf("missing SSH restriction %q",required)}
 }
 if !strings.Contains(files[sshTLSDeny],"DenyGroups "+sshTLSGroup){t.Fatal("normal administrator SSH must deny tunnel users")}
 if !strings.Contains(files[sshTLSRenewTimer],"OnCalendar=daily"){t.Fatal("missing automatic renewal checks")}
}

func TestSSHTLSAccountIdentity(t *testing.T) {
 user := core.User{ID: "example-id", Service: core.SSHTLS, Name: "tlstest"}
 if got,err := SSHTLSLogin(user.Name); err != nil || got != "tlstest" {
  t.Fatalf("expected unchanged username, got %q: %v", got, err)
 }
 if got := sshTLSMarker(user); got != "VPN Engine SSH-TLS example-id" {
  t.Fatalf("unexpected account ownership marker: %q",got)
 }
 if strings.HasPrefix(sshTLSMarker(user), "vpe_") {
  t.Fatal("ownership must not depend on a username prefix")
 }
}
