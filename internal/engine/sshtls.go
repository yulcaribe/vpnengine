package engine

import (
 "context"
 "crypto/rand"
 "crypto/rsa"
 "crypto/x509"
 "crypto/x509/pkix"
 "encoding/pem"
 "errors"
 "fmt"
 "math/big"
 "net"
 "os"
 "os/exec"
 "path/filepath"
 "strconv"
 "strings"
 "time"

 "github.com/yulcaribe/vpnengine/internal/core"
)

const (
 sshTLSDir = DataDir + "/sshtls"
 sshTLSConf = sshTLSDir + "/stunnel.conf"
 sshTLSGroup = "vpe-sshtls"
 sshTLSDeny = "/etc/ssh/sshd_config.d/00-vpn-engine-sshtls.conf"
 sshTLSUnit = "/etc/systemd/system/vpn-engine-sshtls.service"
 sshTLSSSHUnit = "/etc/systemd/system/vpn-engine-sshtls-sshd.service"
 sshTLSRenewService = "/etc/systemd/system/vpn-engine-sshtls-renew.service"
 sshTLSRenewTimer = "/etc/systemd/system/vpn-engine-sshtls-renew.timer"
 sshTLSLocalPort = 2222
)

func SSHTLSLogin(name string) (string, error) {
 if !ValidUsername(name) || len(name)>27 { return "", errors.New("SSH-TLS username must be 1-27 valid characters") }
 return name, nil
}
func ValidSSHTLSPassword(pass string) bool {
 return len(pass)>=8 && len(pass)<=256 && !strings.ContainsAny(pass, ":\r\n\x00")
}
func sshTLSCommand(ctx context.Context, program string, args ...string) error {
 out, err:=exec.CommandContext(ctx,program,args...).CombinedOutput()
 if err!=nil { return fmt.Errorf("%s: %w: %s",program,err,strings.TrimSpace(string(out))) }
 return nil
}
func sshTLSExists(ctx context.Context, name string) bool {
 return exec.CommandContext(ctx,"id","-u",name).Run()==nil
}
const sshTLSMarkerPrefix = "VPN Engine SSH-TLS "

func sshTLSMarker(user core.User) string { return sshTLSMarkerPrefix + user.ID }

func sshTLSPasswd(ctx context.Context, name string) ([]string,error) {
 out,err:=exec.CommandContext(ctx,"getent","passwd",name).Output()
 if err!=nil{return nil,fmt.Errorf("read Linux account %q: %w",name,err)}
 fields:=strings.Split(strings.TrimSpace(string(out)),":")
 if len(fields)!=7 || fields[0]!=name {return nil,errors.New("unexpected Linux account entry")}
 return fields,nil
}

// A group name alone never proves ownership. Current accounts carry an
// ownership marker in GECOS; old vpe_ accounts are recognized only for migration.
func sshTLSGroupOwned(ctx context.Context, name string) error {
 out,err:=exec.CommandContext(ctx,"id","-gn",name).Output()
 if err!=nil{return err}
 if strings.TrimSpace(string(out))!=sshTLSGroup {return errors.New("refusing to modify an unrelated system account")}
 fields,err:=sshTLSPasswd(ctx,name)
 if err!=nil{return err}
 if fields[6]!="/usr/sbin/nologin" {return errors.New("SSH-TLS account has unexpected login shell")}
 if strings.HasPrefix(fields[4],sshTLSMarkerPrefix) {return nil}
 if strings.HasPrefix(name,"vpe_") && fields[4]=="" {return nil}
 return errors.New("Linux account has no VPN Engine SSH-TLS ownership marker")
}

// Resolve a panel user to a system account, allowing a legacy prefixed login
// until the one-time rename succeeds. An unrelated account is never adopted.
func sshTLSAccount(ctx context.Context,user core.User) (string,error) {
 name,err:=SSHTLSLogin(user.Name)
 if err!=nil{return "",err}
 if sshTLSExists(ctx,name) {
  if err=sshTLSGroupOwned(ctx,name);err==nil {
   fields,e:=sshTLSPasswd(ctx,name)
   if e==nil && fields[4]==sshTLSMarker(user) {return name,nil}
  }
 }
 old:="vpe_"+name
 if sshTLSExists(ctx,old) {
  if err=sshTLSGroupOwned(ctx,old);err!=nil{return "",err}
  fields,e:=sshTLSPasswd(ctx,old)
  if e!=nil{return "",e}
  if fields[4]!="" && fields[4]!=sshTLSMarker(user) {
   return "",errors.New("legacy SSH-TLS account ownership differs from panel user")
  }
  return old,nil
 }
 if sshTLSExists(ctx,name) {return "",errors.New("Linux username is already used by a different account")}
 return "",os.ErrNotExist
}

func CurrentSSHTLSLogin(user core.User) string {
 ctx,cancel:=context.WithTimeout(context.Background(),3*time.Second)
 defer cancel()
 login,err:=sshTLSAccount(ctx,user)
 if err==nil{return login}
 return user.Name
}

func sshTLSSetPassword(ctx context.Context, name, pass string) error {
 if !ValidSSHTLSPassword(pass){return errors.New("invalid SSH-TLS password")}
 c:=exec.CommandContext(ctx,"chpasswd")
 c.Stdin=strings.NewReader(name+":"+pass+"\n")
 if out,err:=c.CombinedOutput();err!=nil{return fmt.Errorf("chpasswd: %w: %s",err,strings.TrimSpace(string(out)))}
 return nil
}
func CreateSSHTLSUser(ctx context.Context, user core.User, pass string) error {
 name,err:=SSHTLSLogin(user.Name)
 if err!=nil{return err}
 if !ValidSSHTLSPassword(pass){return errors.New("SSH-TLS password must be 8-256 bytes without colon or newlines")}
 if sshTLSExists(ctx,name){return errors.New("SSH-TLS system username already exists")}
 if err=sshTLSCommand(ctx,"useradd","--system","--no-create-home","--gid",sshTLSGroup,"--shell","/usr/sbin/nologin","--comment",sshTLSMarker(user),name);err!=nil{return err}
 if err=sshTLSSetPassword(ctx,name,pass);err!=nil{
  _=sshTLSCommand(ctx,"userdel",name)
  return err
 }
 return nil
}
func sshTLSKill(ctx context.Context,name string) {
 _=exec.CommandContext(ctx,"pkill","-KILL","-u",name).Run()
}
func sshTLSRemoveUser(ctx context.Context,name string) error {
 if !sshTLSExists(ctx,name){return nil}
 if err:=sshTLSGroupOwned(ctx,name);err!=nil{return err}
 if err:=sshTLSCommand(ctx,"usermod","-L",name);err!=nil{return err}
 sshTLSKill(ctx,name)
 return sshTLSCommand(ctx,"userdel",name)
}
func SetSSHTLSPassword(ctx context.Context,user core.User,password string) error {
 name,err:=sshTLSAccount(ctx,user)
 if err!=nil{return err}
 if err=sshTLSSetPassword(ctx,name,password);err!=nil{return err}
 sshTLSKill(ctx,name)
 return nil
}
func sshTLSEnable(ctx context.Context,name string, enabled bool) error {
 if err:=sshTLSGroupOwned(ctx,name);err!=nil{return err}
 out,err:=exec.CommandContext(ctx,"passwd","-S",name).Output()
 if err!=nil{return err}
 fields:=strings.Fields(string(out))
 if len(fields)<2{return errors.New("unexpected Linux account status")}
 locked:=fields[1]=="L" || fields[1]=="LK"
 if enabled && locked{return sshTLSCommand(ctx,"usermod","-U",name)}
 if !enabled && !locked {
  if err:=sshTLSCommand(ctx,"usermod","-L",name);err!=nil{return err}
  sshTLSKill(ctx,name)
 }
 return nil
}
func SyncSSHTLSUsers(ctx context.Context,users []core.User) error {
 if !ServiceInstalled(core.SSHTLS){return errors.New("SSH-TLS is not installed")}
 var problems []error
 for _,u:=range users {
  if u.Service!=core.SSHTLS {continue}
  name,err:=sshTLSAccount(ctx,u)
  if err!=nil {
   problems=append(problems,fmt.Errorf("SSH-TLS user %s: %w",u.Name,err))
   continue
  }
  if name!=u.Name {
   // A collision never authorizes replacing an existing Linux account.
   // Apply Enable/Disable even if the one-time rename cannot be completed.
   if sshTLSExists(ctx,u.Name) {
    problems=append(problems,fmt.Errorf("cannot migrate SSH-TLS user %q: Linux name is already occupied; legacy login remains valid",u.Name))
   } else {
    sshTLSKill(ctx,name)
    if err=sshTLSCommand(ctx,"usermod","--comment",sshTLSMarker(u),name);err==nil {
     err=sshTLSCommand(ctx,"usermod","--login",u.Name,name)
    }
    if err!=nil {
     problems=append(problems,fmt.Errorf("SSH-TLS rename %q: %w; legacy login retained",u.Name,err))
    } else {
     name=u.Name
    }
   }
  }
  if err=sshTLSEnable(ctx,name,u.Enabled);err!=nil {
   problems=append(problems,fmt.Errorf("SSH-TLS access state %q: %w",u.Name,err))
  }
 }
 return errors.Join(problems...)
}
func RevokeSSHTLSUser(ctx context.Context,u core.User) error {
 name,err:=sshTLSAccount(ctx,u)
 if errors.Is(err,os.ErrNotExist){return nil}
 if err!=nil{return err}
 db,err:=core.NewStore(DataDir).Read()
 if err!=nil{return err}
 for _,current:=range db.Users {
  if current.ID==u.ID && current.Service==core.SSHTLS {
   if err=sshTLSEnable(ctx,name,current.Enabled);err!=nil{return err}
   sshTLSKill(ctx,name)
   return nil
  }
 }
 return sshTLSRemoveUser(ctx,name)
}
func checkSSHTLSTCP(port int) error {
 l,err:=net.Listen("tcp4",fmt.Sprintf("0.0.0.0:%d",port))
 if err!=nil{return fmt.Errorf("TCP %d is occupied: %w",port,err)}
 return l.Close()
}
func PreflightSSHTLS(s core.Service) error {
 if s.Port<1024 || s.Port>65535{return errors.New("SSH-TLS TCP port must be between 1024 and 65535")}
 if s.Port==sshTLSLocalPort || s.Port==51821 || s.Port==443 || s.Port==22 || s.Port==80 {return errors.New("SSH-TLS port conflicts with panel or system services")}
 if s.Endpoint=="" {return errors.New("SSH-TLS endpoint is required")}
 if net.ParseIP(s.Endpoint)==nil && !domainPattern.MatchString(s.Endpoint){return errors.New("invalid SSH-TLS endpoint")}
 if err:=checkSSHTLSTCP(s.Port);err!=nil{return err}
 if err:=checkSSHTLSTCP(sshTLSLocalPort);err!=nil{return err}
 for _,p:=range []string{sshTLSDir,sshTLSDeny,sshTLSUnit,sshTLSSSHUnit,sshTLSRenewService,sshTLSRenewTimer}{
  if _,err:=os.Lstat(p);err==nil{return fmt.Errorf("existing path %s: refusing to overwrite",p)}else if !os.IsNotExist(err){return err}
 }
 if err:=sshTLSRequireAdminInclude();err!=nil && !os.IsNotExist(err){return err}
 if err:=sshTLSCheckExistingDenyRules();err!=nil{return err}
 return nil
}
func sshTLSRequireAdminInclude() error {
 b,err:=os.ReadFile("/etc/ssh/sshd_config")
 if err!=nil{return err}
 for _,line:=range strings.Split(string(b),"\n"){
  fields:=strings.Fields(strings.SplitN(line,"#",2)[0])
  if len(fields)>=2 && strings.EqualFold(fields[0],"Include"){
   for _,p:=range fields[1:] {
    if p=="/etc/ssh/sshd_config.d/*.conf" {return nil}
   }
  }
 }
 return errors.New("administrator sshd must include /etc/ssh/sshd_config.d/*.conf to isolate tunnel users")
}
func sshTLSCheckExistingDenyRules() error {
 paths:=[]string{"/etc/ssh/sshd_config"}
 extras,err:=filepath.Glob("/etc/ssh/sshd_config.d/*.conf")
 if err!=nil{return err}
 paths=append(paths,extras...)
 for _,path:=range paths {
  b,err:=os.ReadFile(path)
  if os.IsNotExist(err){continue}
  if err!=nil{return err}
  for _,line:=range strings.Split(string(b),"\n"){
   fields:=strings.Fields(strings.SplitN(line,"#",2)[0])
   if len(fields)>0&&strings.EqualFold(fields[0],"DenyGroups"){
    return fmt.Errorf("existing SSH DenyGroups policy in %s; refusing to replace it",path)
   }
  }
 }
 return nil
}
func sshTLSVerifyAdminDeny(ctx context.Context) error {
 out,err:=exec.CommandContext(ctx,"/usr/sbin/sshd","-T","-C","user=vpe_probe,host=localhost,addr=127.0.0.1,laddr=127.0.0.1,lport=22").Output()
 if err!=nil{return fmt.Errorf("cannot verify administrator SSH account isolation: %w",err)}
 for _,line:=range strings.Split(string(out),"\n"){
  f:=strings.Fields(line)
  if len(f)>1 && f[0]=="denygroups" {
   for _,group:=range f[1:] {if group==sshTLSGroup{return nil}}
  }
 }
 return errors.New("administrator SSH does not reject tunnel-only accounts")
}
func sshTLSWriteCert(host string) error {
 priv,err:=rsa.GenerateKey(rand.Reader,3072)
 if err!=nil{return err}
 serial,err:=rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),128))
 if err!=nil{return err}
 now:=time.Now()
 cert:=&x509.Certificate{SerialNumber:serial,Subject:pkix.Name{CommonName:host},NotBefore:now.Add(-time.Hour),NotAfter:now.AddDate(3,0,0),KeyUsage:x509.KeyUsageDigitalSignature,ExtKeyUsage:[]x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},BasicConstraintsValid:true}
 if ip:=net.ParseIP(host);ip!=nil{cert.IPAddresses=[]net.IP{ip}}else{cert.DNSNames=[]string{host}}
 der,err:=x509.CreateCertificate(rand.Reader,cert,cert,&priv.PublicKey,priv)
 if err!=nil{return err}
 if err=write0600(sshTLSDir+"/server.key",pem.EncodeToMemory(&pem.Block{Type:"RSA PRIVATE KEY",Bytes:x509.MarshalPKCS1PrivateKey(priv)}));err!=nil{return err}
 return write0600(sshTLSDir+"/server.crt",pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}))
}
func sshTLSFiles(port int) map[string]string {
 return map[string]string{
  sshTLSConf:fmt.Sprintf("# Managed by VPN Engine\nforeground = yes\nclient = no\nsslVersionMin = TLSv1.2\ncert = /run/credentials/vpn-engine-sshtls.service/server.crt\nkey = /run/credentials/vpn-engine-sshtls.service/server.key\n\n[ssh_tls]\naccept = 0.0.0.0:%d\nconnect = 127.0.0.1:%d\n",port,sshTLSLocalPort),
  sshTLSDir+"/sshd_config":fmt.Sprintf("# Managed by VPN Engine\nPort %d\nListenAddress 127.0.0.1\nPidFile /run/vpn-engine-sshtls/sshd.pid\nHostKey /etc/ssh/ssh_host_ed25519_key\nUsePAM yes\nPasswordAuthentication yes\nKbdInteractiveAuthentication no\nPubkeyAuthentication no\nPermitRootLogin no\nAllowGroups %s\nMaxSessions 0\nAllowTcpForwarding local\nAllowStreamLocalForwarding no\nAllowAgentForwarding no\nX11Forwarding no\nPermitTTY no\nPermitTunnel no\nGatewayPorts no\nPermitUserEnvironment no\nPermitEmptyPasswords no\nSubsystem sftp /bin/false\n",sshTLSLocalPort,sshTLSGroup),
  sshTLSDeny:"# Managed by VPN Engine\nDenyGroups "+sshTLSGroup+"\n",
  sshTLSSSHUnit:"# Managed by VPN Engine\n[Unit]\nDescription=VPN Engine isolated SSH tunnel daemon\nAfter=network.target\n[Service]\nType=simple\nRuntimeDirectory=vpn-engine-sshtls\nExecStartPre=/usr/sbin/sshd -t -f "+sshTLSDir+"/sshd_config\nExecStart=/usr/sbin/sshd -D -e -f "+sshTLSDir+"/sshd_config\nRestart=on-failure\nPrivateTmp=yes\n[Install]\nWantedBy=multi-user.target\n",
  sshTLSUnit:"# Managed by VPN Engine\n[Unit]\nDescription=VPN Engine SSH over TLS\nRequires=vpn-engine-sshtls-sshd.service\nAfter=network-online.target vpn-engine-sshtls-sshd.service\n[Service]\nType=simple\nUser=stunnel4\nGroup=stunnel4\nLoadCredential=server.crt:"+sshTLSDir+"/server.crt\nLoadCredential=server.key:"+sshTLSDir+"/server.key\nLoadCredential=stunnel.conf:"+sshTLSConf+"\nExecStart=/usr/bin/stunnel4 /run/credentials/vpn-engine-sshtls.service/stunnel.conf\nRestart=on-failure\nNoNewPrivileges=yes\nProtectSystem=strict\nProtectHome=yes\nPrivateTmp=yes\n[Install]\nWantedBy=multi-user.target\n",
  sshTLSRenewService:"# Managed by VPN Engine\n[Unit]\nDescription=Renew VPN Engine SSH-TLS certificate if needed\n[Service]\nType=oneshot\nExecStart=/usr/local/bin/vpn-engine sshtls-renew\n",
  sshTLSRenewTimer:"# Managed by VPN Engine\n[Unit]\nDescription=Daily SSH-TLS certificate check\n[Timer]\nOnCalendar=daily\nPersistent=true\nRandomizedDelaySec=1h\nUnit=vpn-engine-sshtls-renew.service\n[Install]\nWantedBy=timers.target\n",
 }
}
func InstallSSHTLS(ctx context.Context,s core.Service,log Log,progress Progress) (err error) {
 if err=PreflightSSHTLS(s);err!=nil{return err}
 reportProgress(progress,15,"Installing OpenSSH and stunnel4")
 if err=LogCmd(ctx,log,"apt-get","-o","DPkg::Lock::Timeout=180","install","-y","--no-upgrade","openssh-server","stunnel4","openssl","procps");err!=nil{return err}
 if err=sshTLSRequireAdminInclude();err!=nil{return err}
 if err=sshTLSCheckExistingDenyRules();err!=nil{return err}
 if err=sshTLSCommand(ctx,"groupadd","--system",sshTLSGroup);err!=nil{return err}
 createdGroup:=true
 defer func(){
  if err==nil{return}
  cleanupCtx,cancel:=context.WithTimeout(context.Background(),25*time.Second)
  defer cancel()
  _=RemoveSSHTLS(cleanupCtx,log)
  if createdGroup{_ = exec.CommandContext(cleanupCtx,"groupdel",sshTLSGroup).Run()}
 }()
 if err=os.Mkdir(sshTLSDir,0700);err!=nil{return err}
 if err=write0600(sshTLSDir+"/owned",[]byte("Managed by VPN Engine\n"));err!=nil{return err}
 if err=sshTLSWriteCert(s.Endpoint);err!=nil{return err}
 for path,content:=range sshTLSFiles(s.Port) {
  if err=write0600(path,[]byte(content));err!=nil{return err}
 }
 reportProgress(progress,60,"Checking SSH access restrictions")
 if err=sshTLSCommand(ctx,"/usr/sbin/sshd","-t","-f",sshTLSDir+"/sshd_config");err!=nil{return err}
 if err=sshTLSCommand(ctx,"/usr/sbin/sshd","-t");err!=nil{return err}
 if err=sshTLSVerifyAdminDeny(ctx);err!=nil{return err}
 if err=sshTLSCommand(ctx,"systemctl","reload","ssh.service");err!=nil{return err}
 if err=sshTLSCommand(ctx,"systemctl","daemon-reload");err!=nil{return err}
 reportProgress(progress,82,"Starting SSH-TLS services")
 for _,unit:=range []string{"vpn-engine-sshtls-sshd.service","vpn-engine-sshtls.service","vpn-engine-sshtls-renew.timer"} {
  if err=sshTLSCommand(ctx,"systemctl","enable","--now",unit);err!=nil{return err}
 }
 if err=sshTLSCommand(ctx,"systemctl","is-active","--quiet","vpn-engine-sshtls.service");err!=nil{return err}
 log("SSH-TLS ready: tunnel users cannot open SSH shell, commands or SFTP sessions")
 return nil
}
func ControlSSHTLS(ctx context.Context,action string) error {
 switch action {
 case "start":
  if err:=sshTLSCommand(ctx,"systemctl","start","vpn-engine-sshtls-sshd.service");err!=nil{return err}
  return sshTLSCommand(ctx,"systemctl","start","vpn-engine-sshtls.service")
 case "stop":
  if err:=sshTLSCommand(ctx,"systemctl","stop","vpn-engine-sshtls.service");err!=nil{return err}
  return sshTLSCommand(ctx,"systemctl","stop","vpn-engine-sshtls-sshd.service")
 case "restart":
  if err:=sshTLSCommand(ctx,"systemctl","restart","vpn-engine-sshtls-sshd.service");err!=nil{return err}
  return sshTLSCommand(ctx,"systemctl","restart","vpn-engine-sshtls.service")
 }
 return errors.New("unsupported SSH-TLS action")
}
func sshTLSAccounts(ctx context.Context) ([]string,error) {
 out,err:=exec.CommandContext(ctx,"getent","group",sshTLSGroup).Output()
 if err!=nil{return nil,nil}
 fields:=strings.Split(strings.TrimSpace(string(out)),":")
 if len(fields)<3{return nil,errors.New("malformed SSH-TLS group")}
 gid:=fields[2]
 if _,err=strconv.Atoi(gid);err!=nil{return nil,err}
 b,err:=os.ReadFile("/etc/passwd")
 if err!=nil{return nil,err}
 var result []string
 for _,line:=range strings.Split(string(b),"\n"){
  f:=strings.Split(line,":")
  if len(f)>=7 && f[3]==gid && f[6]=="/usr/sbin/nologin" && (strings.HasPrefix(f[4],sshTLSMarkerPrefix) || (strings.HasPrefix(f[0],"vpe_") && f[4]=="")) {
   if err=sshTLSGroupOwned(ctx,f[0]);err!=nil{return nil,err}
   result=append(result,f[0])
  }
 }
 return result,nil
}
func RemoveSSHTLS(ctx context.Context,log Log) error {
 // A missing ownership marker must not authorize deleting unrelated SSH configurations.
 marker,err:=os.ReadFile(sshTLSDir+"/owned")
 if err!=nil || string(marker)!="Managed by VPN Engine\n" {return errors.New("refusing to remove unowned SSH-TLS service")}
 for _,unit:=range []string{"vpn-engine-sshtls-renew.timer","vpn-engine-sshtls.service","vpn-engine-sshtls-sshd.service"} {
  _=exec.CommandContext(ctx,"systemctl","disable","--now",unit).Run()
 }
 accounts,err:=sshTLSAccounts(ctx)
 if err!=nil{return err}
 for _,name:=range accounts {if err=sshTLSRemoveUser(ctx,name);err!=nil{return err}}
 for _,path:=range []string{sshTLSUnit,sshTLSSSHUnit,sshTLSRenewService,sshTLSRenewTimer,sshTLSDeny} {
  if b,e:=os.ReadFile(path);e==nil&&strings.HasPrefix(string(b),"# Managed by VPN Engine\n"){if err=os.Remove(path);err!=nil{return err}}
 }
 if err=sshTLSCommand(ctx,"/usr/sbin/sshd","-t");err!=nil{return err}
 if err=sshTLSCommand(ctx,"systemctl","reload","ssh.service");err!=nil{return err}
 if err=sshTLSCommand(ctx,"systemctl","daemon-reload");err!=nil{return err}
 if err=os.RemoveAll(sshTLSDir);err!=nil{return err}
 if err=sshTLSCommand(ctx,"groupdel",sshTLSGroup);err!=nil{return err}
 log("Removed VPN Engine SSH-TLS; administrator SSH and other VPN protocols unchanged")
 return nil
}
func RenewSSHTLSCert(ctx context.Context) error {
 b,err:=os.ReadFile(sshTLSDir+"/server.crt")
 if os.IsNotExist(err){return nil}
 if err!=nil{return err}
 block,_:=pem.Decode(b)
 if block==nil{return errors.New("invalid SSH-TLS certificate")}
 old,err:=x509.ParseCertificate(block.Bytes)
 if err!=nil{return err}
 if time.Until(old.NotAfter)>30*24*time.Hour{return nil}
 k,err:=os.ReadFile(sshTLSDir+"/server.key")
 if err!=nil{return err}
 keyBlock,_:=pem.Decode(k)
 if keyBlock==nil{return errors.New("invalid SSH-TLS private key")}
 priv,err:=x509.ParsePKCS1PrivateKey(keyBlock.Bytes)
 if err!=nil{return err}
 serial,err:=rand.Int(rand.Reader,new(big.Int).Lsh(big.NewInt(1),128))
 if err!=nil{return err}
 now:=time.Now()
 renewed:=&x509.Certificate{SerialNumber:serial,Subject:old.Subject,NotBefore:now.Add(-time.Hour),NotAfter:now.AddDate(3,0,0),KeyUsage:old.KeyUsage,ExtKeyUsage:old.ExtKeyUsage,BasicConstraintsValid:true,DNSNames:old.DNSNames,IPAddresses:old.IPAddresses}
 der,err:=x509.CreateCertificate(rand.Reader,renewed,renewed,&priv.PublicKey,priv)
 if err!=nil{return err}
 if err=write0600(filepath.Join(sshTLSDir,"server.crt"),pem.EncodeToMemory(&pem.Block{Type:"CERTIFICATE",Bytes:der}));err!=nil{return err}
 return sshTLSCommand(ctx,"systemctl","try-restart","vpn-engine-sshtls.service")
}
