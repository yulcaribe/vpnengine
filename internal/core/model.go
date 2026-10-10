package core

import "time"

const (
	WireGuard = "wireguard"
	OpenVPN   = "openvpn"
	IKEv2     = "ikev2"
)

type Config struct {
	SetupComplete bool   `json:"setupComplete"`
	AdminUser     string `json:"adminUser"`
	PasswordHash  string `json:"passwordHash"`
	PanelPort     int    `json:"panelPort"`
}

type Service struct {
	ID            string    `json:"id"`
	Port          int       `json:"port"`
	CIDR          string    `json:"cidr"`
	Interface     string    `json:"interface"`
	Endpoint      string    `json:"endpoint"`
	DNS           string    `json:"dns"`
	IPv6          bool      `json:"ipv6"`
	IPv6CIDR      string    `json:"ipv6Cidr,omitempty"`
	IPv6Interface string    `json:"ipv6Interface,omitempty"`
	Installed     bool      `json:"installed"`
	InstalledAt   time.Time `json:"installedAt,omitempty"`
}

type User struct {
	ID           string    `json:"id"`
	Service      string    `json:"service"`
	Name         string    `json:"name"`
	Enabled      bool      `json:"enabled"`
	PasswordHash string    `json:"passwordHash,omitempty"`
	IKESecret    string    `json:"ikeSecret,omitempty"`
	PrivateKey   string    `json:"privateKey,omitempty"`
	PublicKey    string    `json:"publicKey,omitempty"`
	Address      string    `json:"address,omitempty"`
	IPv6Address  string    `json:"ipv6Address,omitempty"`
	CreatedAt    time.Time `json:"createdAt"`
}

type Database struct {
	Config   Config             `json:"config"`
	Services map[string]Service `json:"services"`
	Users    []User             `json:"users"`
}

func NewDB() Database { return Database{Services: map[string]Service{}, Users: []User{}} }

func (db *Database) Normalize() {
	if db.Services == nil {
		db.Services = map[string]Service{}
	}
	if db.Users == nil {
		db.Users = []User{}
	}
}

func IsService(s string) bool { return s == WireGuard || s == OpenVPN || s == IKEv2 }
