package engine

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type CertPaths struct{ CA, Server, Key string }

func PKIPaths(id string) CertPaths {
	dir := filepath.Join(DataDir, "pki", id)
	return CertPaths{CA: filepath.Join(dir, "ca.crt"), Server: filepath.Join(dir, "server.crt"), Key: filepath.Join(dir, "server.key")}
}
func serial() (*big.Int, error) { return rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128)) }
func pemKey(key *rsa.PrivateKey) []byte {
	return pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
}
func makePKI(id, host string) (CertPaths, error) {
	p := PKIPaths(id)
	if _, err := os.Stat(p.CA); err == nil {
		if _, err = os.Stat(p.Server); err == nil {
			if _, err = os.Stat(p.Key); err == nil {
				return p, nil
			}
		}
	}
	if err := mkdir700(filepath.Dir(p.CA)); err != nil {
		return p, err
	}
	caKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return p, err
	}
	serverKey, err := rsa.GenerateKey(rand.Reader, 3072)
	if err != nil {
		return p, err
	}
	caSerial, err := serial()
	if err != nil {
		return p, err
	}
	serverSerial, err := serial()
	if err != nil {
		return p, err
	}
	now := time.Now()
	caT := x509.Certificate{SerialNumber: caSerial, Subject: pkix.Name{CommonName: "VPN Engine CA - " + id}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(10, 0, 0), IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign}
	caDER, err := x509.CreateCertificate(rand.Reader, &caT, &caT, &caKey.PublicKey, caKey)
	if err != nil {
		return p, err
	}
	serverT := x509.Certificate{SerialNumber: serverSerial, Subject: pkix.Name{CommonName: host}, NotBefore: now.Add(-time.Hour), NotAfter: now.AddDate(2, 0, 0), KeyUsage: x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment, ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}
	if ip := net.ParseIP(host); ip != nil {
		serverT.IPAddresses = []net.IP{ip}
	} else {
		serverT.DNSNames = []string{host}
	}
	certDER, err := x509.CreateCertificate(rand.Reader, &serverT, &caT, &serverKey.PublicKey, caKey)
	if err != nil {
		return p, err
	}
	caPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})
	srvPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certDER})
	if err := write0600(filepath.Join(filepath.Dir(p.CA), "ca.key"), pemKey(caKey)); err != nil {
		return p, err
	}
	if err := write0600(p.CA, caPEM); err != nil {
		return p, err
	}
	if err := write0600(p.Server, srvPEM); err != nil {
		return p, err
	}
	if err := write0600(p.Key, pemKey(serverKey)); err != nil {
		return p, err
	}
	return p, nil
}
func CopyPrivate(src, dst string) error {
	b, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return write0600(dst, b)
}
