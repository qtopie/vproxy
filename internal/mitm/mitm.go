package mitm

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"sync"
	"time"
)

const (
	caCertPath = "/tmp/vproxy-ca.crt"
	caKeyPath  = "/tmp/vproxy-ca.key"
)

var (
	caCert       tls.Certificate
	certCache    sync.Map
	initOnce     sync.Once
	initErr      error
)

// EnsureCA loads or dynamically generates the Root CA and writes the certificate to /tmp/vproxy-ca.crt.
func EnsureCA() error {
	initOnce.Do(func() {
		initErr = loadOrGenerateCA()
	})
	return initErr
}

// GetCACertPath returns the local path to the CA certificate.
func GetCACertPath() string {
	return caCertPath
}

func loadOrGenerateCA() error {
	// Attempt to load existing CA from /tmp if present
	if _, err := os.Stat(caCertPath); err == nil {
		if _, err := os.Stat(caKeyPath); err == nil {
			cert, err := tls.LoadX509KeyPair(caCertPath, caKeyPath)
			if err == nil {
				caCert = cert
				return nil
			}
		}
	}

	// Generate a new CA
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return fmt.Errorf("failed to generate CA private key: %v", err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return fmt.Errorf("failed to generate CA serial number: %v", err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			Organization: []string{"VProxy Tracing CA"},
			CommonName:   "VProxy Root CA for Deep Tracing",
		},
		NotBefore:             time.Now().Add(-24 * time.Hour),
		NotAfter:              time.Now().AddDate(10, 0, 0), // 10 years
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		return fmt.Errorf("failed to create CA certificate: %v", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return fmt.Errorf("failed to marshal CA private key: %v", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	// Save to /tmp
	if err := os.WriteFile(caCertPath, certPEM, 0644); err != nil {
		return fmt.Errorf("failed to write CA certificate to %s: %v", caCertPath, err)
	}
	if err := os.WriteFile(caKeyPath, keyPEM, 0600); err != nil {
		return fmt.Errorf("failed to write CA key to %s: %v", caKeyPath, err)
	}

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to parse generated CA key pair: %v", err)
	}

	caCert = cert
	return nil
}

// GetCertificateForHost dynamically signs a certificate for the target hostname using the Root CA.
func GetCertificateForHost(host string) (tls.Certificate, error) {
	// Strip port if present
	if h, _, err := net.SplitHostPort(host); err == nil {
		host = h
	}

	// Check cache
	if cached, ok := certCache.Load(host); ok {
		return cached.(tls.Certificate), nil
	}

	if err := EnsureCA(); err != nil {
		return tls.Certificate{}, err
	}

	// Generate dynamic leaf certificate
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate key for %s: %v", host, err)
	}

	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to generate serial number for %s: %v", host, err)
	}

	template := x509.Certificate{
		SerialNumber: serialNumber,
		Subject: pkix.Name{
			CommonName: host,
		},
		NotBefore:   time.Now().Add(-24 * time.Hour),
		NotAfter:    time.Now().AddDate(1, 0, 0), // 1 year
		KeyUsage:    x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:    []string{host},
	}

	caCertDecoded, err := x509.ParseCertificate(caCert.Certificate[0])
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to parse CA certificate: %v", err)
	}

	caKey, ok := caCert.PrivateKey.(*rsa.PrivateKey)
	if !ok {
		return tls.Certificate{}, fmt.Errorf("invalid CA private key type in memory")
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, &template, caCertDecoded, &priv.PublicKey, caKey)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to sign certificate for %s: %v", host, err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: derBytes})
	
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to marshal key for %s: %v", host, err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	cert, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		return tls.Certificate{}, fmt.Errorf("failed to create key pair for %s: %v", host, err)
	}

	// Cache it
	certCache.Store(host, cert)
	return cert, nil
}
