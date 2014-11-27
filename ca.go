package acme

import (
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"time"
)

var (
	serialNumberBits        = uint(64)
	oneYear                 = 365 * 24 * time.Hour
	rootCertificateTemplate = x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		Subject:            pkix.Name{Organization: []string{"ACME CA"}},
		IsCA:               true,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature |
			x509.KeyUsageCertSign,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
	eeCertificateTemplate = x509.Certificate{
		SignatureAlgorithm: x509.SHA256WithRSA,
		IsCA:               false,
		KeyUsage: x509.KeyUsageKeyEncipherment |
			x509.KeyUsageDigitalSignature,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
	}
)

func newSerialNumber() *big.Int {
	serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), serialNumberBits)
	serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
	if err != nil {
		// XXX do something?
	}
	return serialNumber
}

func newRoot() (interface{}, x509.Certificate, []byte) {
	// Generate a key pair
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil { /* XXX do something? */
	}

	// Sign the certificate
	template := rootCertificateTemplate
	template.SerialNumber = newSerialNumber()
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(oneYear)
	der, err := x509.CreateCertificate(rand.Reader, &template, &template, &priv.PublicKey, priv)
	if err != nil {
		// XXX do something
	}

	// Parse the certificate
	certs, err := x509.ParseCertificates(der)
	if err != nil || len(certs) == 0 {
		// XXX do something
	}

	return priv, *certs[0], der
}

func newEECertificate(publicKey interface{}, domains []string, caCert x509.Certificate, caKey interface{}) ([]byte, error) {
	template := eeCertificateTemplate

	// Set serial
	template.SerialNumber = newSerialNumber()

	// Set validity
	template.NotBefore = time.Now()
	template.NotAfter = template.NotBefore.Add(oneYear)

	// Set hostnames
	template.Subject = pkix.Name{CommonName: domains[0]}
	template.DNSNames = domains

	// Sign
	return x509.CreateCertificate(rand.Reader, &template, &caCert, publicKey, caKey)
}
