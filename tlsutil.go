// Copyright (C) 2024 Michael J. Fromberger. All Rights Reserved.

// Package tlsutil provides support for using TLS certificates.
package tlsutil

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	crand "crypto/rand"
	"crypto/sha1"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math/big"
	"time"
)

const (
	pemCertType    = "CERTIFICATE"
	pemPrivKeyType = "PRIVATE KEY"
)

// newPrivateKey creates a new cryptographically-random private ECDSA key using
// the P-256 curve.
func newPrivateKey() (*ecdsa.PrivateKey, error) {
	pk, err := ecdsa.GenerateKey(elliptic.P256(), crand.Reader)
	if err != nil {
		return nil, fmt.Errorf("generate private key: %w", err)
	}
	return pk, nil
}

// newSerialNumber returns a cryptographically-randomly-generated 128-bit
// serial number suitable for use in a TLS certificate.
func newSerialNumber() *big.Int {
	size := new(big.Int).Lsh(big.NewInt(1), 128)
	sn, err := crand.Int(crand.Reader, size)
	if err != nil {
		panic(fmt.Sprintf("generate serial number: %v", err))
	}
	return sn
}

// NewSigningCert creates a signing ("CA") certificate that is valid for the
// specified period. The contents of base are used as a template for the cert,
// allowing the caller to specify names and other constraints.
//
// The following overrides are applied:
//
//   - If the serial number is not specified, a random one is generated.
//   - If the "not before" time is not specified, [time.Now] is used.
//   - The IsCA flag is set on the resulting cert.
//   - The key is marked for cert signing, digital signatures, and key encipherment.
func NewSigningCert(base *x509.Certificate, validFor time.Duration) (Certificate, error) {
	if validFor <= 0 {
		return Certificate{}, fmt.Errorf("bad validity period: %v", validFor)
	}
	c := *base // shallow copy
	if c.SerialNumber == nil {
		c.SerialNumber = newSerialNumber()
	}
	if c.NotBefore.IsZero() {
		c.NotBefore = time.Now()
	}
	c.NotAfter = c.NotBefore.Add(validFor)
	c.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageCertSign | x509.KeyUsageKeyEncipherment
	c.IsCA = true
	c.MaxPathLenZero = true
	c.BasicConstraintsValid = true

	privKey, err := newPrivateKey()
	if err != nil {
		return Certificate{}, err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return Certificate{}, fmt.Errorf("encode private key: %w", err)
	}

	// Set the subject key ID.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return Certificate{}, fmt.Errorf("subject key ID: %w", err)
	}
	skid := sha1.Sum(pubKeyBytes)
	c.SubjectKeyId = skid[:]

	// N.B. For a signing certificate, the parent is the cert itself.
	certBytes, err := x509.CreateCertificate(crand.Reader, &c, &c, privKey.Public(), privKey)
	if err != nil {
		return Certificate{}, fmt.Errorf("create signing cert: %w", err)
	}
	return Certificate{
		certBytes:    certBytes,
		privKey:      privKey,
		privKeyBytes: privKeyBytes,
	}, nil
}

// A Certificate contains a certificate and its key pair.
type Certificate struct {
	certBytes    []byte
	privKey      *ecdsa.PrivateKey
	privKeyBytes []byte
}

// CertPEM returns the certificate encoded in PEM notation.
func (c Certificate) CertPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemCertType,
		Bytes: c.certBytes,
	})
}

// PrivKeyPEM returns the private key encoded in PEM notation.
func (c Certificate) PrivKeyPEM() []byte {
	return pem.EncodeToMemory(&pem.Block{
		Type:  pemPrivKeyType,
		Bytes: c.privKeyBytes,
	})
}

// TLSCert converts c into a [crypo/tls.Certificate].
func (c Certificate) TLSCertificate() (tls.Certificate, error) {
	return tls.X509KeyPair(c.CertPEM(), c.PrivKeyPEM())
}

// NewServerCert creates a new server certificate that is valid for the
// specified period and is signed by the given signing cert. The contents of
// base are used as a template for the cert, allowing the caller to specify
// names and other constraints.
//
// The following overrides are applied:
//
//   - If the serial number is not specified, a random one is generated.
//   - If the "not before" time is not specified, [time.Now] is used.
//   - The IsCA flag is cleared on the resulting cert.
//   - The key is marked for digital signatures and key encipherment.
//   - If ExtKeyUsage == nil, client and server auth are added.
func NewServerCert(base *x509.Certificate, validFor time.Duration, sc Certificate) (Certificate, error) {
	if validFor <= 0 {
		return Certificate{}, fmt.Errorf("bad validity period: %v", validFor)
	}
	signCert, err := x509.ParseCertificate(sc.certBytes)
	if err != nil {
		return Certificate{}, fmt.Errorf("bad signing certificate: %w", err)
	}

	c := *base // shallow copy
	if c.SerialNumber == nil {
		c.SerialNumber = newSerialNumber()
	}
	if c.NotBefore.IsZero() {
		c.NotBefore = time.Now()
	}
	c.NotAfter = c.NotBefore.Add(validFor)
	c.KeyUsage |= x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment
	if c.ExtKeyUsage == nil { // N.B. nil, not empty
		c.ExtKeyUsage = []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth, x509.ExtKeyUsageServerAuth}
	}
	c.IsCA = false
	c.MaxPathLen = 0
	c.MaxPathLenZero = false
	c.BasicConstraintsValid = true

	privKey, err := newPrivateKey()
	if err != nil {
		return Certificate{}, err
	}
	privKeyBytes, err := x509.MarshalPKCS8PrivateKey(privKey)
	if err != nil {
		return Certificate{}, fmt.Errorf("encode private key: %w", err)
	}

	// Set the subject key ID.
	pubKeyBytes, err := x509.MarshalPKIXPublicKey(privKey.Public())
	if err != nil {
		return Certificate{}, fmt.Errorf("subject key ID: %w", err)
	}
	skid := sha1.Sum(pubKeyBytes)
	c.SubjectKeyId = skid[:]

	// N.B. For a server certificate, the parent is the signing cert.
	certBytes, err := x509.CreateCertificate(crand.Reader, &c, signCert, privKey.Public(), sc.privKey)
	if err != nil {
		return Certificate{}, fmt.Errorf("create server cert: %w", err)
	}
	return Certificate{
		certBytes:    certBytes,
		privKey:      privKey,
		privKeyBytes: privKeyBytes,
	}, nil
}
