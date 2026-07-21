// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"os"
	"strings"
)

const maxPEMCredentialBytes int64 = 1 << 20

// Credentials contains a PDF signer and its X.509 certificate chain.
// Signer may be replaced by an HSM, KMS, PKCS#11, or operating-system-backed
// crypto.Signer without exposing private-key bytes to Paper documents.
type Credentials struct {
	Signer           crypto.Signer
	Certificate      *x509.Certificate
	CertificateChain []*x509.Certificate
}

// LoadPEMCredentials loads one leaf certificate, optional intermediate
// certificates, and an unencrypted PKCS#8, PKCS#1, or SEC1 private key.
//
// Passwords and private-key bytes are intentionally not accepted as string
// arguments. Production servers should prefer injecting a managed
// crypto.Signer; PEM loading is intended for explicitly protected local or
// mounted secret files.
func LoadPEMCredentials(certificateFile, privateKeyFile string, chainFiles []string) (Credentials, error) {
	if strings.TrimSpace(certificateFile) == "" {
		return Credentials{}, errors.New("pdfsigning: certificate file is required")
	}
	if strings.TrimSpace(privateKeyFile) == "" {
		return Credentials{}, errors.New("pdfsigning: private key file is required")
	}

	certificates, err := loadCertificateFile(certificateFile)
	if err != nil {
		return Credentials{}, err
	}
	chain := append([]*x509.Certificate(nil), certificates[1:]...)
	for _, name := range chainFiles {
		loaded, loadErr := loadCertificateFile(name)
		if loadErr != nil {
			return Credentials{}, loadErr
		}
		chain = append(chain, loaded...)
	}

	signer, err := loadPrivateKeyFile(privateKeyFile)
	if err != nil {
		return Credentials{}, err
	}
	if err := signerMatchesCertificate(signer, certificates[0]); err != nil {
		return Credentials{}, err
	}
	return Credentials{Signer: signer, Certificate: certificates[0], CertificateChain: chain}, nil
}

func loadCertificateFile(name string) ([]*x509.Certificate, error) {
	data, err := readCredentialFile(name)
	if err != nil {
		return nil, fmt.Errorf("pdfsigning: read certificate file: %w", err)
	}
	var certificates []*x509.Certificate
	for len(bytes.TrimSpace(data)) != 0 {
		block, rest := pem.Decode(data)
		if block == nil || block.Type != "CERTIFICATE" {
			return nil, fmt.Errorf("pdfsigning: certificate file %q contains a non-certificate PEM block", name)
		}
		parsed, parseErr := x509.ParseCertificate(block.Bytes)
		if parseErr != nil {
			return nil, fmt.Errorf("pdfsigning: parse certificate file %q: %w", name, parseErr)
		}
		certificates = append(certificates, parsed)
		data = rest
	}
	if len(certificates) == 0 {
		return nil, fmt.Errorf("pdfsigning: certificate file %q contains no certificates", name)
	}
	return certificates, nil
}

func loadPrivateKeyFile(name string) (crypto.Signer, error) {
	data, err := readCredentialFile(name)
	if err != nil {
		return nil, fmt.Errorf("pdfsigning: read private key file: %w", err)
	}
	defer clear(data)
	block, rest := pem.Decode(data)
	if block == nil || len(bytes.TrimSpace(rest)) != 0 {
		return nil, fmt.Errorf("pdfsigning: private key file %q must contain exactly one PEM block", name)
	}
	if x509.IsEncryptedPEMBlock(block) {
		return nil, fmt.Errorf("pdfsigning: encrypted PEM private keys are not supported; use a managed crypto.Signer")
	}

	var key any
	switch block.Type {
	case "PRIVATE KEY":
		key, err = x509.ParsePKCS8PrivateKey(block.Bytes)
	case "RSA PRIVATE KEY":
		key, err = x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		key, err = x509.ParseECPrivateKey(block.Bytes)
	default:
		return nil, fmt.Errorf("pdfsigning: unsupported private key PEM type %q", block.Type)
	}
	if err != nil {
		return nil, fmt.Errorf("pdfsigning: parse private key file %q: %w", name, err)
	}
	signer, ok := key.(crypto.Signer)
	if !ok {
		return nil, fmt.Errorf("pdfsigning: private key file %q does not contain a signing key", name)
	}
	switch signer.(type) {
	case *rsa.PrivateKey, *ecdsa.PrivateKey:
		return signer, nil
	default:
		return nil, fmt.Errorf("pdfsigning: private key file %q uses an unsupported signing key type", name)
	}
}

func signerMatchesCertificate(signer crypto.Signer, certificate *x509.Certificate) error {
	signerPublic, err := x509.MarshalPKIXPublicKey(signer.Public())
	if err != nil {
		return fmt.Errorf("pdfsigning: marshal signer public key: %w", err)
	}
	certificatePublic, err := x509.MarshalPKIXPublicKey(certificate.PublicKey)
	if err != nil {
		return fmt.Errorf("pdfsigning: marshal certificate public key: %w", err)
	}
	if !bytes.Equal(signerPublic, certificatePublic) {
		return errors.New("pdfsigning: private key does not match certificate")
	}
	return nil
}

func readCredentialFile(name string) ([]byte, error) {
	file, err := os.Open(name)
	if err != nil {
		return nil, err
	}
	defer func() { _ = file.Close() }()
	info, err := file.Stat()
	if err != nil {
		return nil, err
	}
	if !info.Mode().IsRegular() {
		return nil, errors.New("credential path is not a regular file")
	}
	if info.Size() > maxPEMCredentialBytes {
		return nil, fmt.Errorf("credential file exceeds %d bytes", maxPEMCredentialBytes)
	}
	data, err := io.ReadAll(io.LimitReader(file, maxPEMCredentialBytes+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > maxPEMCredentialBytes {
		clear(data)
		return nil, fmt.Errorf("credential file exceeds %d bytes", maxPEMCredentialBytes)
	}
	return data, nil
}
