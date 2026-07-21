// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestLoadPEMCredentials(t *testing.T) {
	certificate, signer := testSigner(t)
	dir := t.TempDir()
	certificateFile := filepath.Join(dir, "certificate.pem")
	privateKeyFile := filepath.Join(dir, "private-key.pem")
	writeCredentialTestFile(t, certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	key, ok := signer.(*rsa.PrivateKey)
	if !ok {
		t.Fatalf("test signer type = %T, want RSA", signer)
	}
	writeCredentialTestFile(t, privateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: mustMarshalPKCS8(t, key)}))

	credentials, err := LoadPEMCredentials(certificateFile, privateKeyFile, nil)
	if err != nil {
		t.Fatalf("LoadPEMCredentials() error = %v", err)
	}
	if credentials.Certificate == nil || credentials.Certificate.SerialNumber.Cmp(certificate.SerialNumber) != 0 {
		t.Fatal("loaded certificate does not match input certificate")
	}
	if credentials.Signer == nil || len(credentials.CertificateChain) != 0 {
		t.Fatalf("loaded signer/chain = %T/%d, want signer/0", credentials.Signer, len(credentials.CertificateChain))
	}
}

func TestLoadPEMCredentialsRejectsMismatchedKey(t *testing.T) {
	certificate, _ := testSigner(t)
	_, otherSigner := testSigner(t)
	dir := t.TempDir()
	certificateFile := filepath.Join(dir, "certificate.pem")
	privateKeyFile := filepath.Join(dir, "private-key.pem")
	writeCredentialTestFile(t, certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	writeCredentialTestFile(t, privateKeyFile, pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(otherSigner.(*rsa.PrivateKey))}))

	_, err := LoadPEMCredentials(certificateFile, privateKeyFile, nil)
	if err == nil || !strings.Contains(err.Error(), "does not match") {
		t.Fatalf("LoadPEMCredentials() error = %v, want key mismatch", err)
	}
}

func TestLoadPEMCredentialsRejectsEncryptedAndTrailingPrivateKeys(t *testing.T) {
	certificate, signer := testSigner(t)
	dir := t.TempDir()
	certificateFile := filepath.Join(dir, "certificate.pem")
	privateKeyFile := filepath.Join(dir, "private-key.pem")
	writeCredentialTestFile(t, certificateFile, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw}))
	key := signer.(*rsa.PrivateKey)
	encrypted, err := x509.EncryptPEMBlock(rand.Reader, "RSA PRIVATE KEY", x509.MarshalPKCS1PrivateKey(key), []byte("test-only"), x509.PEMCipherAES256) //nolint:staticcheck // Compatibility fixture for rejecting encrypted legacy PEM.
	if err != nil {
		t.Fatal(err)
	}
	writeCredentialTestFile(t, privateKeyFile, pem.EncodeToMemory(encrypted))
	if _, err := LoadPEMCredentials(certificateFile, privateKeyFile, nil); err == nil || !strings.Contains(err.Error(), "encrypted PEM") {
		t.Fatalf("encrypted key error = %v", err)
	}

	encoded := pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(key)})
	encoded = append(encoded, encoded...)
	writeCredentialTestFile(t, privateKeyFile, encoded)
	if _, err := LoadPEMCredentials(certificateFile, privateKeyFile, nil); err == nil || !strings.Contains(err.Error(), "exactly one") {
		t.Fatalf("trailing key error = %v", err)
	}
}

func TestLoadPEMCredentialsRejectsNonRegularAndOversizedFiles(t *testing.T) {
	dir := t.TempDir()
	if _, err := LoadPEMCredentials(dir, "unused", nil); err == nil || !strings.Contains(err.Error(), "not a regular file") {
		t.Fatalf("directory credential error = %v", err)
	}

	oversized := filepath.Join(dir, "oversized.pem")
	writeCredentialTestFile(t, oversized, bytes.Repeat([]byte{'x'}, int(maxPEMCredentialBytes)+1))
	if _, err := LoadPEMCredentials(oversized, "unused", nil); err == nil || !strings.Contains(err.Error(), "exceeds") {
		t.Fatalf("oversized credential error = %v", err)
	}
}

func mustMarshalPKCS8(t *testing.T, key any) []byte {
	t.Helper()
	data, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func writeCredentialTestFile(t *testing.T, name string, data []byte) {
	t.Helper()
	if err := os.WriteFile(name, data, 0o600); err != nil {
		t.Fatal(err)
	}
}
