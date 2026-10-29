// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign_test

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"math/big"
	"strings"
	"testing"
	"time"

	"github.com/cssbruno/pdfrune/sign"
)

var oidDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}

func bindingTestPDF() []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := []int{0}
	add := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets)-1, body)
	}
	add("<< /Type /Catalog /Pages 2 0 R >>")
	add("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	add("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] >>")
	x := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, o := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", o)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), x)
	return out.Bytes()
}

type ca struct {
	cert *x509.Certificate
	key  *ecdsa.PrivateKey
}

func newKey(t *testing.T) *ecdsa.PrivateKey {
	k, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func issue(t *testing.T, tmpl *x509.Certificate, parent *ca, pub crypto.PublicKey, selfKey *ecdsa.PrivateKey) *x509.Certificate {
	t.Helper()
	now := time.Now()
	tmpl.NotBefore = now.Add(-time.Hour)
	tmpl.NotAfter = now.Add(24 * time.Hour)
	parentCert, parentKey := tmpl, selfKey
	if parent != nil {
		parentCert, parentKey = parent.cert, parent.key
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, parentCert, pub, parentKey)
	if err != nil {
		t.Fatal(err)
	}
	c, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func newRoot(t *testing.T) *ca {
	k := newKey(t)
	c := issue(t, &x509.Certificate{
		SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "Test Root"},
		IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
	}, nil, &k.PublicKey, k)
	return &ca{cert: c, key: k}
}

func leafTemplate(serial int64, cn string) *x509.Certificate {
	return &x509.Certificate{
		SerialNumber: big.NewInt(serial), Subject: pkix.Name{CommonName: cn},
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageContentCommitment,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidDocumentSigning},
		BasicConstraintsValid: true,
	}
}

// --- minimal DER rewriting helpers (test only) ---

func children(t *testing.T, b []byte) []asn1.RawValue {
	t.Helper()
	var out []asn1.RawValue
	for len(b) > 0 {
		var v asn1.RawValue
		rest, err := asn1.Unmarshal(b, &v)
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, v)
		b = rest
	}
	return out
}

func enc(t *testing.T, class, tag int, content ...[]byte) []byte {
	t.Helper()
	b, err := asn1.Marshal(asn1.RawValue{Class: class, Tag: tag, IsCompound: true, Bytes: bytes.Join(content, nil)})
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// swapSignerCertificate replaces the CMS certificate set and the SignerInfo
// sid with cert, leaving signed attributes and signature bytes untouched.
func swapSignerCertificate(t *testing.T, cms []byte, cert *x509.Certificate, chain ...*x509.Certificate) []byte {
	t.Helper()
	var ci asn1.RawValue
	if _, err := asn1.Unmarshal(cms, &ci); err != nil {
		t.Fatal(err)
	}
	top := children(t, ci.Bytes)
	sd := children(t, top[1].Bytes)[0]
	sdc := children(t, sd.Bytes)
	sis := children(t, sdc[4].Bytes)
	si := children(t, sis[0].Bytes)
	sid, err := asn1.Marshal(struct {
		Issuer asn1.RawValue
		Serial *big.Int
	}{asn1.RawValue{FullBytes: cert.RawIssuer}, cert.SerialNumber})
	if err != nil {
		t.Fatal(err)
	}
	si[1] = asn1.RawValue{FullBytes: sid}
	var siParts [][]byte
	for _, c := range si {
		siParts = append(siParts, c.FullBytes)
	}
	newSI := enc(t, 0, 16, siParts...)
	certs := [][]byte{cert.Raw}
	for _, c := range chain {
		certs = append(certs, c.Raw)
	}
	newSD := enc(t, 0, 16, sdc[0].FullBytes, sdc[1].FullBytes, sdc[2].FullBytes, enc(t, 2, 0, certs...), enc(t, 0, 17, newSI))
	return enc(t, 0, 16, top[0].FullBytes, enc(t, 2, 0, newSD))
}

// The sid and certificate set are outside the signature. Swapping them for
// another trusted certificate over the same key made Verify report that
// certificate's holder as the signer although the signed ESS
// signing-certificate-v2 attribute names the original one.
func TestVerifyBindsTheSignerToTheESSSigningCertificate(t *testing.T) {
	root := newRoot(t)
	key := newKey(t)
	alice := issue(t, leafTemplate(100, "Alice"), root, &key.PublicKey, nil)
	other := issue(t, leafTemplate(200, "Other identity, same key"), root, &key.PublicKey, nil)
	pool := x509.NewCertPool()
	pool.AddCert(root.cert)
	signed, err := sign.Bytes(bindingTestPDF(), sign.Options{Signer: key, Certificate: alice, SubFilter: sign.SubFilterETSI_CAdESDetached})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sign.Verify(signed, pool); err != nil {
		t.Fatalf("Verify(original) error = %v", err)
	}
	extracted, err := sign.ExtractSignature(signed)
	if err != nil {
		t.Fatal(err)
	}
	swapped := swapSignerCertificate(t, extracted.CMS, other)
	tampered, err := sign.EmbedDetachedCMS(signed, swapped)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := sign.Verify(tampered, pool); err == nil || !strings.Contains(err.Error(), "ESS") {
		t.Fatalf("Verify(swapped signer) error = %v, want the ESS binding", err)
	}
	if _, err := sign.VerifyDetachedCMSIntegrity(swapped, extracted.SignedContent); err == nil {
		t.Fatal("VerifyDetachedCMSIntegrity accepted the swapped signer")
	}
}

// crypto/x509 is called with ExtKeyUsageAny, which skips its check that each
// CA's extended key usage allows the leaf's use; a CA limited to TLS server
// authentication could issue a trusted document signer.
func TestVerifyRejectsSignersUnderTLSOnlyCAs(t *testing.T) {
	for name, usage := range map[string][]x509.ExtKeyUsage{
		"TLS-only CA":         {x509.ExtKeyUsageServerAuth},
		"email-protection CA": {x509.ExtKeyUsageEmailProtection},
	} {
		t.Run(name, func(t *testing.T) {
			root := newRoot(t)
			intermediateKey := newKey(t)
			intermediate := issue(t, &x509.Certificate{
				SerialNumber: big.NewInt(2), Subject: pkix.Name{CommonName: name},
				IsCA: true, BasicConstraintsValid: true, KeyUsage: x509.KeyUsageCertSign,
				ExtKeyUsage: usage,
			}, root, &intermediateKey.PublicKey, nil)
			leafKey := newKey(t)
			leaf := issue(t, leafTemplate(300, "Signer"), &ca{cert: intermediate, key: intermediateKey}, &leafKey.PublicKey, nil)
			pool := x509.NewCertPool()
			pool.AddCert(root.cert)
			signed, err := sign.Bytes(bindingTestPDF(), sign.Options{Signer: leafKey, Certificate: leaf, CertificateChain: []*x509.Certificate{intermediate}})
			if err != nil {
				t.Fatal(err)
			}
			_, err = sign.Verify(signed, pool)
			if allowed := usage[0] != x509.ExtKeyUsageServerAuth; allowed != (err == nil) {
				t.Fatalf("Verify() error = %v", err)
			}
		})
	}
}
