// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign

import (
	"bytes"
	"compress/zlib"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"fmt"
	"math/big"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// These tests cover valid PDFs and CMS packages produced by other signers.

type handBuiltCMSOptions struct {
	subjectKeyIDSigner bool
	pss                bool
	pssParams          []byte
	unsortedAttributes bool
}

func testSignerWithSubjectKeyID(t *testing.T) (*x509.Certificate, *rsa.PrivateKey) {
	t.Helper()
	cert, signer := testSignerWithTemplate(t, &x509.Certificate{
		SerialNumber:          big.NewInt(7),
		Subject:               pkix.Name{CommonName: "Compat Signer"},
		SubjectKeyId:          []byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20},
		KeyUsage:              x509.KeyUsageDigitalSignature,
		UnknownExtKeyUsage:    []asn1.ObjectIdentifier{oidDocumentSigning},
		BasicConstraintsValid: true,
	})
	return cert, signer.(*rsa.PrivateKey)
}

func pssParamsDER(hash, mgfHash asn1.ObjectIdentifier, saltLength int) []byte {
	return derSequence(
		der(0xa0, derSequence(derOID(hash), derNull())),
		der(0xa1, derSequence(derOID(oidMGF1), derSequence(derOID(mgfHash), derNull()))),
		der(0xa2, derInteger(saltLength)),
	)
}

// buildHandCMS builds a detached CMS SignedData by hand so individual RFC 5652
// features can be toggled.
func buildHandCMS(t *testing.T, content []byte, cert *x509.Certificate, key *rsa.PrivateKey, options handBuiltCMSOptions) []byte {
	t.Helper()
	digest := sha256.Sum256(content)
	timeDER, err := asn1.Marshal(time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	contentType := derSequence(derOID(oidContentType), derSet(derOID(oidData)))
	messageDigest := derSequence(derOID(oidMessageDigest), derSet(derOctetString(digest[:])))
	signingTime := derSequence(derOID(oidSigningTime), derSet(timeDER))
	attrsContent := derValueContent(derSet(contentType, messageDigest, signingTime))
	if options.unsortedAttributes {
		attrsContent = bytes.Join([][]byte{messageDigest, contentType, signingTime}, nil)
	}
	attrsDigest := sha256.Sum256(der(0x31, attrsContent))

	var signatureAlgorithm, signature []byte
	if options.pss {
		params := options.pssParams
		if params == nil {
			params = pssParamsDER(oidSHA256, oidSHA256, 32)
		}
		signatureAlgorithm = derSequence(derOID(oidRSASSAPSS), params)
		if len(params) == 0 {
			signatureAlgorithm = derSequence(derOID(oidRSASSAPSS))
		}
		signature, err = rsa.SignPSS(rand.Reader, key, crypto.SHA256, attrsDigest[:], &rsa.PSSOptions{SaltLength: 32})
	} else {
		signatureAlgorithm = derSequence(derOID(oidSHA256WithRSA), derNull())
		signature, err = rsa.SignPKCS1v15(rand.Reader, key, crypto.SHA256, attrsDigest[:])
	}
	if err != nil {
		t.Fatal(err)
	}
	version, sid := 1, derSequence(cert.RawIssuer, derInteger(cert.SerialNumber))
	if options.subjectKeyIDSigner {
		version, sid = 3, der(0x80, cert.SubjectKeyId)
	}
	signerInfo := derSequence(derInteger(version), sid, derSequence(derOID(oidSHA256)),
		der(0xa0, attrsContent), signatureAlgorithm, derOctetString(signature))
	signedData := derSequence(derInteger(version), derSet(derSequence(derOID(oidSHA256))),
		derSequence(derOID(oidData)), der(0xa0, cert.Raw), derSet(signerInfo))
	return derSequence(derOID(oidSignedData), der(0xa0, signedData))
}

// requireOpenSSLAccepts cross-checks that a hand-built CMS is valid for
// OpenSSL, so the tests do not encode a misreading of RFC 5652.
func requireOpenSSLAccepts(t *testing.T, cms, content []byte) {
	t.Helper()
	if _, err := exec.LookPath("openssl"); err != nil {
		t.Skip("openssl not available")
	}
	dir := t.TempDir()
	cmsPath, contentPath := filepath.Join(dir, "cms.der"), filepath.Join(dir, "content.bin")
	if err := os.WriteFile(cmsPath, cms, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(contentPath, content, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("openssl", "cms", "-verify", "-binary", "-noverify", "-inform", "DER",
		"-in", cmsPath, "-content", contentPath, "-out", os.DevNull).CombinedOutput()
	if err != nil {
		t.Fatalf("openssl rejected the hand-built CMS, test input is invalid: %v\n%s", err, out)
	}
}

type xrefLayout int

const (
	classicXref xrefLayout = iota
	// streamXref uses one uncompressed cross-reference stream.
	streamXref
	// compressedXref keeps the catalog, pages, AcroForm and field in a Flate
	// object stream indexed by a Flate + PNG predictor xref stream.
	compressedXref
	// hybridXref uses a classic table whose /XRefStm lists the compressed
	// objects (PDF 1.5 hybrid-reference file).
	hybridXref
)

func flate(t *testing.T, data []byte) []byte {
	t.Helper()
	var out bytes.Buffer
	writer := zlib.NewWriter(&out)
	if _, err := writer.Write(data); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	return out.Bytes()
}

// pngUpRows applies the PNG Up predictor to rows of the given width.
func pngUpRows(data []byte, width int) []byte {
	out := make([]byte, 0, len(data)+len(data)/width)
	previous := make([]byte, width)
	for pos := 0; pos < len(data); pos += width {
		out = append(out, 2)
		for i, b := range data[pos : pos+width] {
			out = append(out, b-previous[i])
		}
		previous = data[pos : pos+width]
	}
	return out
}

type xrefStreamRow struct {
	kind   byte
	field2 uint32
	field3 uint16
}

func xrefStreamRows(rows []xrefStreamRow) []byte {
	var out bytes.Buffer
	for _, row := range rows {
		out.WriteByte(row.kind)
		_ = binary.Write(&out, binary.BigEndian, row.field2)
		_ = binary.Write(&out, binary.BigEndian, row.field3)
	}
	return out.Bytes()
}

// signedPDFWithXrefLayout builds a complete single-signature PAdES PDF whose
// cross-reference data uses layout.
func signedPDFWithXrefLayout(t *testing.T, layout xrefLayout) []byte {
	t.Helper()
	cert, key := testSignerWithSubjectKeyID(t)
	pdf := pdfWithXrefLayout(t, layout, nil)
	contentsStart := bytes.Index(pdf, []byte("/Contents <")) + len("/Contents ")
	contentsEnd := bytes.IndexByte(pdf[contentsStart:], '>') + contentsStart + 1
	byteRange := fmt.Sprintf("[%010d %010d %010d %010d]", 0, contentsStart, contentsEnd, len(pdf)-contentsEnd)
	copy(pdf[bytes.Index(pdf, []byte("[0000000000 0000000000")):], byteRange)
	content := append(append([]byte(nil), pdf[:contentsStart]...), pdf[contentsEnd:]...)
	cms, err := CreateCMS(content, CMSOptions{Signer: key, Certificate: cert, Detached: true})
	if err != nil {
		t.Fatalf("CreateCMS() error = %v", err)
	}
	hex.Encode(pdf[contentsStart+1:], cms)
	return pdf
}

// pdfWithXrefLayout builds an unsigned-placeholder PDF whose objects 1-6 use
// the default bodies unless overridden.
func pdfWithXrefLayout(t *testing.T, layout xrefLayout, overrides map[int]string) []byte {
	t.Helper()
	bodies := map[int]string{
		1: "<< /Type /Catalog /Pages 2 0 R /AcroForm 4 0 R >>",
		2: "<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		3: "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Annots [5 0 R] >>",
		4: "<< /Fields [5 0 R] /SigFlags 3 >>",
		5: "<< /Type /Annot /Subtype /Widget /FT /Sig /T (S) /Rect [0 0 0 0] /P 3 0 R /V 6 0 R >>",
		6: "<< /Type /Sig /Filter /Adobe.PPKLite /SubFilter /ETSI.CAdES.detached /ByteRange [0000000000 0000000000 0000000000 0000000000] /Contents <" +
			strings.Repeat("0", 8192) + "> >>",
	}
	for number, body := range overrides {
		bodies[number] = body
	}
	compressed := []int{1, 2, 4, 5}
	packed := layout == compressedXref || layout == hybridXref

	var b bytes.Buffer
	b.WriteString("%PDF-1.7\n")
	offsets := make(map[int]int)
	writeObject := func(number int, body string) {
		offsets[number] = b.Len()
		fmt.Fprintf(&b, "%d 0 obj\n%s\nendobj\n", number, body)
	}
	if packed {
		var header, members bytes.Buffer
		for _, number := range compressed {
			fmt.Fprintf(&header, "%d %d ", number, members.Len())
			members.WriteString(bodies[number])
			members.WriteByte('\n')
		}
		data := flate(t, append(header.Bytes(), members.Bytes()...))
		offsets[8] = b.Len()
		fmt.Fprintf(&b, "8 0 obj\n<< /Type /ObjStm /N %d /First %d /Filter /FlateDecode /Length %d >>\nstream\n", len(compressed), header.Len(), len(data))
		b.Write(data)
		b.WriteString("\nendstream\nendobj\n")
		writeObject(3, bodies[3])
		writeObject(6, bodies[6])
	} else {
		for number := 1; number <= 6; number++ {
			writeObject(number, bodies[number])
		}
	}
	slot := func(number int) uint16 {
		for i, candidate := range compressed {
			if candidate == number {
				return uint16(i)
			}
		}
		t.Fatalf("object %d is not compressed", number)
		return 0
	}

	var xrefOffset int
	switch layout {
	case classicXref:
		xrefOffset = b.Len()
		b.WriteString("xref\n0 7\n0000000000 65535 f \n")
		for number := 1; number <= 6; number++ {
			fmt.Fprintf(&b, "%010d 00000 n \n", offsets[number])
		}
		b.WriteString("trailer\n<< /Size 7 /Root 1 0 R >>\n")
	case streamXref:
		xrefOffset = b.Len()
		rows := []xrefStreamRow{{0, 0, 65535}}
		for number := 1; number <= 6; number++ {
			rows = append(rows, xrefStreamRow{1, uint32(offsets[number]), 0})
		}
		rows = append(rows, xrefStreamRow{1, uint32(xrefOffset), 0})
		data := xrefStreamRows(rows)
		fmt.Fprintf(&b, "7 0 obj\n<< /Type /XRef /Size 8 /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n", len(data))
		b.Write(data)
		b.WriteString("\nendstream\nendobj\n")
	case compressedXref:
		xrefOffset = b.Len()
		rows := []xrefStreamRow{{0, 0, 65535}}
		for number := 1; number <= 6; number++ {
			if offset, ok := offsets[number]; ok && number != 1 && number != 2 && number != 4 && number != 5 {
				rows = append(rows, xrefStreamRow{1, uint32(offset), 0})
			} else {
				rows = append(rows, xrefStreamRow{2, 8, slot(number)})
			}
		}
		rows = append(rows, xrefStreamRow{1, uint32(xrefOffset), 0}, xrefStreamRow{1, uint32(offsets[8]), 0})
		data := flate(t, pngUpRows(xrefStreamRows(rows), 7))
		fmt.Fprintf(&b, "7 0 obj\n<< /Type /XRef /Size 9 /W [1 4 2] /Root 1 0 R /Filter /FlateDecode /DecodeParms << /Columns 7 /Predictor 12 >> /Length %d >>\nstream\n", len(data))
		b.Write(data)
		b.WriteString("\nendstream\nendobj\n")
	case hybridXref:
		streamOffset := b.Len()
		var rows []xrefStreamRow
		for _, number := range compressed {
			rows = append(rows, xrefStreamRow{2, 8, slot(number)})
		}
		data := xrefStreamRows(rows)
		fmt.Fprintf(&b, "7 0 obj\n<< /Type /XRef /Size 9 /W [1 4 2] /Index [1 2 4 2] /Length %d >>\nstream\n", len(data))
		b.Write(data)
		b.WriteString("\nendstream\nendobj\n")
		xrefOffset = b.Len()
		fmt.Fprintf(&b, "xref\n0 1\n0000000000 65535 f \n3 1\n%010d 00000 n \n6 3\n%010d 00000 n \n%010d 00000 n \n%010d 00000 n \n",
			offsets[3], offsets[6], streamOffset, offsets[8])
		fmt.Fprintf(&b, "trailer\n<< /Size 9 /Root 1 0 R /XRefStm %d >>\n", streamOffset)
	}
	fmt.Fprintf(&b, "startxref\n%d\n%%%%EOF\n", xrefOffset)
	return b.Bytes()
}

func TestSignatureDictionaryKeepsNonASCIIText(t *testing.T) {
	cert, signer := testSigner(t)
	out, err := Bytes(minimalPDFBytes(), Options{Signer: signer, Certificate: cert,
		Name: "Dra. Ana Lúcia", Reason: "Prescrição", Location: "São Paulo", FieldName: "Assinatura Médica",
		ContactInfo: "contato (clínica)"})
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	for _, lossy := range []string{"L?cia", "Prescri??o", "S?o Paulo", "M?dica", "cl?nica"} {
		if bytes.Contains(out, []byte(lossy)) {
			t.Errorf("signed PDF stores %q: non-ASCII text replaced by '?'", lossy)
		}
	}
	// "São Paulo" as UTF-16BE with a byte order mark.
	if !bytes.Contains(out, []byte("/Location <FEFF005300E3006F0020005000610075006C006F>")) {
		t.Error("signed PDF lacks /Location as a UTF-16BE hex string")
	}
	if _, err := VerifyIntegrity(out); err != nil {
		t.Fatalf("VerifyIntegrity() error = %v", err)
	}
}

func TestPDFStringKeepsASCIILiteral(t *testing.T) {
	for input, want := range map[string]string{
		"Dr. Ana (CRM 123)": `(Dr. Ana \(CRM 123\))`,
		"a\\b\n\r\t":        `(a\\b\n\r\t)`,
		"":                  `()`,
		"Ł":                 `<FEFF0141>`,
		"😀":                 `<FEFFD83DDE00>`,
		"bell\x07":          `<FEFF00620065006C006C0007>`,
	} {
		if got := pdfString(input); got != want {
			t.Errorf("pdfString(%q) = %s, want %s", input, got, want)
		}
	}
}

func TestVerifyReadsCrossReferenceStreams(t *testing.T) {
	for _, tc := range []struct {
		name   string
		layout xrefLayout
	}{
		{"classic", classicXref},
		{"xref stream", streamXref},
		{"compressed objects", compressedXref},
		{"hybrid", hybridXref},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pdf := signedPDFWithXrefLayout(t, tc.layout)
			count, err := CountSignatures(pdf)
			if err != nil || count != 1 {
				t.Fatalf("CountSignatures() = %d, %v, want 1", count, err)
			}
			if got := SignatureCount(pdf); got != 1 {
				t.Fatalf("SignatureCount() = %d, want 1", got)
			}
			if _, err := ExtractSingleSignature(pdf); err != nil {
				t.Fatalf("ExtractSingleSignature() error = %v", err)
			}
			if _, err := VerifyIntegrity(pdf); err != nil {
				t.Fatalf("VerifyIntegrity() error = %v", err)
			}
			// Bytes appended after the signed revision still invalidate it.
			if _, err := VerifyIntegrity(append(append([]byte(nil), pdf...), "\n% tail\n"...)); err == nil {
				t.Fatal("VerifyIntegrity() accepted bytes outside the ByteRange")
			}
		})
	}
}

func TestSignRejectsCrossReferenceStreamSource(t *testing.T) {
	cert, signer := testSigner(t)
	_, err := Bytes(signedPDFWithXrefLayout(t, streamXref), Options{Signer: signer, Certificate: cert})
	if !errors.Is(err, ErrUnsupportedPDF) {
		t.Fatalf("Bytes(xref stream) error = %v, want ErrUnsupportedPDF", err)
	}
}

func TestCountSignaturesReportsParseErrors(t *testing.T) {
	pdf := signedPDFWithXrefLayout(t, compressedXref)
	broken := bytes.Replace(pdf, []byte("/Type /ObjStm"), []byte("/Type /XXXXXX"), 1)
	if count, err := CountSignatures(broken); err == nil {
		t.Fatalf("CountSignatures(broken object stream) = %d, nil, want an error", count)
	}
	if got := SignatureCount(broken); got != 0 {
		t.Fatalf("SignatureCount(broken object stream) = %d, want 0", got)
	}
	unsigned, err := CountSignatures(minimalPDFBytes())
	if err != nil || unsigned != 0 {
		t.Fatalf("CountSignatures(unsigned) = %d, %v, want 0, nil", unsigned, err)
	}
}

func TestVerifyRejectsSignatureDictionaryInObjectStream(t *testing.T) {
	pdf := signedPDFWithXrefLayout(t, compressedXref)
	resolver, err := newPDFReadXrefResolverContext(t.Context(), pdf, mustStartXref(t, pdf), DefaultMaxXrefChainLength, DefaultMaxXrefEntries)
	if err != nil {
		t.Fatalf("newPDFReadXrefResolverContext() error = %v", err)
	}
	if _, start, err := resolver.indirectValueContext(t.Context(), pdfRef{Object: 5}); err != nil || start != -1 {
		t.Fatalf("indirectValueContext(compressed) start = %d, %v, want -1", start, err)
	}
	if _, err := resolver.objectOffsetContext(t.Context(), pdfRef{Object: 5}); !errors.Is(err, ErrUnsupportedPDF) {
		t.Fatalf("objectOffsetContext(compressed) error = %v, want ErrUnsupportedPDF", err)
	}

	// A direct /V inside a compressed field has no file offset, so its
	// ByteRange and /Contents could not be checked against the file.
	packedSignature := pdfWithXrefLayout(t, compressedXref, map[int]string{
		5: "<< /FT /Sig /T (S) /V << /Type /Sig /ByteRange [0 1 2 3] /Contents <00> >> >>",
	})
	if count, err := CountSignatures(packedSignature); !errors.Is(err, ErrUnsupportedPDF) {
		t.Fatalf("CountSignatures(packed signature) = %d, %v, want ErrUnsupportedPDF", count, err)
	}
}

func mustStartXref(t *testing.T, pdf []byte) int {
	t.Helper()
	offset, err := findStartXref(pdf)
	if err != nil {
		t.Fatalf("findStartXref() error = %v", err)
	}
	return offset
}

func TestVerifyAcceptsSubjectKeyIdentifierSignerID(t *testing.T) {
	cert, key := testSignerWithSubjectKeyID(t)
	content := []byte("signed pdf byte range")
	cms := buildHandCMS(t, content, cert, key, handBuiltCMSOptions{subjectKeyIDSigner: true})
	requireOpenSSLAccepts(t, cms, content)
	result, err := VerifyDetachedCMSIntegrity(cms, content)
	if err != nil {
		t.Fatalf("VerifyDetachedCMSIntegrity(SKI sid) error = %v", err)
	}
	if !result.Signer.Equal(cert) {
		t.Fatal("VerifyDetachedCMSIntegrity(SKI sid) returned another signer")
	}
	if signer, err := SignerCertificate(cms); err != nil || !signer.Equal(cert) {
		t.Fatalf("SignerCertificate(SKI sid) = %v, %v", signer, err)
	}

	other, _ := testSignerWithSubjectKeyID(t)
	other.SubjectKeyId = []byte{9, 9, 9}
	foreign := buildHandCMS(t, content, other, key, handBuiltCMSOptions{subjectKeyIDSigner: true})
	foreign = bytes.Replace(foreign, other.Raw, cert.Raw, 1)
	if _, err := VerifyDetachedCMSIntegrity(foreign, content); err == nil {
		t.Fatal("VerifyDetachedCMSIntegrity() accepted an SKI that names no embedded certificate")
	}
}

func TestVerifyAcceptsRSAPSS(t *testing.T) {
	cert, key := testSignerWithSubjectKeyID(t)
	content := []byte("signed pdf byte range")
	cms := buildHandCMS(t, content, cert, key, handBuiltCMSOptions{pss: true})
	requireOpenSSLAccepts(t, cms, content)
	if _, err := VerifyDetachedCMSIntegrity(cms, content); err != nil {
		t.Fatalf("VerifyDetachedCMSIntegrity(RSA-PSS) error = %v", err)
	}
}

func TestVerifyRejectsUnsafeRSAPSSParameters(t *testing.T) {
	cert, key := testSignerWithSubjectKeyID(t)
	content := []byte("signed pdf byte range")
	for name, params := range map[string][]byte{
		"absent (SHA-1 defaults)": {},
		"SHA-1 hash":              pssParamsDER(oidSHA1, oidSHA256, 32),
		"MGF1 hash mismatch":      pssParamsDER(oidSHA256, oidSHA512, 32),
		"wrong salt length":       pssParamsDER(oidSHA256, oidSHA256, 20),
		"hash defaulted":          derSequence(der(0xa2, derInteger(32))),
	} {
		cms := buildHandCMS(t, content, cert, key, handBuiltCMSOptions{pss: true, pssParams: params})
		if _, err := VerifyDetachedCMSIntegrity(cms, content); err == nil {
			t.Errorf("VerifyDetachedCMSIntegrity(RSA-PSS %s) succeeded", name)
		}
	}
}

func TestVerifyAcceptsSignedUnsortedAttributes(t *testing.T) {
	cert, key := testSignerWithSubjectKeyID(t)
	content := []byte("signed pdf byte range")
	cms := buildHandCMS(t, content, cert, key, handBuiltCMSOptions{unsortedAttributes: true})
	requireOpenSSLAccepts(t, cms, content)
	if _, err := VerifyDetachedCMSIntegrity(cms, content); err != nil {
		t.Fatalf("VerifyDetachedCMSIntegrity(unsorted attrs) error = %v", err)
	}
}

func TestParserAcceptsLegalEndOfLineVariants(t *testing.T) {
	cert, signer := testSigner(t)
	for name, input := range map[string][]byte{
		// Same length, so every offset stays valid.
		"CR only":                bytes.ReplaceAll(minimalPDFBytes(), []byte("\n"), []byte("\r")),
		"trailer << on one line": bytes.Replace(minimalPDFBytes(), []byte("trailer\n<<"), []byte("trailer <<"), 1),
		"startxref then comment": bytes.Replace(minimalPDFBytes(), []byte("\n%%EOF"), []byte(" %%EOF"), 1),
	} {
		out, err := Bytes(input, Options{Signer: signer, Certificate: cert})
		if err != nil {
			t.Errorf("Bytes(%s) error = %v", name, err)
			continue
		}
		if _, err := VerifyIntegrity(out); err != nil {
			t.Errorf("VerifyIntegrity(%s) error = %v", name, err)
		}
	}
}

func TestCAdESSubFilterHasPAdESBaselineAttributes(t *testing.T) {
	cert, signer := testSigner(t)
	out, err := Bytes(minimalPDFBytes(), Options{Signer: signer, Certificate: cert})
	if err != nil {
		t.Fatalf("Bytes() error = %v", err)
	}
	extracted, err := ExtractSingleSignature(out)
	if err != nil {
		t.Fatalf("ExtractSingleSignature() error = %v", err)
	}
	values, err := SignedAttributeValues(extracted.CMS, oidSigningCertV2)
	if err != nil || len(values) != 1 {
		t.Fatalf("signing-certificate-v2 = %v, %v, want one value", values, err)
	}
	var signingCertificate struct {
		Certs []struct {
			CertHash     []byte
			IssuerSerial struct {
				Issuer []asn1.RawValue
				Serial *big.Int
			}
		}
	}
	if rest, err := asn1.Unmarshal(values[0].FullBytes, &signingCertificate); err != nil || len(rest) != 0 {
		t.Fatalf("decode signing-certificate-v2: %v", err)
	}
	certHash := sha256.Sum256(cert.Raw)
	if len(signingCertificate.Certs) != 1 || !bytes.Equal(signingCertificate.Certs[0].CertHash, certHash[:]) ||
		signingCertificate.Certs[0].IssuerSerial.Serial.Cmp(cert.SerialNumber) != 0 {
		t.Fatal("signing-certificate-v2 does not identify the signer certificate")
	}
	if values, _ := SignedAttributeValues(extracted.CMS, oidSigningTime); len(values) != 0 {
		t.Error("ETSI.CAdES.detached CMS carries signing-time (PAdES-B-B forbids it)")
	}
	if _, err := VerifyIntegrity(out); err != nil {
		t.Fatalf("VerifyIntegrity() error = %v", err)
	}

	legacy, err := Bytes(minimalPDFBytes(), Options{Signer: signer, Certificate: cert, SubFilter: SubFilterAdobePKCS7Detached})
	if err != nil {
		t.Fatalf("Bytes(adbe.pkcs7.detached) error = %v", err)
	}
	result, err := VerifyIntegrity(legacy)
	if err != nil || result.CMS.SigningTime == nil {
		t.Fatalf("adbe.pkcs7.detached signing-time = %v, %v, want present", result, err)
	}
}
