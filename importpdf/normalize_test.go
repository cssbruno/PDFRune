// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// The fixtures in testdata were produced by independent writers: Ghostscript
// (cross-reference streams, object streams, RC4) and pypdf (RC4, AES-128,
// AES-256 R5/R6). base.pdf is the unencrypted classic-xref page they share.
func readFixture(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatal(err)
	}
	return data
}

func fixturePageContent(t *testing.T, data []byte, password string) []byte {
	t.Helper()
	source, err := OpenBytesWithOptions(data, ImportOptions{Password: password})
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if source.PageCount() != 1 {
		t.Fatalf("page count = %d, want 1", source.PageCount())
	}
	page, err := source.Page(1, "MediaBox")
	if err != nil {
		t.Fatalf("page: %v", err)
	}
	content, err := page.ContentWithError()
	if err != nil {
		t.Fatalf("content: %v", err)
	}
	return content
}

func TestImportReadsCrossReferenceAndObjectStreams(t *testing.T) {
	content := fixturePageContent(t, readFixture(t, "xref-stream.pdf"), "")
	if !bytes.Contains(content, []byte("Tj")) && !bytes.Contains(content, []byte("TJ")) {
		t.Fatalf("content has no text operator: %q", content)
	}
}

func TestImportDecryptsStandardSecurityHandlers(t *testing.T) {
	want := fixturePageContent(t, readFixture(t, "base.pdf"), "")
	for name, password := range map[string]string{
		"rc4-128-owner-only.pdf": "",
		"aes-256-owner-only.pdf": "",
		"rc4-40-user.pdf":        "senha",
		"rc4-128-user.pdf":       "senha",
		"aes-128-user.pdf":       "senha",
		"aes-256-r5-user.pdf":    "senha",
		"aes-256-user.pdf":       "senha",
	} {
		t.Run(name, func(t *testing.T) {
			if got := fixturePageContent(t, readFixture(t, name), password); !bytes.Equal(got, want) {
				t.Fatalf("decrypted content differs from the unencrypted page:\n got %q\nwant %q", got, want)
			}
		})
	}
}

func TestImportAcceptsTheOwnerPassword(t *testing.T) {
	want := fixturePageContent(t, readFixture(t, "base.pdf"), "")
	for _, name := range []string{"rc4-40-user.pdf", "rc4-128-user.pdf", "aes-128-user.pdf", "aes-256-r5-user.pdf", "aes-256-user.pdf"} {
		t.Run(name, func(t *testing.T) {
			if got := fixturePageContent(t, readFixture(t, name), "dono"); !bytes.Equal(got, want) {
				t.Fatalf("owner-password content differs from the unencrypted page")
			}
		})
	}
}

func TestImportDecryptsObjectStreamsOfEncryptedFiles(t *testing.T) {
	content := fixturePageContent(t, readFixture(t, "rc4-128-object-streams.pdf"), "senha")
	if !bytes.Contains(content, []byte("Tj")) && !bytes.Contains(content, []byte("TJ")) {
		t.Fatalf("content has no text operator: %q", content)
	}
}

func TestImportReportsMissingAndIncorrectPasswords(t *testing.T) {
	for _, name := range []string{"rc4-40-user.pdf", "rc4-128-user.pdf", "aes-128-user.pdf", "aes-256-r5-user.pdf", "aes-256-user.pdf", "rc4-128-object-streams.pdf"} {
		t.Run(name, func(t *testing.T) {
			data := readFixture(t, name)
			if _, err := OpenBytes(data); !errors.Is(err, ErrPasswordRequired) {
				t.Fatalf("without password error = %v, want ErrPasswordRequired", err)
			}
			if _, err := OpenBytesWithOptions(data, ImportOptions{Password: "errada"}); !errors.Is(err, ErrIncorrectPassword) {
				t.Fatalf("wrong password error = %v, want ErrIncorrectPassword", err)
			}
		})
	}
}

func TestNormalizationDecryptsStringsAndDropsEncryption(t *testing.T) {
	normalized, err := normalizeSourceContext(context.Background(), readFixture(t, "aes-256-user.pdf"), ImportOptions{MaxSourceBytes: MaxSourceBytes, Password: "senha"})
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Contains(normalized, []byte("/Encrypt")) {
		t.Fatal("normalized PDF still references an encryption dictionary")
	}
	if !bytes.Contains(normalized, []byte("<"+hex.EncodeToString([]byte("Laudo (titulo)"))+">")) {
		t.Fatal("normalized PDF does not carry the decrypted /Title string")
	}
	again, err := parseClassicSourceContext(context.Background(), normalized, ImportOptions{MaxSourceBytes: MaxSourceBytes})
	if err != nil {
		t.Fatalf("normalized PDF is not classic: %v", err)
	}
	if again.PageCount() != 1 {
		t.Fatalf("normalized page count = %d", again.PageCount())
	}
}

func TestNormalizationIsBoundedBySourceLimit(t *testing.T) {
	_, err := normalizeSourceContext(context.Background(), readFixture(t, "xref-stream.pdf"), ImportOptions{MaxSourceBytes: 64})
	if !errors.Is(err, ErrSourceTooLarge) {
		t.Fatalf("error = %v, want ErrSourceTooLarge", err)
	}
}

func TestUndoPNGPredictorRows(t *testing.T) {
	// Two 3-byte rows: None, then Up (adds the row above).
	encoded := []byte{0, 1, 2, 3, 2, 1, 1, 1}
	decoded, err := undoPNGPredictor(encoded, 3, 1, 8)
	if err != nil {
		t.Fatal(err)
	}
	if want := []byte{1, 2, 3, 2, 3, 4}; !bytes.Equal(decoded, want) {
		t.Fatalf("decoded = %v, want %v", decoded, want)
	}
	if _, err := undoPNGPredictor([]byte{9, 0, 0, 0}, 3, 1, 8); err == nil {
		t.Fatal("invalid row type was accepted")
	}
}

func TestLiteralStringDecoding(t *testing.T) {
	for raw, want := range map[string]string{
		`(a\(b\)c)`:   "a(b)c",
		`(\101\102)`:  "AB",
		"(x\\\ny)":    "xy",
		"(line\r\nb)": "line\nb",
		`(\n\t\\)`:    "\n\t\\",
	} {
		if got := string(decodePDFLiteralString([]byte(raw))); got != want {
			t.Fatalf("decode %q = %q, want %q", raw, got, want)
		}
	}
	if got := decodePDFHexString([]byte("<41 4>")); !bytes.Equal(got, []byte{0x41, 0x40}) {
		t.Fatalf("hex decode = %x", got)
	}
}

func TestImportAcceptsStreamObjectWithoutEndobj(t *testing.T) {
	// pypdf writes the xref stream of an incremental update without endobj.
	source, err := OpenBytes(readFixture(t, "pypdf-incremental-on-xref-stream.pdf"))
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	if source.PageCount() == 0 {
		t.Fatal("no pages")
	}
}

func TestImportIgnoresAnUnneededPassword(t *testing.T) {
	for _, name := range []string{"libreoffice-permissions-only.pdf", "rc4-128-owner-only.pdf", "aes-256-owner-only.pdf"} {
		if _, err := OpenBytesWithOptions(readFixture(t, name), ImportOptions{Password: "qualquer"}); err != nil {
			t.Fatalf("%s opens without a password but a typed one failed it: %v", name, err)
		}
	}
}

func TestImportOpensLibreOfficeUserPassword(t *testing.T) {
	data := readFixture(t, "libreoffice-user-password.pdf")
	if _, err := OpenBytes(data); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("error = %v, want ErrPasswordRequired", err)
	}
	if _, err := OpenBytesWithOptions(data, ImportOptions{Password: "senha"}); err != nil {
		t.Fatalf("open with password: %v", err)
	}
}

func TestImportReadsAPDFWithBytesBeforeTheHeader(t *testing.T) {
	base := readFixture(t, "xref-stream.pdf")
	for name, prefix := range map[string]string{"utf-8 bom": "\xef\xbb\xbf", "preamble": "HTTP/1.1 200 OK\r\n\r\n"} {
		if _, err := OpenBytes(append([]byte(prefix), base...)); err != nil {
			t.Fatalf("%s: %v", name, err)
		}
	}
	protected := append([]byte("\xef\xbb\xbf"), readFixture(t, "aes-256-user.pdf")...)
	if _, err := OpenBytes(protected); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("prefixed protected PDF error = %v, want ErrPasswordRequired", err)
	}
	if _, err := OpenBytes(append(bytes.Repeat([]byte{' '}, 2048), base...)); err == nil {
		t.Fatal("a header beyond the first 1024 bytes was accepted")
	}
}
