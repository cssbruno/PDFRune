// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfcdr

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// An indirect /Length was spliced as raw text, so a trailing comment in its
// object ("57 % len", valid PDF) swallowed the /Filter after it and the
// sanitized form lost its text.
func TestInlinedLengthIsSplicedAsItsValue(t *testing.T) {
	content := "BT /F1 12 Tf 10 10 Td (SecretFormText) Tj ET"
	compressed := zlibBytes([]byte(content))
	form := fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [0 0 100 100] /Resources << /Font << /F1 6 0 R >> >> /Length 7 0 R /Filter /FlateDecode\n>>\nstream\n%s\nendstream", compressed)
	source := resourceGraphPDF(t, "<< /XObject << /X0 5 0 R >> >>",
		form,
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
		fmt.Sprintf("%d %% len", len(compressed)),
	)
	clean, err := Sanitize(source)
	if err != nil {
		t.Fatalf("Sanitize() error = %v", err)
	}
	if !bytes.Contains(clean, []byte("/Filter /FlateDecode")) {
		t.Fatalf("sanitized form lost its /Filter:\n%s", clean)
	}
}

// Each repeated "/Length 5 0 R" copied the 1 MB target before the sanitizer
// refused the duplicate: 1000 repetitions built gigabytes.
func TestRepeatedInlinedKeysAreNotCopied(t *testing.T) {
	source := resourceGraphPDF(t, "<< /Foo 5 0 R >>",
		"<< "+strings.Repeat("/Length 6 0 R ", 1000)+">>",
		"[ /"+strings.Repeat("a", 1<<20)+" ]",
	)
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = Sanitize(source)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("1000 repeated keys allocated %d MB", allocated>>20)
	}
}

// Pages sharing one large font sanitized it again for every page; no byte
// limit charges that, so 10000 pages took about an hour.
func TestSharedResourceIsSanitizedOnce(t *testing.T) {
	widths := "[" + strings.Repeat("["+strings.Repeat("500 ", 9999)+"]", 40) + "]"
	build := func(pages int) []byte {
		builder := &pdfBuilder{}
		catalog, tree, content, font := builder.reserve(), builder.reserve(), builder.reserve(), builder.reserve()
		var kids strings.Builder
		for i := 0; i < pages; i++ {
			page := builder.reserve()
			fmt.Fprintf(&kids, "%d 0 R ", page)
			builder.set(page, []byte(fmt.Sprintf("<< /Type /Page /Parent %d 0 R /MediaBox [0 0 10 10] /Resources << /Font << /F1 %d 0 R >> >> /Contents %d 0 R >>", tree, font, content)))
		}
		builder.set(catalog, []byte(fmt.Sprintf("<< /Type /Catalog /Pages %d 0 R >>", tree)))
		builder.set(tree, []byte(fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), pages)))
		builder.set(content, pdfStreamBody([]byte("0 0 1 1 re f")))
		builder.set(font, []byte("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /FirstChar 0 /Widths "+widths+" >>"))
		data, err := builder.bytes(context.Background(), catalog)
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	elapsed := func(pages int) time.Duration {
		start := time.Now()
		if _, err := Sanitize(build(pages)); err != nil {
			t.Fatalf("Sanitize(%d pages) error = %v", pages, err)
		}
		return time.Since(start)
	}
	one, many := elapsed(1), elapsed(40)
	if many > 5*one+500*time.Millisecond {
		t.Fatalf("40 pages sharing one font took %v, one page %v", many, one)
	}
}

// The early output check added a fixed trailer allowance, so a 502-byte
// output needed MaxOutputBytes 542.
func TestMaxOutputBytesAcceptsAnOutputThatFits(t *testing.T) {
	source := resourceGraphPDF(t, "<< >>")
	clean, err := Sanitize(source)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := SanitizeContext(context.Background(), source, Options{MaxOutputBytes: int64(len(clean))}); err != nil {
		t.Fatalf("MaxOutputBytes equal to the %d-byte output: %v", len(clean), err)
	}
	if _, err := SanitizeContext(context.Background(), source, Options{MaxOutputBytes: int64(len(clean) - 1)}); err == nil {
		t.Fatal("an output one byte over MaxOutputBytes was accepted")
	}
}

func zlibBytes(data []byte) []byte {
	var out bytes.Buffer
	w := zlib.NewWriter(&out)
	_, _ = w.Write(data)
	_ = w.Close()
	return out.Bytes()
}
