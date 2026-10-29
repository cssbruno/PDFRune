// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package characterize

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"strings"
	"testing"
)

func sharedContentPDF(pages int, content []byte) []byte {
	var compressed bytes.Buffer
	w, _ := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	_, _ = w.Write(content)
	_ = w.Close()
	objects := []string{"<< /Type /Catalog /Pages 2 0 R >>", "",
		fmt.Sprintf("<< /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream", compressed.Len(), compressed.Bytes())}
	var kids strings.Builder
	for i := 0; i < pages; i++ {
		fmt.Fprintf(&kids, "%d 0 R ", 4+i)
		objects = append(objects, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Contents 3 0 R >>")
	}
	objects[1] = fmt.Sprintf("<< /Type /Pages /Kids [%s] /Count %d >>", kids.String(), pages)
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, len(objects))
	for i, body := range objects {
		offsets[i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f\r\n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n\r\n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(objects)+1, xref)
	return out.Bytes()
}

// Build extracted each page with its own parse and a fresh decode budget, so
// pages sharing a 30 MiB content stream inflated it once per page and the
// document limit TextContext enforces never applied.
func TestBuildAppliesTheDocumentDecodeBudget(t *testing.T) {
	pdf := sharedContentPDF(8, bytes.Repeat([]byte(" "), 30<<20))
	fingerprint := Fingerprint{GOOS: "test", GOARCH: "test", GoVersion: "go-test", CPUs: 1}
	if _, err := Build(context.Background(), []Artifact{{Name: "a.pdf", PDF: pdf}}, "test", fingerprint, DefaultLimits()); err == nil {
		t.Fatal("Build accepted 240 MiB of decoded page content")
	}
}
