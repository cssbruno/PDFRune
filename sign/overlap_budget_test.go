// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign

import (
	"bytes"
	"compress/zlib"
	"fmt"
	"strings"
	"testing"
)

// Field i holds a literal string containing the text of field i+1, so every
// field's span holds all later fields: the file grows with n while scanning
// the AcroForm read n^2 bytes.
func TestCountSignaturesBoundsOverlappingFieldSpans(t *testing.T) {
	const n = 2000
	offsets := make([]int, n+3)
	var inner []byte
	for i := n; i >= 1; i-- {
		header := fmt.Sprintf("%d 0 obj\n<< /FT /Tx /P (", i+2)
		object := append(append([]byte(header), inner...), ") >>\nendobj\n"...)
		for j := i + 1; j <= n; j++ {
			offsets[j+2] += len(header)
		}
		inner = object
	}
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	catalog := buf.Len()
	buf.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R /AcroForm << /Fields [")
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&buf, "%d 0 R ", i+2)
	}
	buf.WriteString("] >> >>\nendobj\n")
	pages := buf.Len()
	buf.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\nendobj\n")
	base := buf.Len()
	buf.Write(inner)
	xref := buf.Len()
	fmt.Fprintf(&buf, "xref\n0 %d\n0000000000 65535 f \n%010d 00000 n \n%010d 00000 n \n", n+3, catalog, pages)
	for i := 1; i <= n; i++ {
		fmt.Fprintf(&buf, "%010d 00000 n \n", base+offsets[i+2])
	}
	fmt.Fprintf(&buf, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", n+3, xref)

	if _, err := CountSignatures(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "overlap beyond the PDF size") {
		t.Fatalf("CountSignatures() error = %v, want overlapping objects rejected", err)
	}
}

// A 600-byte xref stream inflates to 500000 one-byte rows; chained by /Prev
// 128 times it made an 80 KB file cost seconds of CPU and gigabytes of
// allocation, each section passing its own limit.
func TestCountSignaturesBoundsRowsAcrossXrefStreams(t *testing.T) {
	const rows = 500000
	var compressed bytes.Buffer
	w, _ := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	_, _ = w.Write(make([]byte, rows))
	_ = w.Close()
	var buf bytes.Buffer
	buf.WriteString("%PDF-1.7\n")
	prev := -1
	for i := 0; i < 16; i++ {
		offset := buf.Len()
		fmt.Fprintf(&buf, "%d 0 obj\n<< /Type /XRef /W [0 0 1] /Size %d /Root 1 0 R /Filter /FlateDecode /Length %d", i+1, rows, compressed.Len())
		if prev >= 0 {
			fmt.Fprintf(&buf, " /Prev %d", prev)
		}
		buf.WriteString(" >>\nstream\n")
		buf.Write(compressed.Bytes())
		buf.WriteString("\nendstream\nendobj\n")
		prev = offset
	}
	fmt.Fprintf(&buf, "startxref\n%d\n%%%%EOF\n", prev)

	if _, err := CountSignatures(buf.Bytes()); err == nil || !strings.Contains(err.Error(), "xref streams exceed maximum size") {
		t.Fatalf("CountSignatures() error = %v, want the xref row budget", err)
	}
}
