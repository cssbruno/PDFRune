// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"testing"
)

// A classic subsection naming object 300000000000 once sized the normalized
// xref table to one row per number up to it, so a 1 KB file that took the
// normalization path (/XRefStm here) allocated until the process was killed.
func TestNormalizationIgnoresHugeClassicObjectNumber(t *testing.T) {
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] >>",
	}
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, 0, len(objects)+1)
	for i, body := range objects {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	huge := out.Len()
	out.WriteString("300000000000 0 obj\nnull\nendobj\n")
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f\r\n", len(objects)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n\r\n", offset)
	}
	fmt.Fprintf(&out, "300000000000 1\n%010d 00000 n\r\n", huge)
	fmt.Fprintf(&out, "trailer\n<< /Size 4 /Root 1 0 R /XRefStm 0 >>\nstartxref\n%d\n%%%%EOF\n", xref)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	source, err := OpenBytesImmutableWithOptionsContext(context.Background(), out.Bytes(), ImportOptions{})
	runtime.ReadMemStats(&after)
	if err != nil {
		t.Fatalf("OpenBytesImmutableWithOptionsContext() error = %v", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64<<20 {
		t.Fatalf("opening a %d-byte PDF allocated %d MB", out.Len(), allocated>>20)
	}
	if count := source.PageCount(); count != 1 {
		t.Fatalf("PageCount() = %d, want 1", count)
	}
}
