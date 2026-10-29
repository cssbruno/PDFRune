// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// Through OpenReaderAt, every object is read in a window of at least 64 KB.
// Caching the body as a subslice of that window kept the whole window alive,
// so 3000 tiny font objects retained about 190 MB.
func TestReaderAtCacheDoesNotRetainReadWindows(t *testing.T) {
	const fonts = 3000
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := make([]int, 0, 3+fonts)
	write := func(body string) {
		offsets = append(offsets, out.Len())
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", len(offsets), body)
	}
	var refs strings.Builder
	for i := 0; i < fonts; i++ {
		fmt.Fprintf(&refs, "/F%d %d 0 R ", i, 4+i)
	}
	write("<< /Type /Catalog /Pages 2 0 R >>")
	write("<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	write("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << /Font << " + refs.String() + ">> >> >>")
	for i := 0; i < fonts; i++ {
		write("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>")
	}
	for out.Len() < 1<<20 {
		out.WriteString("% padding so every object gets a full 64 KB read window\n")
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f\r\n", len(offsets)+1)
	for _, offset := range offsets {
		fmt.Fprintf(&out, "%010d 00000 n\r\n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets)+1, xref)

	data := out.Bytes()
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	source, err := OpenReaderAt(bytes.NewReader(data), int64(len(data)))
	if err != nil {
		t.Fatalf("OpenReaderAt() error = %v", err)
	}
	page, err := source.Page(1, "MediaBox")
	if err != nil {
		t.Fatalf("Page() error = %v", err)
	}
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(source)
	runtime.KeepAlive(page)
	if retained := int64(after.HeapAlloc) - int64(before.HeapAlloc); retained > 32<<20 {
		t.Fatalf("source and page retain %d MB for a %d MB file", retained>>20, len(data)>>20)
	}
}
