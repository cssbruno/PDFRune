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

// Objects without endobj span the objects after them up to the next endobj.
// A page resource chained through 2000 of them, followed by 4 MB of filler,
// once copied that filler once per object (8 GB for a 4 MB file).
func TestPageBoundsBytesCopiedFromOverlappingObjects(t *testing.T) {
	const chain = 2000
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	offsets := map[int]int{}
	write := func(number int, body string) {
		offsets[number] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", number, body)
	}
	write(1, "<< /Type /Catalog /Pages 2 0 R >>")
	write(2, "<< /Type /Pages /Kids [3 0 R] /Count 1 >>")
	write(3, "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << /Font << /F 10 0 R >> >> >>")
	for i := 0; i < chain; i++ {
		offsets[10+i] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%d 0 R\n", 10+i, 11+i)
	}
	offsets[10+chain] = out.Len()
	fmt.Fprintf(&out, "%d 0 obj\nnull\n", 10+chain)
	for out.Len() < 4<<20 {
		out.WriteString("% filler filler filler filler filler filler filler filler filler\n")
	}
	out.WriteString("endobj\n")
	xref := out.Len()
	size := 11 + chain
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f\r\n", size)
	for number := 1; number < size; number++ {
		offset, ok := offsets[number]
		if !ok {
			out.WriteString("0000000000 00000 f\r\n")
			continue
		}
		fmt.Fprintf(&out, "%010d 00000 n\r\n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", size, xref)

	source, err := OpenBytesImmutableWithOptionsContext(context.Background(), out.Bytes(), ImportOptions{})
	if err != nil {
		t.Fatalf("OpenBytesImmutableWithOptionsContext() error = %v", err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = source.Page(1, "MediaBox")
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 4*uint64(out.Len())+64<<20 {
		t.Fatalf("reading the page of a %d MB PDF allocated %d MB", out.Len()>>20, allocated>>20)
	}
}
