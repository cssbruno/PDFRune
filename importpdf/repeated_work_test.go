// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"testing"
	"time"
)

// Without startxref, reconstruction splits every object stream it finds and
// skips those that fail. /N 100000 allocated two 800 KB slices per stream
// before the empty header failed, about 1.5 GB for 2000 tiny objects.
func TestReconstructionChecksObjectStreamNBeforeAllocating(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n")
	for i := 1; i <= 2000; i++ {
		fmt.Fprintf(&out, "%d 0 obj\n<</Type/ObjStm/N 100000/First 0/Length 0>>stream\n\nendstream\nendobj\n", i)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = OpenBytesImmutableWithOptionsContext(context.Background(), out.Bytes(), ImportOptions{})
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 128<<20 {
		t.Fatalf("reconstructing %d KB allocated %d MB", out.Len()>>10, allocated>>20)
	}
}

// emptyDeflateBlocks returns a zlib stream of empty fixed-Huffman blocks,
// 10 bits each, that inflates to nothing.
func emptyDeflateBlocks(blocks int) []byte {
	var out bytes.Buffer
	out.Write([]byte{0x78, 0x9c})
	var acc uint64
	var bits uint
	put := func(value uint64, n uint) {
		acc |= value << bits
		for bits += n; bits >= 8; bits -= 8 {
			out.WriteByte(byte(acc))
			acc >>= 8
		}
	}
	for i := 0; i < blocks; i++ {
		final := uint64(0)
		if i == blocks-1 {
			final = 1
		}
		put(final, 1)
		put(1, 2) // fixed Huffman
		put(0, 7) // end of block
	}
	if bits > 0 {
		put(0, 8-bits)
	}
	out.Write([]byte{0, 0, 0, 1}) // Adler-32 of no data
	return out.Bytes()
}

// A /Contents array naming one stream that inflates to nothing was inflated
// once per entry; the page content limit counts output, so it never stopped.
func TestPageContentDecodesARepeatedStreamOnce(t *testing.T) {
	stream := emptyDeflateBlocks(1 << 20)
	objects := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << >> /Contents [" + strings.Repeat("4 0 R ", 1000) + "] >>",
		fmt.Sprintf("<< /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream", len(stream), stream),
	}
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

	source, err := OpenBytes(out.Bytes())
	if err != nil {
		t.Fatalf("OpenBytes() error = %v", err)
	}
	// One inflate takes about 10 ms; the 1000 entries took 10 s.
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := source.PageContext(ctx, 1, "MediaBox"); err != nil {
		t.Fatalf("PageContext() error = %v", err)
	}
}
