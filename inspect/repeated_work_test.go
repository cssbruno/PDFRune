// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

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

func repeatedWorkPDF(objects ...string) []byte {
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

func repeatedWorkStream(dict string, data []byte) string {
	var compressed bytes.Buffer
	w, _ := zlib.NewWriterLevel(&compressed, zlib.BestCompression)
	_, _ = w.Write(data)
	_ = w.Close()
	return fmt.Sprintf("<< %s /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream", dict, compressed.Len(), compressed.Bytes())
}

func textAllocation(t *testing.T, pdf []byte) uint64 {
	t.Helper()
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	if _, err := TextContext(context.Background(), pdf); err != nil {
		t.Fatalf("TextContext() error = %v", err)
	}
	runtime.ReadMemStats(&after)
	return after.TotalAlloc - before.TotalAlloc
}

// A form that inflates one byte past the resource limit fails to decode and
// was inflated again, uncharged, for every Do that drew it.
func TestTextInflatesAFailingFormOnce(t *testing.T) {
	pdf := repeatedWorkPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /XObject << /X 5 0 R >> >> /Contents 4 0 R >>",
		repeatedWorkStream("", bytes.Repeat([]byte("/X Do\n"), 200)),
		repeatedWorkStream("/Type /XObject /Subtype /Form /BBox [0 0 10 10]", bytes.Repeat([]byte{' '}, maxResourceStreamSize+1)),
	)
	if allocated := textAllocation(t, pdf); allocated > 64<<20 {
		t.Fatalf("200 draws of one failing form allocated %d MB", allocated>>20)
	}
}

// A bfrange destination of a megabyte was copied and decoded for every
// glyph shown; destinations past maxCMapTextBytes now map to no text.
func TestTextIgnoresOversizedCMapDestination(t *testing.T) {
	cmap := "begincmap\n1 begincodespacerange <00> <FF> endcodespacerange\n1 beginbfrange\n<00> <FF> <" +
		strings.Repeat("0001", 500000) + ">\nendbfrange\nendcmap\n"
	pdf := repeatedWorkPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		repeatedWorkStream("", []byte("BT /F1 12 Tf 10 10 Td <"+strings.Repeat("41", 200)+"> Tj ET\n")),
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /ToUnicode 6 0 R >>",
		repeatedWorkStream("", []byte(cmap)),
	)
	if allocated := textAllocation(t, pdf); allocated > 64<<20 {
		t.Fatalf("200 glyphs through a 1 MB destination allocated %d MB", allocated>>20)
	}
}

// 65000 codespace ranges that never match were all tried for every glyph,
// about 3 s for 50000 glyphs from a 2 KB file.
func TestTextBoundsCodespaceRanges(t *testing.T) {
	cmap := "begincmap\n65000 begincodespacerange\n" + strings.Repeat("<FF> <FF>\n", 65000) + "endcodespacerange\nendcmap\n"
	pdf := repeatedWorkPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		repeatedWorkStream("", []byte("BT /F1 12 Tf 10 10 Td <"+strings.Repeat("00", 100000)+"> Tj ET\n")),
		"<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /GBK-EUC-H /DescendantFonts [7 0 R] /ToUnicode 6 0 R >>",
		repeatedWorkStream("", []byte(cmap)),
		"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /X >>",
	)
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if _, err := TextContext(ctx, pdf); err != nil {
		t.Fatalf("TextContext() error = %v", err)
	}
}
