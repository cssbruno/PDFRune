// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfverify

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"image"
	"image/png"
	"runtime"
	"testing"
)

func round3PDF(objects ...string) []byte {
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

// Objects were found by a regex over the raw bytes, so a structure tree
// written as text inside an attachment stream made an untagged PDF pass.
func TestInspectTagsReadsTheCatalogsTree(t *testing.T) {
	attachment := "/MarkInfo << /Marked true >>\n" +
		"90 0 obj\n<< /Type /StructTreeRoot /K 91 0 R /ParentTree 92 0 R >>\nendobj\n" +
		"91 0 obj\n<< /Type /StructElem /S /Document /P 90 0 R >>\nendobj\n" +
		"92 0 obj\n<< /Nums [] >>\nendobj\n"
	pdf := round3PDF(
		"<< /Type /Catalog /Pages 2 0 R /Names << /EmbeddedFiles << /Names [(a.pdf) 6 0 R] >> >> >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Contents 4 0 R >>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len("BT ET"), "BT ET"),
		fmt.Sprintf("<< /Type /EmbeddedFile /Length %d >>\nstream\n%s\nendstream", len(attachment), attachment),
		"<< /Type /Filespec /F (a.pdf) /EF << /F 5 0 R >> >>",
	)
	report, err := InspectTags(context.Background(), pdf, TagInspectionLimits{})
	if err != nil {
		t.Fatal(err)
	}
	if report.Passed || report.Marked || report.StructureRoot != 0 {
		t.Fatalf("untagged PDF read as tagged: marked=%v root=%d passed=%v", report.Marked, report.StructureRoot, report.Passed)
	}
}

// png.Decode allocates the image its header declares, so a 142-byte PNG
// declaring 16000x16000 cost 976 MB before the pixel limit was checked.
func TestPNGPixelLimitIsCheckedFromTheHeader(t *testing.T) {
	var encoded bytes.Buffer
	if err := png.Encode(&encoded, image.NewGray(image.Rect(0, 0, 4000, 4000))); err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, err := pngSize(encoded.Bytes(), 1000*1000)
	runtime.ReadMemStats(&after)
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("pngSize() error = %v, want ErrLimit", err)
	}
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 1<<20 {
		t.Fatalf("checking the header allocated %d KB", allocated>>10)
	}
	if size, err := pngSize(encoded.Bytes(), 4000*4000); err != nil || size != (image.Point{X: 4000, Y: 4000}) {
		t.Fatalf("pngSize() = %v, %v", size, err)
	}
}

// The pin was a substring of the version line, so "24.0" accepted 24.02.0
// and the report recorded the pin rather than the binary used.
func TestPopplerVersionIsMatchedExactly(t *testing.T) {
	output := "pdftoppm version 24.02.0\nCopyright 2005-2024 The Poppler Developers\n"
	if got := popplerVersion(output); got != "24.02.0" {
		t.Fatalf("popplerVersion() = %q", got)
	}
	for _, pin := range []string{"24.0", "2", "24.02"} {
		if popplerVersion(output) == pin {
			t.Fatalf("pin %q matched 24.02.0", pin)
		}
	}
}
