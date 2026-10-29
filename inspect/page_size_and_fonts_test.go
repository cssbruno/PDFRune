// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import (
	"fmt"
	"strings"
	"testing"
	"time"
)

// /UserUnit was read from every object typed /Catalog, so an unreferenced
// one (common in merged files) changed the size, and thousands of decoy
// catalogs each walked a page tree (4.6 s for 716 KB, not cancellable).
func TestFirstPageSizeComesFromTheTrailerRootPage(t *testing.T) {
	base := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 300] /UserUnit 2 /Contents 4 0 R >>",
		repeatedWorkStream("", []byte("BT ET")),
	}
	orphan := append(append([]string(nil), base...),
		"<< /Type /Catalog /Pages 6 0 R >>",
		"<< /Type /Pages /Kids [7 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 6 0 R /MediaBox [0 0 1 1] /UserUnit 5 /Contents 4 0 R >>",
	)
	if w, h, err := FirstPageSizePoints(repeatedWorkPDF(orphan...)); err != nil || w != 400 || h != 600 {
		t.Fatalf("FirstPageSizePoints() = %vx%v, %v; want 400x600", w, h, err)
	}

	decoys := append([]string(nil), base...)
	var kids strings.Builder
	for i := 0; i < 3000; i++ {
		fmt.Fprintf(&kids, "%d 0 R ", 6+3000+i)
	}
	for i := 0; i < 3000; i++ {
		decoys = append(decoys, "<< /Type /Catalog /Pages 5 0 R >>")
	}
	decoys = append(decoys[:4], append([]string{"<< /Type /Pages /Kids [" + kids.String() + "] >>"}, decoys[4:]...)...)
	for i := 0; i < 3000; i++ {
		decoys = append(decoys, "<< /Type /Pages /Kids [] >>")
	}
	start := time.Now()
	if w, h, err := FirstPageSizePoints(repeatedWorkPDF(decoys...)); err != nil || w != 400 || h != 600 {
		t.Fatalf("FirstPageSizePoints(decoys) = %vx%v, %v", w, h, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("3000 decoy catalogs took %v", elapsed)
	}
}

// A font written inside /Resources rather than as an indirect object was
// rebuilt on every Tf, 3.7 ms each for 60000 CID widths.
func TestDirectFontsAreBuiltOnce(t *testing.T) {
	var widths strings.Builder
	widths.WriteString("[")
	for i := 0; i < 6; i++ {
		fmt.Fprintf(&widths, " %d [%s]", i*10000, strings.TrimSpace(strings.Repeat("500 ", 10000)))
	}
	widths.WriteString("]")
	font := "<< /Type /Font /Subtype /Type0 /BaseFont /X /Encoding /Identity-H /DescendantFonts [ << /Type /Font /Subtype /CIDFontType2 /BaseFont /X /W 5 0 R >> ] >>"
	pdf := repeatedWorkPDF(
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 200 200] /Resources << /Font << /F1 "+font+" >> >> /Contents 4 0 R >>",
		repeatedWorkStream("", []byte("BT\n"+strings.Repeat("/F1 1 Tf\n", 2000)+"<0041> Tj ET\n")),
		widths.String(),
	)
	start := time.Now()
	if _, err := Text(pdf); err != nil {
		t.Fatal(err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Fatalf("2000 Tf of a direct font took %v", elapsed)
	}
}
