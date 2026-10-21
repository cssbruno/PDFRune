// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import (
	"bytes"
	"compress/zlib"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"

	"github.com/cssbruno/pdfrune/importpdf"
	"github.com/cssbruno/pdfrune/pdfcdr"
)

func TestTextDecodesIdentityHThroughToUnicode(t *testing.T) {
	cmap := "/CIDInit /ProcSet findresource begin 12 dict begin begincmap\n" +
		"1 begincodespacerange <0000> <FFFF> endcodespacerange\n" +
		"2 beginbfchar <0001> <0041> <0002> <00E7> endbfchar\n" +
		"1 beginbfrange <0003> <0004> [<00E3> <006F>] endbfrange\n" +
		"endcmap CMapName currentdict /CMap defineresource pop end end"
	data := textTestPage(
		"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Arial /Encoding /Identity-H /DescendantFonts [7 0 R] /ToUnicode 8 0 R >>",
		"BT /F1 12 Tf 72 700 Td <0001000200030004> Tj ET",
		textTestStream("q Q"),
		"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Arial /CIDSystemInfo << /Registry (Adobe) /Ordering (Identity) /Supplement 0 >> >>",
		textTestStream(cmap),
	)
	if got := textTestExtract(t, data); got != "Ação" {
		t.Fatalf("Text() = %q, want %q", got, "Ação")
	}
}

func TestTextToUnicodeRangesSurrogatesLigaturesAndCodeWidths(t *testing.T) {
	cmap := "begincmap\n" +
		"2 begincodespacerange <00> <7F> <8000> <FFFF> endcodespacerange\n" +
		"3 beginbfchar <41> <0041> <8001> <D83DDE00> <8002> <00660069> endbfchar\n" +
		"1 beginbfrange <8010> <8012> <00E1> endbfrange\n" +
		"endcmap"
	font := "<< /Type /Font /Subtype /Type0 /BaseFont /Mixed /Encoding 9 0 R /DescendantFonts [7 0 R] /ToUnicode 8 0 R >>"
	data := textTestPage(font, "BT /F1 12 Tf <41800180028010801180129999> Tj ET",
		textTestStream("q Q"),
		"<< /Type /Font /Subtype /CIDFontType0 /BaseFont /Mixed >>",
		textTestStream(cmap),
		textTestStream("begincmap 2 begincodespacerange <00> <7F> <8000> <FFFF> endcodespacerange endcmap"),
	)
	// <9999> has no mapping and must produce nothing.
	if got, want := textTestExtract(t, data), "A\U0001F600fiáâã"; got != want {
		t.Fatalf("Text() = %q, want %q", got, want)
	}
}

func TestTextIdentityHWithoutToUnicodeEmitsNothing(t *testing.T) {
	data := textTestPage(
		"<< /Type /Font /Subtype /Type0 /BaseFont /AAAAAA+Arial /Encoding /Identity-H /DescendantFonts [7 0 R] >>",
		"BT /F1 12 Tf <00480065006C006C006F> Tj ET",
		textTestStream("q Q"),
		"<< /Type /Font /Subtype /CIDFontType2 /BaseFont /AAAAAA+Arial >>",
	)
	if got := textTestExtract(t, data); got != "" {
		t.Fatalf("Text() = %q, want no text for codes without a Unicode mapping", got)
	}
}

func TestTextAppliesSimpleFontEncodings(t *testing.T) {
	tests := map[string]struct {
		font, content, want string
	}{
		"MacRoman": {
			"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding /MacRomanEncoding >>",
			"BT /F1 12 Tf (A\\215\\213o) Tj ET", "Ação",
		},
		"WinAnsi differences": {
			"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica /Encoding << /Type /Encoding /BaseEncoding /WinAnsiEncoding /Differences [1 /ccedilla /atilde] >> >>",
			"BT /F1 12 Tf (A\\001\\002o) Tj ET", "Ação",
		},
		"glyph name rules": {
			"<< /Type /Font /Subtype /Type1 /BaseFont /ABCDEF+Custom /Encoding << /Differences [1 /uni00E700E3 /u00EA /f_i /a.sc /g31] >> >>",
			"BT /F1 12 Tf (\\001\\002\\003\\004\\005) Tj ET", "çãêfia",
		},
		"ToUnicode wins over Encoding": {
			"<< /Type /Font /Subtype /TrueType /BaseFont /Arial /Encoding /WinAnsiEncoding /ToUnicode 6 0 R >>",
			"BT /F1 12 Tf (ab) Tj ET", "éb",
		},
		"Standard default for Type1": {
			"<< /Type /Font /Subtype /Type1 /BaseFont /Times-Roman >>",
			"BT /F1 12 Tf (\\341\\047\\347) Tj ET", "Æ’ç",
		},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			data := textTestPage(test.font, test.content, textTestStream("1 beginbfchar <61> <00E9> endbfchar"))
			if got := textTestExtract(t, data); got != test.want {
				t.Fatalf("Text() = %q, want %q", got, test.want)
			}
		})
	}
}

func TestTextSeparatesRunsLinesAndPages(t *testing.T) {
	content := "BT /F1 10 Tf 72 700 Td (Hemoglobina) Tj 150 0 Td (13,5) Tj 0 -14 Td (14,0) Tj T* (Leucocitos) Tj (6.200) ' [(12,0)-3000(g/dL)] TJ ET"
	got := textTestExtract(t, textTestPage("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", content, textTestStream("q Q")))
	for _, fused := range []string{"Hemoglobina13,5", "13,514,0", "14,0Leucocitos", "Leucocitos6.200", "12,0g/dL"} {
		if strings.Contains(got, fused) {
			t.Errorf("Text() = %q contains fused run %q", got, fused)
		}
	}
	if !strings.Contains(got, "13,5\n14,0") {
		t.Errorf("Text() = %q, want a line break where the baseline moves down", got)
	}

	pages, err := Text(inspectTestPDF(t))
	if err != nil {
		t.Fatal(err)
	}
	if pages != "Inspect page one\nInspect page two" {
		t.Errorf("Text() = %q, want pages on separate lines", pages)
	}
}

func TestTextUsesGlyphWidthsToFindWordGaps(t *testing.T) {
	// Each glyph is 500/1000 em wide at 10 pt: "Hemo" ends at x=20, so a run
	// at x=20 continues the word and one at x=40 starts a new word.
	font := "<< /Type /Font /Subtype /TrueType /BaseFont /Mono /FirstChar 32 /LastChar 126 /Widths 6 0 R >>"
	content := "BT /F1 10 Tf 0 0 Td (Hemo) Tj 20 0 Td (globina) Tj 1 0 0 1 75 0 Tm (13,5) Tj [(g)-250(/dL)] TJ ET"
	widths := "[" + strings.Repeat("500 ", 95) + "]"
	got := textTestExtract(t, textTestPage(font, content, widths))
	if got != "Hemoglobina 13,5g /dL" {
		t.Fatalf("Text() = %q, want word gaps from glyph widths and TJ adjustments", got)
	}
}

func TestTextIncludesFormXObjectText(t *testing.T) {
	form := "BT /F1 12 Tf 72 700 Td (Hemoglobina 13,5 g/dL) Tj ET /Fm0 Do"
	data := textTestPage("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", "q /Fm0 Do Q /Img Do",
		fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> /XObject << /Fm0 6 0 R >> >> /Length %d >>\nstream\n%s\nendstream", len(form), form))
	if got := textTestExtract(t, data); got != "Hemoglobina 13,5 g/dL" {
		t.Errorf("Text() = %q, want form text once despite the self-reference", got)
	}
	if got := textTestCDRText(t, data); !strings.Contains(got, "Hemoglobina") {
		t.Errorf("Text(after CDR) = %q, want form text", got)
	}
}

func TestTextFormXObjectsAreDepthBounded(t *testing.T) {
	bodies := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Resources << /XObject << /X 5 0 R >> >> /Contents 4 0 R >>",
		textTestStream("/X Do"),
	}
	const forms = maxFormXObjectDepth + 4
	for i := 0; i < forms; i++ {
		content := fmt.Sprintf("BT (L%d) Tj ET /X Do", i)
		next := min(i+6, forms+4)
		bodies = append(bodies, fmt.Sprintf("<< /Subtype /Form /Resources << /XObject << /X %d 0 R >> >> /Length %d >>\nstream\n%s\nendstream", next, len(content), content))
	}
	got := textTestExtract(t, inspectPDFWithBodies(bodies))
	if !strings.Contains(got, "L0") || !strings.Contains(got, fmt.Sprintf("L%d", maxFormXObjectDepth-1)) || strings.Contains(got, fmt.Sprintf("L%d", maxFormXObjectDepth)) {
		t.Fatalf("Text() = %q, want forms up to depth %d", got, maxFormXObjectDepth)
	}
}

func TestTextDecodesFlateToUnicodeAndForms(t *testing.T) {
	var cmap, form bytes.Buffer
	for buffer, text := range map[*bytes.Buffer]string{
		&cmap: "1 beginbfchar <01> <00E7> endbfchar",
		&form: "BT /F1 12 Tf (\\001) Tj ET",
	} {
		writer := zlib.NewWriter(buffer)
		_, _ = writer.Write([]byte(text))
		_ = writer.Close()
	}
	data := textTestPage("<< /Type /Font /Subtype /TrueType /BaseFont /X /ToUnicode 7 0 R >>", "/Fm0 Do",
		fmt.Sprintf("<< /Subtype /Form /Filter /FlateDecode /Resources << /Font << /F1 5 0 R >> >> /Length %d >>\nstream\n%s\nendstream", form.Len(), form.String()),
		fmt.Sprintf("<< /Filter /FlateDecode /Length %d >>\nstream\n%s\nendstream", cmap.Len(), cmap.String()),
	)
	if got := textTestExtract(t, data); got != "ç" {
		t.Fatalf("Text() = %q, want Flate-decoded form and ToUnicode", got)
	}
}

func TestTextDecodesProducerFixtures(t *testing.T) {
	words := []string{"Hemograma", "Maria Sintética", "Hemoglobina", "13,8 g/dL", "Leucócitos", "6.200", "µL", "Ação, coração, ênfase", "acentuação", "≤", "≥", "±"}
	fixtures, err := filepath.Glob(filepath.Join("testdata", "synthetic-lab-report-*.pdf"))
	if err != nil || len(fixtures) == 0 {
		t.Fatalf("fixtures = %v, %v", fixtures, err)
	}
	for _, fixture := range fixtures {
		t.Run(filepath.Base(fixture), func(t *testing.T) {
			data, err := os.ReadFile(fixture)
			if err != nil {
				t.Fatal(err)
			}
			for name, text := range map[string]string{"original": textTestExtract(t, data), "after CDR": textTestCDRText(t, data)} {
				for _, word := range words {
					if !strings.Contains(text, word) {
						t.Errorf("%s: Text() lacks %q; got %q", name, word, text)
					}
				}
			}
		})
	}
}

func TestTextContinuesAfterInlineImageFollowedByOperand(t *testing.T) {
	content := "BT /F1 12 Tf (Hemoglobina 13,5) Tj ET q 10 0 0 10 0 0 cm BI /W 2 /H 1 /CS /G /BPC 8 ID \xff\x00 EI 0 g Q BT /F1 12 Tf (Leucocitos) Tj ET"
	data := textTestPage("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", content, textTestStream("q Q"))
	if got := textTestExtract(t, data); !strings.Contains(got, "Leucocitos") {
		t.Errorf("Text() = %q, want text after the inline image", got)
	}
	if got := textTestCDRText(t, data); !strings.Contains(got, "Leucocitos") {
		t.Errorf("Text(after CDR) = %q, want text after the inline image", got)
	}
}

func TestTextInlineImageHonorsAbbreviatedLength(t *testing.T) {
	// Without /L the scan would stop at the first EI and show "(x)".
	stream := []byte("BT (before) Tj BI /W 9 /H 1 /L 9 ID EI (x) Tj EI 0 -20 Td (after) Tj ET")
	text, err := textFromContentStreamContext(context.Background(), stream)
	if err != nil {
		t.Fatal(err)
	}
	if text != "before\nafter" {
		t.Fatalf("text = %q, want /L to skip image data containing EI", text)
	}
}

func TestTextKeepsTextBeforeUnterminatedInlineImage(t *testing.T) {
	stream := []byte("BT (kept) Tj ET BI /W 1 /H 1 ID \x00\x01 BT (lost) Tj ET")
	text, err := textFromContentStreamContext(context.Background(), stream)
	if err != nil {
		t.Fatalf("error = %v, want the stream to end at the broken inline image", err)
	}
	if text != "kept" {
		t.Fatalf("text = %q, want text before the inline image only", text)
	}
}

func TestFirstPageSizePointsReadsInheritedIndirectAndUserUnit(t *testing.T) {
	tests := map[string]struct {
		bodies        []string
		width, height float64
	}{
		"inherited": {[]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 /MediaBox [0 0 595 842] >>",
			"<< /Type /Page /Parent 2 0 R /Resources <<>> /Contents 4 0 R >>",
			textTestStream("q Q"),
		}, 595, 842},
		"indirect": {[]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox 5 0 R /Resources <<>> /Contents 4 0 R >>",
			textTestStream("q Q"),
			"[0 0 595 842]",
		}, 595, 842},
		"UserUnit": {[]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 300 400] /UserUnit 2 /Rotate 90 /Resources <<>> /Contents 4 0 R >>",
			textTestStream("q Q"),
		}, 600, 800},
	}
	for name, test := range tests {
		t.Run(name, func(t *testing.T) {
			width, height, err := FirstPageSizePoints(inspectPDFWithBodies(test.bodies))
			if err != nil || width != test.width || height != test.height {
				t.Fatalf("FirstPageSizePoints() = %v, %v, %v; want %v, %v", width, height, err, test.width, test.height)
			}
		})
	}
}

func TestHexStringAllocationIsLinear(t *testing.T) {
	for _, n := range []int{10_000, 40_000} {
		content := []byte("BT /F1 12 Tf " + strings.Repeat("[<0012>-3<0034>] TJ ", n) + "ET")
		var before, after runtime.MemStats
		runtime.GC()
		runtime.ReadMemStats(&before)
		if _, err := textFromContentStreamContext(context.Background(), content); err != nil {
			t.Fatal(err)
		}
		runtime.ReadMemStats(&after)
		if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(len(content))*64 {
			t.Errorf("allocated %d bytes for a %d-byte stream (>64x)", allocated, len(content))
		}
	}
}

func TestTextThroughCDRWithManyHexStringsAllocatesLinearly(t *testing.T) {
	content := "BT /F1 12 Tf " + strings.Repeat("[<0012>-3<0034>] TJ ", 100_000) + "ET"
	data := textTestPage("<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>", content, textTestStream("q Q"))
	clean, err := pdfcdr.Sanitize(data)
	if err != nil {
		t.Fatal(err)
	}
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := Text(clean); err != nil {
		t.Fatal(err)
	}
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > uint64(len(content))*64 {
		t.Errorf("Text allocated %d bytes for a %d-byte content stream (>64x)", allocated, len(content))
	}
}

// textTestPage builds a one-page PDF whose /F1 font is object 5 and whose
// /Fm0 XObject is object 6; extra bodies start at object 6.
func textTestPage(fontDict, content string, extra ...string) []byte {
	bodies := []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 595 842] /Resources << /Font << /F1 5 0 R >> /XObject << /Fm0 6 0 R >> >> /Contents 4 0 R >>",
		textTestStream(content),
		fontDict,
	}
	return inspectPDFWithBodies(append(bodies, extra...))
}

func textTestStream(content string) string {
	return fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content)
}

func textTestExtract(t *testing.T, data []byte) string {
	t.Helper()
	text, err := Text(data)
	if err != nil {
		t.Fatalf("Text() error = %v", err)
	}
	return text
}

func textTestCDRText(t *testing.T, data []byte) string {
	t.Helper()
	source, err := importpdf.OpenBytesImmutableWithOptionsContext(context.Background(), data, importpdf.ImportOptions{})
	if err != nil {
		t.Fatalf("import: %v", err)
	}
	clean, err := pdfcdr.SanitizeContext(context.Background(), source, pdfcdr.Options{})
	if err != nil {
		t.Fatalf("cdr: %v", err)
	}
	return textTestExtract(t, clean)
}
