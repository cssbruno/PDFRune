package importpdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"testing"
	"time"
)

// buildClassic writes bodies as objects 1..n with a classic xref table.
func buildClassic(bodies []string) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	offsets := make([]int, len(bodies)+1)
	for i, body := range bodies {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f \n", len(offsets))
	for _, offset := range offsets[1:] {
		fmt.Fprintf(&out, "%010d 00000 n \n", offset)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", len(offsets), xref)
	return out.Bytes()
}

// buildXrefStream writes bodies as objects 1..n and an uncompressed xref
// stream; extra adds raw type-1 entries (object number -> offset).
func buildXrefStream(bodies []string, extra map[int]int) []byte {
	var out bytes.Buffer
	out.WriteString("%PDF-1.5\n")
	offsets := map[int]int{}
	for i, body := range bodies {
		offsets[i+1] = out.Len()
		fmt.Fprintf(&out, "%d 0 obj\n%s\nendobj\n", i+1, body)
	}
	for k, v := range extra {
		offsets[k] = v
	}
	self := len(bodies) + 1
	for k := range offsets {
		if k >= self {
			self = k + 1
		}
	}
	xrefPos := out.Len()
	offsets[self] = xrefPos
	var rows bytes.Buffer
	for n := 0; n <= self; n++ {
		off, ok := offsets[n]
		if !ok {
			rows.Write([]byte{0, 0, 0, 0, 0, 0xff, 0xff})
			continue
		}
		rows.Write([]byte{1, byte(off >> 24), byte(off >> 16), byte(off >> 8), byte(off), 0, 0})
	}
	fmt.Fprintf(&out, "%d 0 obj\n<< /Type /XRef /Size %d /W [1 4 2] /Root 1 0 R /Length %d >>\nstream\n", self, self+1, rows.Len())
	out.Write(rows.Bytes())
	fmt.Fprintf(&out, "\nendstream\nendobj\nstartxref\n%d\n%%%%EOF\n", xrefPos)
	return out.Bytes()
}

func standardBodies(pageExtra string, content string) []string {
	return []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources <<>> /Contents 4 0 R " + pageExtra + ">>",
		fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content), content),
	}
}

// readerAtObjectBodyContext never reaches an odd limit and loops forever.
func TestReaderAtReturnsForAnUnterminatedObjectWithOddRemainder(t *testing.T) {
	var out bytes.Buffer
	out.WriteString("%PDF-1.4\n")
	off1 := out.Len()
	out.WriteString("1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	off2 := out.Len()
	// Page tree node without endobj, followed by ~150 KB of comment lines.
	out.WriteString("2 0 obj\n<< /Type /Pages /Kids [] /Count 0 >>\n")
	for out.Len()-off2 < 150000 {
		out.WriteString("% padding padding padding padding padding padding padding padding\n")
	}
	xref := out.Len()
	fmt.Fprintf(&out, "xref\n0 3\n0000000000 65535 f \n%010d 00000 n \n%010d 00000 n \ntrailer\n<< /Size 3 /Root 1 0 R >>\nstartxref\n%d\n%%%%EOF\n", off1, off2, xref)
	if (out.Len()-off2)%2 == 0 {
		// make the remainder odd: one extra byte before startxref's EOF
		out.WriteString("\n")
	}
	data := out.Bytes()
	t.Logf("remainder from object 2 = %d", len(data)-off2)
	done := make(chan error, 1)
	go func() {
		_, err := OpenReaderAt(bytes.NewReader(data), int64(len(data)))
		done <- err
	}()
	select {
	case err := <-done:
		t.Logf("returned: %v", err)
	case <-time.After(5 * time.Second):
		t.Fatal("OpenReaderAt did not return within 5s (infinite loop in readerAtObjectBodyContext)")
	}
}

// every nesting level copies the raw bytes of its whole subtree.
func TestNestedValuesDoNotCopyTheirRawBytesPerLevel(t *testing.T) {
	const depth = 120
	big := strings.Repeat("A", 1<<20)
	body := "<< /Type /Catalog /Pages 2 0 R /X " + strings.Repeat("[", depth) + "(" + big + ")" + strings.Repeat("]", depth) + " >>"
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	dict, err := parsePDFObjectDictContext(context.Background(), []byte(body))
	runtime.GC()
	runtime.ReadMemStats(&after)
	runtime.KeepAlive(dict)
	if err != nil {
		t.Fatal(err)
	}
	live := int64(after.HeapAlloc) - int64(before.HeapAlloc)
	t.Logf("input %d bytes, live heap after parse %d bytes (x%.0f)", len(body), live, float64(live)/float64(len(body)))
	if live > 10*int64(len(body)) {
		t.Fatalf("parsing a %d-byte dictionary retains %d bytes", len(body), live)
	}
}

// V4 /Length is optional (key length comes from the crypt filter), but
// the code falls back to 40 bits and the correct password is rejected.
func TestV4AESWithoutTopLevelLengthUses128Bits(t *testing.T) {
	data, err := os.ReadFile("testdata/aes-128-user.pdf")
	if err != nil {
		t.Fatal(err)
	}
	mod := bytes.Replace(data, []byte("/Length 128\n"), []byte("%Length 128\n"), 1)
	if bytes.Equal(mod, data) {
		t.Fatal("fixture changed")
	}
	if _, err := OpenBytesWithOptions(mod, ImportOptions{Password: "senha"}); err != nil {
		t.Fatalf("V4 AESV2 without top-level /Length: %v", err)
	}
}

// /Contents may be an indirect reference to an array of streams.
func TestContentsMayBeAnIndirectArray(t *testing.T) {
	data := buildClassic([]string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources <<>> /Contents 4 0 R >>",
		"[5 0 R]",
		"<< /Length 23 >>\nstream\n0 0 1 rg 0 0 100 100 re\nendstream",
	})
	src, err := OpenBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	page, err := src.Page(1, "MediaBox")
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if c, err := page.ContentWithError(); err != nil || !bytes.Contains(c, []byte("re")) {
		t.Fatalf("content = %q, %v", c, err)
	}
}

// page attributes given as indirect objects (MediaBox, Kids) are rejected.
func TestPageTreeEntriesMayBeIndirect(t *testing.T) {
	t.Run("MediaBox", func(t *testing.T) {
		data := buildClassic([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox 5 0 R /Resources <<>> /Contents 4 0 R >>",
			"<< /Length 0 >>\nstream\n\nendstream",
			"[0 0 612 792]",
		})
		src, err := OpenBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := src.Page(1, "MediaBox"); err != nil {
			t.Fatalf("Page: %v", err)
		}
	})
	t.Run("Kids", func(t *testing.T) {
		data := buildClassic([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids 5 0 R /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources <<>> /Contents 4 0 R >>",
			"<< /Length 0 >>\nstream\n\nendstream",
			"[3 0 R]",
		})
		if _, err := OpenBytes(data); err != nil {
			t.Fatalf("Open: %v", err)
		}
	})
}

// the hidden XRefStm stream's own /Prev must be ignored; following it
// revisits the same section and aborts with "cyclic xref chain".
func TestHybridXRefStmPrevIsIgnored(t *testing.T) {
	for _, withPrev := range []bool{false, true} {
		base := minimalImportPDF() // classic xref at 265
		var out bytes.Buffer
		out.Write(base)
		off5 := out.Len()
		objstm := "6 0 << /Updated true >>"
		fmt.Fprintf(&out, "5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Length %d >>\nstream\n%s\nendstream\nendobj\n", len(objstm), objstm)
		off7 := out.Len()
		var rows bytes.Buffer
		row := func(t byte, a, b int) {
			rows.Write([]byte{t, byte(a >> 24), byte(a >> 16), byte(a >> 8), byte(a), byte(b >> 8), byte(b)})
		}
		row(1, off5, 0)
		row(2, 5, 0)
		row(1, off7, 0)
		prev := ""
		if withPrev {
			prev = " /Prev 265"
		}
		fmt.Fprintf(&out, "7 0 obj\n<< /Type /XRef /Size 8 /Index [5 3] /W [1 4 2]%s /Length %d >>\nstream\n", prev, rows.Len())
		out.Write(rows.Bytes())
		out.WriteString("\nendstream\nendobj\n")
		xref := out.Len()
		fmt.Fprintf(&out, "xref\n0 1\n0000000000 65535 f \ntrailer\n<< /Size 8 /Root 1 0 R /Prev 265 /XRefStm %d >>\nstartxref\n%d\n%%%%EOF\n", off7, xref)
		if _, err := OpenBytes(out.Bytes()); err != nil {
			t.Errorf("withPrev=%v: %v", withPrev, err)
		}
	}
}

// an xref subsection header with trailing whitespace ("0 5 \n").
func TestXrefSubsectionHeaderMayEndWithSpace(t *testing.T) {
	data := bytes.Replace(minimalImportPDF(), []byte("xref\n0 5\n"), []byte("xref\n0 5 \n"), 1)
	if _, err := OpenBytes(data); err != nil {
		t.Fatalf("Open: %v", err)
	}
}

// no recovery when offsets or /Length are slightly wrong.
func TestRecoversFromConvertedLineEndsAndShortLength(t *testing.T) {
	t.Run("crlf-converted", func(t *testing.T) {
		data := bytes.ReplaceAll(buildClassic(standardBodies("", "0 0 1 rg 0 0 5 5 re f")), []byte("\n"), []byte("\r\n"))
		if _, err := OpenBytes(data); err != nil {
			t.Errorf("LF->CRLF converted file: %v", err)
		}
	})
	t.Run("length-short", func(t *testing.T) {
		content := "0 0 1 rg 0 0 5 5 re f"
		data := buildClassic([]string{
			"<< /Type /Catalog /Pages 2 0 R >>",
			"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
			"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources <<>> /Contents 4 0 R >>",
			fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(content)-2, content),
		})
		src, err := OpenBytes(data)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := src.Page(1, "MediaBox"); err != nil {
			t.Errorf("Page with /Length 2 bytes short: %v", err)
		}
	})
}

// normalization materializes every xref entry, so one dangling entry
// that nothing references aborts an xref-stream/encrypted import, while the
// same file with a classic table imports fine.
func TestNormalizationSkipsAnUnreferencedBrokenEntry(t *testing.T) {
	bodies := standardBodies("", "0 0 1 rg 0 0 5 5 re f")
	classic := buildClassic(append(bodies, "<< /Unused true >>"))
	// object 5 entry points at offset 0 (the header), as broken writers emit.
	classic = bytes.Replace(classic, []byte(fmt.Sprintf("%010d 00000 n \ntrailer", bytes.Index(classic, []byte("5 0 obj")))), []byte("0000000000 00000 n \ntrailer"), 1)
	if _, err := OpenBytes(classic); err != nil {
		t.Fatalf("classic control: %v", err)
	}
	stream := buildXrefStream(bodies, map[int]int{5: 0})
	if _, err := OpenBytes(stream); err != nil {
		t.Fatalf("xref-stream file with an unreferenced dangling entry: %v", err)
	}
}

// TrimBox/BleedBox/ArtBox default to the CropBox, not the MediaBox.
func TestTrimBoxDefaultsToCropBox(t *testing.T) {
	data := buildClassic(standardBodies("/CropBox [50 50 550 750] ", ""))
	src, err := OpenBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	page, err := src.Page(1, "TrimBox")
	if err != nil {
		t.Fatal(err)
	}
	if page.WidthPoints() != 500 || page.HeightPoints() != 700 {
		t.Fatalf("TrimBox size = %vx%v, want CropBox 500x700", page.WidthPoints(), page.HeightPoints())
	}
}

func TestOpenBytesDoesNotAmplifyNestedValues(t *testing.T) {
	big := strings.Repeat("A", 4<<20)
	data := buildClassic(standardBodies("/X "+strings.Repeat("[", 120)+"("+big+")"+strings.Repeat("]", 120)+" ", ""))
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	_, err := OpenBytes(data)
	runtime.ReadMemStats(&after)
	t.Logf("file %d bytes, err=%v, TotalAlloc during OpenBytes = %d MB", len(data), err, (after.TotalAlloc-before.TotalAlloc)>>20)
	if after.TotalAlloc-before.TotalAlloc > uint64(20*len(data)) {
		t.Fatal("allocation amplification")
	}
}

// insertAfterHeader adds a comment line after the header line, which moves
// every object without updating any offset.
func insertAfterHeader(data []byte) []byte {
	eol := bytes.IndexByte(data, '\n') + 1
	out := append([]byte{}, data[:eol]...)
	out = append(out, []byte("% inserted after writing, so every offset is stale\n")...)
	return append(out, data[eol:]...)
}

func TestReconstructsFilesWithStaleOffsets(t *testing.T) {
	for _, name := range []string{"xref-stream.pdf", "pypdf-incremental-on-xref-stream.pdf", "base.pdf"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		source, err := OpenBytes(insertAfterHeader(data))
		if err != nil {
			t.Fatalf("%s with stale offsets: %v", name, err)
		}
		if _, err := source.Page(1, "MediaBox"); err != nil {
			t.Fatalf("%s page: %v", name, err)
		}
	}
}

func TestReconstructsAnEncryptedFileWithStaleOffsets(t *testing.T) {
	data, err := os.ReadFile("testdata/aes-128-user.pdf")
	if err != nil {
		t.Fatal(err)
	}
	damaged := insertAfterHeader(data)
	if _, err := OpenBytes(damaged); !errors.Is(err, ErrPasswordRequired) {
		t.Fatalf("without password: %v, want ErrPasswordRequired", err)
	}
	if _, err := OpenBytesWithOptions(damaged, ImportOptions{Password: "senha"}); err != nil {
		t.Fatalf("with password: %v", err)
	}
}

func TestReconstructsAFileWithoutStartxref(t *testing.T) {
	data := buildClassic(standardBodies("", "0 0 1 rg 0 0 5 5 re f"))
	cut := bytes.LastIndex(data, []byte("startxref"))
	if _, err := OpenBytes(data[:cut]); err != nil {
		t.Fatalf("file cut before startxref: %v", err)
	}
}

func TestRecoversOneObjectWhoseOffsetIsWrong(t *testing.T) {
	data := buildClassic(standardBodies("", "0 0 1 rg 0 0 5 5 re f"))
	// Point the content stream entry at the page object instead.
	page := bytes.Index(data, []byte("3 0 obj"))
	content := bytes.Index(data, []byte("4 0 obj"))
	data = bytes.Replace(data, []byte(fmt.Sprintf("%010d 00000 n", content)), []byte(fmt.Sprintf("%010d 00000 n", page)), 1)
	source, err := OpenBytes(data)
	if err != nil {
		t.Fatal(err)
	}
	page1, err := source.Page(1, "MediaBox")
	if err != nil {
		t.Fatalf("Page: %v", err)
	}
	if c, err := page1.ContentWithError(); err != nil || !bytes.Contains(c, []byte("re f")) {
		t.Fatalf("content = %q, %v", c, err)
	}
}

func TestReconstructionOfHeadersWithoutEndsStaysLinear(t *testing.T) {
	var data bytes.Buffer
	data.WriteString("%PDF-1.4\n")
	for data.Len() < 4<<20 {
		data.WriteString("1 0 obj\n<< /A 1 >>\n")
	}
	start := time.Now()
	if _, err := OpenBytes(data.Bytes()); err == nil {
		t.Fatal("a file with no catalog was accepted")
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("reconstruction took %v", elapsed)
	}
}

func TestReconstructionDoesNotReadAFileWithoutAHeader(t *testing.T) {
	data := buildClassic(standardBodies("", ""))
	data = bytes.Replace(data, []byte("%PDF-1.4"), []byte("%XYZ-1.4"), 1)
	if _, err := OpenBytes(insertAfterHeader(data)); err == nil {
		t.Fatal("a damaged file without a PDF header was rebuilt")
	}
}

func TestReconstructionKeepsTheLatestRevision(t *testing.T) {
	for _, name := range []string{"xref-stream.pdf", "pypdf-incremental-on-xref-stream.pdf", "rc4-128-user.pdf"} {
		data, err := os.ReadFile("testdata/" + name)
		if err != nil {
			t.Fatal(err)
		}
		options := ImportOptions{Password: "senha"}
		want, err := OpenBytesWithOptions(data, options)
		if err != nil {
			t.Fatal(err)
		}
		got, err := OpenBytesWithOptions(insertAfterHeader(data), options)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		if got.PageCount() != want.PageCount() {
			t.Fatalf("%s: %d pages, want %d", name, got.PageCount(), want.PageCount())
		}
		for n := 1; n <= want.PageCount(); n++ {
			wantPage, _ := want.Page(n, "MediaBox")
			gotPage, err := got.Page(n, "MediaBox")
			if err != nil {
				t.Fatalf("%s page %d: %v", name, n, err)
			}
			wantContent, _ := wantPage.ContentWithError()
			gotContent, _ := gotPage.ContentWithError()
			if !bytes.Equal(gotContent, wantContent) || !bytes.Equal(gotPage.Resources(), wantPage.Resources()) {
				t.Fatalf("%s page %d differs after reconstruction", name, n)
			}
		}
	}
}

func TestReconstructionIgnoresHugeObjectNumbers(t *testing.T) {
	data := []byte("%PDF-1.4\n300000000000 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\n")
	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = OpenBytes(data)
	runtime.ReadMemStats(&after)
	if after.TotalAlloc-before.TotalAlloc > 64<<20 {
		t.Fatalf("reconstruction allocated %d MB", (after.TotalAlloc-before.TotalAlloc)>>20)
	}
}
