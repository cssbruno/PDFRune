package pdfcdr

import (
	"bytes"
	"os"
	"testing"
)

// an object reached through a pattern's /Shading entry is
// sanitized as a resource-name map (preserveKeys=true), so the external-stream
// and removed-key policy is skipped for a real, rendered shading stream.
func TestPatternShadingIsSanitizedAsAnObject(t *testing.T) {
	source := resourceGraphPDF(t,
		"<< /Pattern << /P0 5 0 R >> >>",
		"<< /Type /Pattern /PatternType 2 /Shading 6 0 R >>",
		"<< /ShadingType 4 /ColorSpace /DeviceRGB /BitsPerCoordinate 8 /BitsPerComponent 8 /BitsPerFlag 8 /Decode [0 1 0 1 0 1 0 1 0 1]"+
			" /F (\\\\\\\\attacker.test\\\\share\\\\x.bin) /FFilter /FlateDecode /OpenAction (x) /JS (app.alert(1)) /Length 0 >>\nstream\n\nendstream",
	)
	clean, err := Sanitize(source)
	if err != nil {
		return // refusing the document is an acceptable outcome
	}
	for _, tok := range []string{"attacker.test", "/FFilter", "/JS", "/OpenAction"} {
		if bytes.Contains(clean, []byte(tok)) {
			t.Errorf("output retains %s", tok)
		}
	}
}

// Ghostscript emits a shading both in the page
// /Shading map and as a pattern's /Shading. With an indirect /ColorSpace the
// two roles classify the child differently and the document is rejected.
func TestShadingSharedByMapAndPatternIsAccepted(t *testing.T) {
	source := resourceGraphPDF(t,
		"<< /Pattern << /P0 5 0 R >> /Shading << /Sh0 6 0 R >> >>",
		"<< /PatternType 2 /Shading 6 0 R >>",
		"<< /ShadingType 2 /ColorSpace 7 0 R /Coords [0 0 100 0] /Function << /FunctionType 2 /Domain [0 1] /C0 [0] /C1 [1] /N 1 >> >>",
		"[/ICCBased 8 0 R]",
		"<< /N 1 /Length 0 >>\nstream\n\nendstream",
	)
	if _, err := Sanitize(source); err != nil {
		t.Fatalf("Sanitize() rejected a legitimate shared shading: %v", err)
	}
}

func TestGhostscriptSharedShadingIsAccepted(t *testing.T) {
	// Ghostscript 10.06 pdfwrite output of a Separation shading painted with
	// shfill and through makepattern: both reach the same shading object.
	data, err := os.ReadFile("testdata/ghostscript-shared-shading.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Sanitize(data); err != nil {
		t.Fatalf("Sanitize(gs output) = %v", err)
	}
}

// a PostScript form XObject marked with /Subtype2 /PS is
// retained; only /Subtype /PS is rejected.
func TestSubtype2PostScriptXObjectIsNotRetained(t *testing.T) {
	source := activeResourcePDF(t, "<< /Type /XObject /Subtype /Form /Subtype2 /PS /BBox [0 0 10 10] /Length 9 >>\nstream\nshowpage\n\nendstream")
	clean, err := Sanitize(source)
	if err != nil {
		return // refusing the document is an acceptable outcome
	}
	if bytes.Contains(clean, []byte("/PS")) {
		t.Fatalf("output retains a PostScript form XObject marker")
	}
}

// OPI proxies (prepress) are rejected outright instead of dropping /OPI.
func TestOPIProxyIsDroppedNotRejected(t *testing.T) {
	source := activeResourcePDF(t, "<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /OPI << /2.0 << /Type /OPI /Version 2.0 /F (hires.tif) /Inks /full_color >> >> /Length 0 >>\nstream\n\nendstream")
	clean, err := Sanitize(source)
	if err != nil {
		t.Fatalf("Sanitize() rejected a form XObject with an OPI proxy: %v", err)
	}
	if bytes.Contains(clean, []byte("hires.tif")) {
		t.Fatal("OPI external reference retained")
	}
}

// the role recorded for an object referenced in both
// roles depends on map iteration order, and that role is part of the
// deduplication key, so identical input yields different output bytes.
func TestOutputIsDeterministicForRoleIndependentObjects(t *testing.T) {
	source := resourceGraphPDF(t,
		"<< /XObject << /A 5 0 R /B 6 0 R >> /ColorSpace << /CS1 8 0 R >> >>",
		"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace 7 0 R /Length 1 >>\nstream\n\x00\nendstream",
		"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace [/Indexed 7 0 R 0 <00>] /Length 1 >>\nstream\n\x00\nendstream",
		"[/ICCBased 9 0 R]",
		"[/ICCBased 9 0 R]",
		"<< /N 1 /Length 0 >>\nstream\n\nendstream",
	)
	first, err := Sanitize(source)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 200; i++ {
		next, err := Sanitize(source)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(first, next) {
			t.Fatalf("run %d produced different output (%d vs %d bytes)", i, len(first), len(next))
		}
	}
}

func TestWrongResourceStreamLengthIsRepaired(t *testing.T) {
	for name, body := range map[string]string{
		"short": "<< /Type /XObject /Subtype /Image /Width 2 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length 1 >>\nstream\n\x00\x00\nendstream",
		"long":  "<< /Type /XObject /Subtype /Image /Width 2 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length 4 >>\nstream\n\x00\x00\nendstream",
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := Sanitize(activeResourcePDF(t, body)); err != nil {
				t.Errorf("Sanitize() = %v", err)
			}
		})
	}
}

func TestWrongContentStreamLengthIsRepaired(t *testing.T) {
	builder := &pdfBuilder{}
	for i := 0; i < 4; i++ {
		builder.reserve()
	}
	builder.set(1, []byte("<< /Type /Catalog /Pages 2 0 R >>"))
	builder.set(2, []byte("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"))
	builder.set(3, []byte("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 100 100] /Contents 4 0 R >>"))
	builder.set(4, []byte("<< /Length 5 >>\nstream\n0 0 10 10 re f\nendstream"))
	data, _ := builder.bytes(nil, 1)
	if _, err := Sanitize(data); err != nil {
		t.Errorf("Sanitize() = %v", err)
	}
}

func TestIndirectLengthWithoutEOLBeforeEndstream(t *testing.T) {
	source := resourceGraphPDF(t,
		"<< /XObject << /Im0 5 0 R >> >>",
		"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length 6 0 R >>\nstream\n\xffendstream",
		"1",
	)
	if _, err := Sanitize(source); err != nil {
		t.Fatalf("Sanitize() = %v", err)
	}
}

func TestIndirectLengthMismatchIsNotCopiedToOutput(t *testing.T) {
	source := resourceGraphPDF(t,
		"<< /XObject << /Im0 5 0 R >> >>",
		"<< /Type /XObject /Subtype /Image /Width 1 /Height 1 /BitsPerComponent 8 /ColorSpace /DeviceGray /Length 6 0 R >>\nstream\nABCDEFGH\nendstream",
		"500",
	)
	clean, err := Sanitize(source)
	if err != nil {
		return // refusing the document is an acceptable outcome
	}
	if bytes.Contains(clean, []byte("\n500\n")) {
		t.Fatal("output stream declares /Length 500 for 8 data bytes")
	}
}

func TestPatternShadingDictionaryGetsTheFullPolicy(t *testing.T) {
	for name, pattern := range map[string][]string{
		"direct": {
			"<< /Type /Pattern /PatternType 2 /Shading << /ShadingType 2 /ColorSpace /DeviceGray /Coords [0 0 1 0] /Function << /FunctionType 2 /Domain [0 1] /C0 [0] /C1 [1] /N 1 >> /JS (app.alert(1)) /URI (https://attacker.test) >> >>",
		},
		"indirect dictionary": {
			"<< /Type /Pattern /PatternType 2 /Shading 6 0 R >>",
			"<< /ShadingType 2 /ColorSpace /DeviceGray /Coords [0 0 1 0] /Function << /FunctionType 2 /Domain [0 1] /C0 [0] /C1 [1] /N 1 >> /JS (app.alert(1)) /URI (https://attacker.test) >>",
		},
	} {
		t.Run(name, func(t *testing.T) {
			source := resourceGraphPDF(t, "<< /Pattern << /P0 5 0 R >> >>", pattern...)
			clean, err := Sanitize(source)
			if err != nil {
				return // refusing the document is an acceptable outcome
			}
			for _, token := range []string{"/JS", "app.alert", "/URI", "attacker.test"} {
				if bytes.Contains(clean, []byte(token)) {
					t.Errorf("output retains %s", token)
				}
			}
			if !bytes.Contains(clean, []byte("/ShadingType 2")) {
				t.Error("the shading itself was lost")
			}
		})
	}
}

func TestResourcesNamedLikeStructuralKeysAreKept(t *testing.T) {
	source := resourceGraphPDF(t,
		"<< /XObject 5 0 R /ExtGState << /A << /CA 0.5 >> /F << /ca 0.5 >> >> >>",
		"<< /A 6 0 R /JS 6 0 R >>",
		"<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Length 0 >>\nstream\n\nendstream",
	)
	clean, err := Sanitize(source)
	if err != nil {
		t.Fatalf("Sanitize() = %v", err)
	}
	for _, token := range []string{"/A ", "/JS ", "/F <<"} {
		if !bytes.Contains(clean, []byte(token)) {
			t.Errorf("resource named %q was dropped", token)
		}
	}
}
