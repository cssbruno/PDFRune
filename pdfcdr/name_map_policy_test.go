// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfcdr

import (
	"bytes"
	"fmt"
	"regexp"
	"strings"
	"testing"
)

// A dictionary under a resource category key that only had the shape of a
// resource-name map kept every key the policy removes, so an action, a widget
// annotation or a file specification with its embedded file crossed the
// reconstruction intact. A map carrying /Type, /S, /Subtype or /FT names, an
// indirect /Type or /S, or a direct /EF dictionary is not a name map.
func TestStructuralDictionariesAreNotResourceNameMaps(t *testing.T) {
	for name, tc := range map[string]struct {
		resources string
		objects   []string
		absent    []string
	}{
		"direct action": {
			"<< /Properties << /Type /Action /S /JavaScript /JS 5 0 R /AA << /O 6 0 R >> /OpenAction 6 0 R /Next 6 0 R >> >>",
			[]string{pdfStreamText("app.launchURL('http://PAYLOAD.example');"), "<< /S /Named /N /Print >>"},
			[]string{"/Action", "/JS", "/AA", "/OpenAction", "/Next", "PAYLOAD", "/Named"},
		},
		"indirect widget": {
			"<< /ExtGState 5 0 R >>",
			[]string{"<< /Type /Annot /Subtype /Widget /FT /Btn /A 6 0 R /AA << /U 6 0 R >> >>", "<< /S /Hide /T 5 0 R /H false >>"},
			[]string{"/Annot", "/Widget", "/Hide"},
		},
		"indirect action type": {
			"<< /Font << /Type /Action /S 5 0 R /JS 6 0 R >> >>",
			[]string{"/JavaScript", "(app.alert\\(1\\))"},
			[]string{"/JavaScript", "app.alert"},
		},
		"indirect action type without /Type": {
			"<< /Font << /S 5 0 R /JS 6 0 R >> >>",
			[]string{"/JavaScript", "(app.alert\\(1\\))"},
			[]string{"/JavaScript", "app.alert"},
		},
		"file specification": {
			"<< /XObject << /Type /Filespec /UF 5 0 R /EF << /UF 6 0 R >> >> >>",
			[]string{"(invoice.exe)", pdfStreamText("MZ-EMBEDDED")},
			[]string{"/Filespec", "/EF", "invoice.exe", "MZ-EMBEDDED"},
		},
		"file specification without /Type": {
			"<< /XObject << /UF 5 0 R /EF << /UF 6 0 R >> >> >>",
			[]string{"(invoice.exe)", pdfStreamText("MZ-EMBEDDED")},
			[]string{"/EF", "MZ-EMBEDDED"},
		},
	} {
		t.Run(name, func(t *testing.T) {
			clean, err := Sanitize(resourceGraphPDF(t, tc.resources, tc.objects...))
			if err != nil {
				return // refusing the document also keeps the content out
			}
			for _, token := range tc.absent {
				if bytes.Contains(clean, []byte(token)) {
					t.Errorf("output contains %q:\n%s", token, clean)
				}
			}
		})
	}
}

// Action dictionaries left in retained resources are dropped for every ISO
// 32000-2 action type, in plain and #-escaped spellings, with their /Next.
func TestEveryActionTypeIsDropped(t *testing.T) {
	for _, action := range []string{"GoTo", "GoToR", "GoToE", "GoToDp", "Launch", "Thread", "URI", "Sound", "Movie", "Hide", "Named", "SubmitForm", "ResetForm", "ImportData", "SetOCGState", "Rendition", "Trans", "GoTo3DView", "JavaScript", "ECMAScript", "RichMediaExecute"} {
		escaped := fmt.Sprintf("#%02X%s", action[0], action[1:])
		for _, spelling := range []string{action, escaped} {
			form := fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Act << /S /%s /N /Print >> /Length 0 >>\nstream\n\nendstream", spelling)
			clean, err := Sanitize(resourceGraphPDF(t, "<< /XObject << /X0 5 0 R >> >>", form))
			if err != nil {
				t.Fatalf("Sanitize(/S /%s) error = %v", spelling, err)
			}
			if bytes.Contains(clean, []byte("/S /"+spelling)) {
				t.Errorf("action /S /%s survived", spelling)
			}
		}
	}
	chained := "<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /Next 6 0 R /Length 0 >>\nstream\n\nendstream"
	clean, err := Sanitize(resourceGraphPDF(t, "<< /XObject << /X0 5 0 R >> >>", chained, "<< /S /Named /N /Print >>"))
	if err != nil {
		t.Fatalf("Sanitize() error = %v", err)
	}
	if bytes.Contains(clean, []byte("/Next")) || bytes.Contains(clean, []byte("/Named")) {
		t.Errorf("chained action survived:\n%s", clean)
	}
}

// pdfcdr resolved "+7 0 R" to source object 7 but wrote it back unchanged,
// and the renumbering pass only rewrites unsigned references, so the output
// pointed at whatever object received number 7.
func TestSignedReferencesAreWrittenCanonically(t *testing.T) {
	form := func(marker string) string {
		return fmt.Sprintf("<< /Type /XObject /Subtype /Form /BBox [0 0 10 10] /%s true /Length 0 >>\nstream\n\nendstream", marker)
	}
	clean, err := Sanitize(resourceGraphPDF(t, "<< /XObject << /X0 5 0 R /X1 +7 0 R /X2 6 0 R >> >>", form("SRC5"), form("SRC6"), form("SRC7")))
	if err != nil {
		t.Fatalf("Sanitize() error = %v", err)
	}
	match := regexp.MustCompile(`/X1 (\S+) 0 R`).FindSubmatch(clean)
	if match == nil {
		t.Fatalf("output has no /X1 reference:\n%s", clean)
	}
	object := regexp.MustCompile(`(?s)\n` + regexp.QuoteMeta(string(match[1])) + ` 0 obj\n(.*?)endobj`).FindSubmatch(clean)
	if object == nil || !strings.Contains(string(object[1]), "/SRC7") {
		t.Fatalf("/X1 %s 0 R does not name the source object 7:\n%s", match[1], clean)
	}
}

func pdfStreamText(data string) string {
	return fmt.Sprintf("<< /Length %d >>\nstream\n%s\nendstream", len(data), data)
}
