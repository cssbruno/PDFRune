// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import "testing"

// Advances from the Adobe Core 14 AFM files, read through WinAnsi codes
// (quotesingle at 39), for fonts written without /Widths.
func TestStandardFontWidthsCoverBoldHelveticaAndTimes(t *testing.T) {
	for _, tc := range []struct {
		font  string
		code  byte
		width float64
	}{
		{"Helvetica-Bold", 'm', 889},
		{"ABCDEF+Arial-BoldMT", 'i', 278},
		{"Times-Roman", 'W', 944},
		{"Times-Roman", '\'', 180},
		{"Times-Bold", 'M', 944},
		{"Times-Italic", 'm', 722},
		{"Times-BoldItalic", 'W', 889},
	} {
		var widths pdfFontWidths
		standardFontWidths(&widths, tc.font)
		if !widths.known || widths.simple[tc.code] != tc.width {
			t.Errorf("%s %q width = %v (known %v), want %v", tc.font, tc.code, widths.simple[tc.code], widths.known, tc.width)
		}
	}
}
