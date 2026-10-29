// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"context"
	"fmt"
	"testing"
)

// An object-stream offset near MaxInt64 once wrapped first+offset negative,
// passed the bounds check and panicked on the slice that followed.
func TestObjectStreamOffsetOverflowIsRejectedWithoutPanic(t *testing.T) {
	header := "1 9223372036854775807"
	stream := header + " xxx"
	for name, pdf := range map[string]string{
		"damaged xref repair": fmt.Sprintf("%%PDF-1.7\n1 0 obj\n<< /Type /ObjStm /N 1 /First %d /Length %d >>\nstream\n%s\nendstream\nendobj\ntrailer\n<< /Root 2 0 R >>\n%%%%EOF\n", len(header), len(stream), stream),
	} {
		t.Run(name, func(t *testing.T) {
			defer func() {
				if recovered := recover(); recovered != nil {
					t.Fatalf("opening the crafted PDF panicked: %v", recovered)
				}
			}()
			if _, err := OpenBytesImmutableWithOptionsContext(context.Background(), []byte(pdf), ImportOptions{}); err == nil {
				t.Fatal("a PDF without a usable page tree opened")
			}
		})
	}
}
