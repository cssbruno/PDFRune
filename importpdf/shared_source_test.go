// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"context"
	"errors"
	"testing"
	"time"
)

// A shared Source is read under one lock. A caller waiting for it while
// another goroutine reads a long page used to wait past its own deadline.
func TestSharedSourceLockHonorsTheWaitersDeadline(t *testing.T) {
	source, err := OpenBytes(minimalImportPDF())
	if err != nil {
		t.Fatal(err)
	}
	source.mu.Lock()
	defer source.mu.Unlock()
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()
	start := time.Now()
	_, err = source.PageContext(ctx, 1, "MediaBox")
	if !errors.Is(err, context.DeadlineExceeded) || time.Since(start) > time.Second {
		t.Fatalf("PageContext() = %v after %v, want the deadline", err, time.Since(start))
	}
}

// Pages sharing an object reuse its cached body and reference list instead of
// copying and parsing it again.
func TestPagesShareReferencedObjectBodies(t *testing.T) {
	source, err := OpenBytes(buildSecurityPDF(t, []string{
		"<< /Type /Catalog /Pages 2 0 R >>",
		"<< /Type /Pages /Kids [3 0 R] /Count 1 >>",
		"<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>",
		"<< /Length 0 >>\nstream\n\nendstream",
		"<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>",
	}))
	if err != nil {
		t.Fatal(err)
	}
	first, err := source.Page(1, "MediaBox")
	if err != nil {
		t.Fatal(err)
	}
	second, err := source.Page(1, "MediaBox")
	if err != nil {
		t.Fatal(err)
	}
	if len(first.objects) == 0 {
		t.Fatal("the page references no objects")
	}
	for ref, body := range first.objects {
		other := second.objects[ref]
		if len(body) > 0 && (len(other) != len(body) || &other[0] != &body[0]) {
			t.Fatalf("object %s was copied for the second read", ref)
		}
	}
}
