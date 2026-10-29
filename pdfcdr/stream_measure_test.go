// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfcdr

import (
	"bytes"
	"fmt"
	"runtime"
	"testing"
)

// Each form XObject has a wrong /Length and no endstream of its own; only the
// last object of the file keeps one. Measuring a stream past its endobj copied
// the rest of the file per object, so a 545 KB upload allocated 2.6 GB.
func TestBrokenStreamLengthsStayLinear(t *testing.T) {
	const forms = 2000
	builder := &pdfBuilder{}
	for i := 0; i < 3+forms; i++ {
		builder.reserve()
	}
	var refs bytes.Buffer
	for i := 0; i < forms; i++ {
		fmt.Fprintf(&refs, "/X%d %d 0 R ", i, 4+i)
		builder.set(4+i, []byte("<< /Type /XObject /Subtype /Form /BBox [0 0 1 1] /Length 1 >>\nstream\nq Q\nendstream"))
	}
	builder.set(1, []byte("<< /Type /Catalog /Pages 2 0 R >>"))
	builder.set(2, []byte("<< /Type /Pages /Kids [3 0 R] /Count 1 >>"))
	builder.set(3, []byte("<< /Type /Page /Parent 2 0 R /MediaBox [0 0 10 10] /Resources << /XObject << "+refs.String()+">> >> >>"))
	data, err := builder.bytes(nil, 1)
	if err != nil {
		t.Fatal(err)
	}
	last := bytes.LastIndex(data, []byte("endstream"))
	data = append(bytes.ReplaceAll(data[:last], []byte("endstream"), []byte("xndstream")), data[last:]...)

	var before, after runtime.MemStats
	runtime.ReadMemStats(&before)
	_, _ = Sanitize(data)
	runtime.ReadMemStats(&after)
	if allocated := after.TotalAlloc - before.TotalAlloc; allocated > 64*uint64(len(data))+64<<20 {
		t.Fatalf("sanitizing %d bytes allocated %d MB", len(data), allocated>>20)
	}
}
