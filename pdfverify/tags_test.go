// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfverify

import (
	"bytes"
	"context"
	"os"
	"testing"
)

func taggedFinalPDF(t *testing.T) []byte {
	t.Helper()
	pdf, err := os.ReadFile("testdata/tagged.pdf")
	if err != nil {
		t.Fatal(err)
	}
	return pdf
}

func TestInspectTagsReadsFinalBytesAndValidatesHierarchy(t *testing.T) {
	report, err := InspectTags(context.Background(), taggedFinalPDF(t), TagInspectionLimits{})
	if err != nil || !report.Passed || !report.Marked || report.StructureRoot == 0 || report.ParentTree == 0 || report.DocumentElement == 0 || report.MarkedContent != 2 || report.ContentMarked != 2 || report.ContentEnds != 2 {
		t.Fatalf("tag report = %#v, %v", report, err)
	}
	roles := make([]string, len(report.Nodes))
	depths := make([]uint16, len(report.Nodes))
	for index, node := range report.Nodes {
		roles[index], depths[index] = node.Role, node.Depth
	}
	if got, want := roles, []string{"Document", "H1", "P"}; !equalStrings(got, want) {
		t.Fatalf("roles = %v, want %v", got, want)
	}
	if got, want := depths, []uint16{0, 1, 1}; !equalDepths(got, want) {
		t.Fatalf("depths = %v, want %v", got, want)
	}
}

func TestInspectTagsReportsAbsentOrDamagedFinalTagEvidence(t *testing.T) {
	damaged := bytes.Replace(taggedFinalPDF(t), []byte("/Marked true"), []byte("/Marked false"), 1)
	report, err := InspectTags(context.Background(), damaged, TagInspectionLimits{})
	if err != nil || report.Passed || report.Marked || len(report.Failures) == 0 {
		t.Fatalf("damaged report = %#v, %v", report, err)
	}

	plain, err := os.ReadFile("testdata/plain.pdf")
	if err != nil {
		t.Fatal(err)
	}
	missing, err := InspectTags(context.Background(), plain, TagInspectionLimits{})
	if err != nil || missing.Passed || missing.StructureElements != 0 || len(missing.Failures) < 3 {
		t.Fatalf("missing report = %#v, %v", missing, err)
	}
}

func TestCountPDFOperatorKeepsAdjacentTokensDistinctAndIgnoresText(t *testing.T) {
	stream := []byte("/P << /MCID 0 >> BDC\nEMC\n(BDC) Tj\n/Artifact BMC\nEMC")
	if got := countPDFOperator(stream, "BDC"); got != 1 {
		t.Fatalf("BDC count = %d", got)
	}
	if got := countPDFOperator(stream, "BMC"); got != 1 {
		t.Fatalf("BMC count = %d", got)
	}
	if got := countPDFOperator(stream, "EMC"); got != 2 {
		t.Fatalf("EMC count = %d", got)
	}
}

func equalStrings(left, right []string) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}

func equalDepths(left, right []uint16) bool {
	if len(left) != len(right) {
		return false
	}
	for index := range left {
		if left[index] != right[index] {
			return false
		}
	}
	return true
}
