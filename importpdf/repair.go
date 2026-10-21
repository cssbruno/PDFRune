// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
)

// Reconstruction rebuilds the cross-reference information of a file whose
// xref table or offsets cannot be used, the way conforming readers repair a
// damaged file: every "N G obj" header that starts a line is read in file
// order, a later definition of an object replaces an earlier one as an
// incremental update would, and the last trailer (or cross-reference stream
// dictionary) names the catalog. The result is a classic PDF that the regular
// parser, and normalization when it is encrypted, then read as usual.

// errReconstructionBudget stops a scan whose object bodies keep running to the
// end of the file, which would otherwise cost quadratic time.
var errReconstructionBudget = errors.New("PDF reconstruction exceeds its work budget")

type scannedObject struct {
	ref    ObjRef
	offset int
	body   []byte
}

type scannedTrailer struct {
	offset int
	dict   pdfDict
}

// scanPDFObjectsContext finds the indirect objects and trailers of data in file
// order. It steps over each object it reads, so stream data is not mistaken for
// object headers.
func (doc *Source) scanPDFObjectsContext(ctx context.Context, data []byte) ([]scannedObject, []scannedTrailer, error) {
	var objects []scannedObject
	var trailers []scannedTrailer
	budget := 8*len(data) + 1<<20
	for pos := 0; pos < len(data); {
		if err := importContextErr(ctx); err != nil {
			return nil, nil, err
		}
		if pos == 0 || data[pos-1] == '\n' || data[pos-1] == '\r' {
			p := pos
			for p < len(data) && (data[p] == ' ' || data[p] == '\t' || data[p] == 0 || data[p] == '\f') {
				p++
			}
			if p < len(data) && data[p] >= '0' && data[p] <= '9' {
				if ref, ok := indirectObjectRefAt(data, p); ok {
					body, end, found, err := doc.objectSpanContext(ctx, ref, data[p:], true)
					if ctxErr := importContextErr(ctx); ctxErr != nil {
						return nil, nil, ctxErr
					}
					if err == nil && found {
						budget -= end
					} else {
						budget -= len(data) - p
					}
					if budget < 0 {
						return nil, nil, errReconstructionBudget
					}
					if err == nil && found {
						if len(objects) >= MaxXrefEntries {
							return nil, nil, errors.New("PDF xref entry count exceeds maximum size")
						}
						objects = append(objects, scannedObject{ref: ref, offset: p, body: body})
						pos = p + end
						continue
					}
				}
			} else if hasPDFWord(data, p, "trailer") {
				if dict, err := parsePDFObjectDictContext(ctx, data[p+len("trailer"):]); err == nil {
					trailers = append(trailers, scannedTrailer{offset: p, dict: dict})
				}
			}
		}
		next := bytes.IndexAny(data[pos:], "\r\n")
		if next < 0 {
			break
		}
		pos += next + 1
	}
	return objects, trailers, nil
}

// recoveredObjectOffset finds ref by scanning the file once, for an xref entry
// that does not lead to the object it names.
func (doc *Source) recoveredObjectOffset(ctx context.Context, ref ObjRef) (int, bool) {
	if doc.data == nil || doc.scanning {
		return 0, false
	}
	if doc.recovered == nil {
		doc.scanning = true
		objects, _, err := doc.scanPDFObjectsContext(ctx, doc.data)
		doc.scanning = false
		doc.recovered = make(map[ObjRef]int, len(objects))
		if err != nil {
			return 0, false
		}
		for _, object := range objects {
			doc.recovered[object.ref] = object.offset
		}
	}
	offset, ok := doc.recovered[ref]
	return offset, ok
}

// reconstructSourceContext returns a classic PDF rebuilt from the objects
// found in data, or an error when data holds no usable catalog.
func reconstructSourceContext(ctx context.Context, data []byte, options ImportOptions) ([]byte, error) {
	options, err := normalizeImportOptions(options)
	if err != nil {
		return nil, err
	}
	n := &pdfNormalizer{
		doc: &Source{
			data:      data,
			offsets:   make(map[ObjRef]int),
			xrefSeen:  make(map[int]bool),
			cache:     make(map[ObjRef][]byte),
			resolving: make(map[ObjRef]bool),
			limits:    options,
			scanning:  true,
		},
	}
	objects, trailers, err := n.doc.scanPDFObjectsContext(ctx, data)
	if err != nil {
		return nil, err
	}

	type definition struct {
		ref   ObjRef
		order int
		body  []byte
	}
	latest := make(map[int]definition)
	var objectStreams []scannedObject
	var trailer pdfDict
	trailerAt := -1
	for order, object := range objects {
		dictBytes := object.body
		if streamPos := findPDFStreamKeyword(object.body); streamPos >= 0 {
			dictBytes = object.body[:streamPos]
		}
		typeName := ""
		dict, dictErr := parsePDFObjectDictContext(ctx, dictBytes)
		if dictErr == nil && dict["Type"].kind == pdfValueName {
			typeName = dict["Type"].name
		}
		switch typeName {
		case "XRef":
			// A cross-reference stream carries the trailer entries of its
			// section; its offsets are the ones being rebuilt, so it is dropped.
			if _, ok := dict["Root"]; ok && object.offset > trailerAt {
				trailer, trailerAt = dict, object.offset
			}
			continue
		case "ObjStm":
			objectStreams = append(objectStreams, object)
			continue
		}
		latest[object.ref.num] = definition{ref: object.ref, order: order, body: object.body}
	}
	for _, candidate := range trailers {
		if _, ok := candidate.dict["Root"]; ok && candidate.offset > trailerAt {
			trailer, trailerAt = candidate.dict, candidate.offset
		}
	}
	if trailer == nil {
		trailer = pdfDict{}
	}

	if len(objectStreams) > 0 {
		if encrypt, ok := trailer["Encrypt"]; ok && encrypt.kind != pdfValueNull {
			// Object streams of an encrypted file would need decrypting before
			// they can be split; that combination is left to the regular path.
			return nil, errors.New("PDF reconstruction does not split encrypted object streams")
		}
		positions := make(map[int]int, len(objects))
		for order, object := range objects {
			positions[object.offset] = order
		}
		for _, stream := range objectStreams {
			members, err := n.objectStreamMembersContext(ctx, stream.ref, stream.body)
			if err != nil {
				continue
			}
			order := positions[stream.offset]
			for number, body := range members {
				if current, ok := latest[number]; ok && current.order > order {
					continue
				}
				latest[number] = definition{ref: ObjRef{num: number}, order: order, body: body}
			}
		}
	}

	// The catalog may sit in an object stream, so the root is checked once
	// those are split; without a usable one, the latest catalog is used.
	if root, ok := pdfValueAsRef(trailer["Root"]); !ok || latest[root.num].ref != root {
		catalog, order := ObjRef{}, -1
		for _, object := range latest {
			if object.order > order && isPDFCatalogBody(ctx, object.body) {
				catalog, order = object.ref, object.order
			}
		}
		if order < 0 {
			return nil, errors.New("PDF reconstruction found no catalog")
		}
		trailer["Root"] = pdfValue{kind: pdfValueRef, ref: catalog, raw: []byte(fmt.Sprintf("%d %d R", catalog.num, catalog.gen))}
	}

	// The rebuilt table has one row per object number up to the largest, so a
	// number past the entry limit (one header can name 300000000000) is left
	// out instead of sizing that table.
	for number := range latest {
		if number >= MaxXrefEntries {
			delete(latest, number)
		}
	}
	numbers := make([]int, 0, len(latest))
	for number := range latest {
		numbers = append(numbers, number)
	}
	sort.Ints(numbers)
	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	positions := make(map[int]int, len(numbers))
	maxNumber := 0
	for _, number := range numbers {
		if err := importContextErr(ctx); err != nil {
			return nil, err
		}
		object := latest[number]
		positions[number] = out.Len()
		if number > maxNumber {
			maxNumber = number
		}
		fmt.Fprintf(&out, "%d %d obj\n", object.ref.num, object.ref.gen)
		out.Write(object.body)
		out.WriteString("\nendobj\n")
		if int64(out.Len()) > options.MaxSourceBytes {
			return nil, ErrSourceTooLarge
		}
	}
	xrefOffset := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n0000000000 65535 f\r\n", maxNumber+1)
	for number := 1; number <= maxNumber; number++ {
		object, ok := latest[number]
		if !ok {
			out.WriteString("0000000000 00000 f\r\n")
			continue
		}
		fmt.Fprintf(&out, "%010d %05d n\r\n", positions[number], object.ref.gen)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d", maxNumber+1)
	for _, key := range []string{"Root", "Info", "ID", "Encrypt"} {
		if value, ok := trailer[key]; ok && len(value.raw) > 0 {
			fmt.Fprintf(&out, " /%s ", key)
			out.Write(value.raw)
		}
	}
	fmt.Fprintf(&out, " >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset)
	if int64(out.Len()) > options.MaxSourceBytes {
		return nil, ErrSourceTooLarge
	}
	return out.Bytes(), nil
}

func isPDFCatalogBody(ctx context.Context, body []byte) bool {
	if findPDFStreamKeyword(body) >= 0 {
		return false
	}
	dict, err := parsePDFObjectDictContext(ctx, body)
	return err == nil && dict["Type"].kind == pdfValueName && dict["Type"].name == "Catalog"
}

// isTerminalImportError reports an error that another reading of the same
// bytes cannot change: cancellation, a password problem, unsupported
// encryption, or a size limit.
func isTerminalImportError(err error) bool {
	return errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) ||
		errors.Is(err, ErrPasswordRequired) || errors.Is(err, ErrIncorrectPassword) ||
		errors.Is(err, ErrUnsupportedEncryption) || errors.Is(err, ErrSourceTooLarge)
}
