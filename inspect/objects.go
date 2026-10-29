// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/cssbruno/pdfrune/importpdf"
)

const (
	maxObjectNesting      = 32
	maxObjectRefHops      = 16
	maxFormXObjectDepth   = 12
	maxResourceStreamSize = 8 * 1024 * 1024
)

type pdfObjectKind uint8

const (
	pdfObjectNull pdfObjectKind = iota
	pdfObjectBool
	pdfObjectNumber
	pdfObjectName
	pdfObjectString
	pdfObjectArray
	pdfObjectDict
	pdfObjectRef
	pdfObjectKeyword
)

// pdfObject is a parsed PDF value used to read font and XObject resources.
type pdfObject struct {
	kind   pdfObjectKind
	number float64
	name   string
	str    []byte
	array  []pdfObject
	dict   map[string]pdfObject
	ref    streamObjectRef
}

func (o pdfObject) get(key string) pdfObject {
	if o.kind != pdfObjectDict {
		return pdfObject{}
	}
	return o.dict[key]
}

// parsePDFObject parses one PDF value at pos. Integer pairs followed by R are
// read as indirect references; containers are bounded in depth and size.
func parsePDFObject(data []byte, pos, depth int) (pdfObject, int, error) {
	if depth > maxObjectNesting {
		return pdfObject{}, pos, fmt.Errorf("%w: object nesting exceeds %d", ErrTextLimitExceeded, maxObjectNesting)
	}
	pos = skipPDFWhitespaceAndComments(data, pos)
	if pos >= len(data) {
		return pdfObject{}, pos, errors.New("pdf object is truncated")
	}
	switch data[pos] {
	case '<':
		if pos+1 < len(data) && data[pos+1] == '<' {
			return parsePDFDictObject(data, pos+2, depth)
		}
		raw, next := readPDFHexString(data, pos)
		return pdfObject{kind: pdfObjectString, str: raw}, next, nil
	case '(':
		raw, next := readPDFLiteralString(data, pos)
		return pdfObject{kind: pdfObjectString, str: raw}, next, nil
	case '[':
		items := make([]pdfObject, 0, textTokenCapacity)
		pos++
		for {
			pos = skipPDFWhitespaceAndComments(data, pos)
			if pos >= len(data) {
				return pdfObject{}, pos, errors.New("pdf array is unterminated")
			}
			if data[pos] == ']' {
				return pdfObject{kind: pdfObjectArray, array: items}, pos + 1, nil
			}
			if len(items) >= maxTextArrayElements {
				return pdfObject{}, pos, fmt.Errorf("%w: array element count exceeds %d", ErrTextLimitExceeded, maxTextArrayElements)
			}
			item, next, err := parsePDFObjectOrRef(data, pos, depth+1)
			if err != nil {
				return pdfObject{}, next, err
			}
			items = append(items, item)
			pos = next
		}
	case '/':
		name, next := readPDFName(data, pos)
		return pdfObject{kind: pdfObjectName, name: name}, next, nil
	default:
		word, next := readPDFWord(data, pos)
		if word == "" {
			return pdfObject{}, pos + 1, fmt.Errorf("unexpected pdf delimiter %q", data[pos])
		}
		switch word {
		case "true", "false":
			return pdfObject{kind: pdfObjectBool, name: word}, next, nil
		case "null":
			return pdfObject{}, next, nil
		}
		if number, err := strconv.ParseFloat(word, 64); err == nil && isPDFOperandWord(word) {
			return pdfObject{kind: pdfObjectNumber, number: number}, next, nil
		}
		return pdfObject{kind: pdfObjectKeyword, name: word}, next, nil
	}
}

func parsePDFDictObject(data []byte, pos, depth int) (pdfObject, int, error) {
	dict := make(map[string]pdfObject)
	for {
		pos = skipPDFWhitespaceAndComments(data, pos)
		if pos >= len(data) {
			return pdfObject{}, pos, errors.New("pdf dictionary is unterminated")
		}
		if data[pos] == '>' {
			if pos+1 < len(data) && data[pos+1] == '>' {
				return pdfObject{kind: pdfObjectDict, dict: dict}, pos + 2, nil
			}
			return pdfObject{}, pos, errors.New("pdf dictionary has a malformed end")
		}
		if data[pos] != '/' {
			return pdfObject{}, pos, errors.New("pdf dictionary key is not a name")
		}
		if len(dict) >= maxTextArrayElements {
			return pdfObject{}, pos, fmt.Errorf("%w: dictionary entry count exceeds %d", ErrTextLimitExceeded, maxTextArrayElements)
		}
		key, next := readPDFName(data, pos)
		value, next, err := parsePDFObjectOrRef(data, next, depth+1)
		if err != nil {
			return pdfObject{}, next, err
		}
		dict[key] = value
		pos = next
	}
}

// parsePDFObjectOrRef parses a value and folds "num gen R" into a reference.
func parsePDFObjectOrRef(data []byte, pos, depth int) (pdfObject, int, error) {
	value, next, err := parsePDFObject(data, pos, depth)
	if err != nil || value.kind != pdfObjectNumber {
		return value, next, err
	}
	number, ok := pdfObjectInteger(value)
	if !ok || number < 0 {
		return value, next, nil
	}
	genStart := skipPDFWhitespaceAndComments(data, next)
	genWord, genEnd := readPDFWord(data, genStart)
	generation, err := strconv.Atoi(genWord)
	if err != nil || generation < 0 {
		return value, next, nil
	}
	rStart := skipPDFWhitespaceAndComments(data, genEnd)
	if word, rEnd := readPDFWord(data, rStart); word == "R" {
		return pdfObject{kind: pdfObjectRef, ref: streamObjectRef{number: number, generation: generation}}, rEnd, nil
	}
	return value, next, nil
}

func pdfObjectInteger(value pdfObject) (int, bool) {
	if value.kind != pdfObjectNumber || value.number != float64(int(value.number)) || value.number > 1<<31 || value.number < -(1<<31) {
		return 0, false
	}
	return int(value.number), true
}

func pdfObjectNumberOr(value pdfObject, fallback float64) float64 {
	if value.kind != pdfObjectNumber {
		return fallback
	}
	return value.number
}

// pdfResourceObjects resolves indirect objects referenced from one page's
// resources. Object bodies come from importpdf, which already collected the
// resource graph of the page, and stay borrowed from the PageRef.
type pdfResourceObjects struct {
	ctx      context.Context
	bodies   map[streamObjectRef][]byte
	integers map[streamObjectRef]indirectInteger
	parsed   map[streamObjectRef]pdfObject
	budget   *textBudget
	// streams holds each stream's decode result, failures included, so a
	// form drawn or a font selected many times is inflated only once.
	streams map[streamObjectRef]resourceStream
}

type resourceStream struct {
	dict pdfObject
	data []byte
	ok   bool
}

// textBudget is the decoded-byte budget shared by page contents, resource
// streams, and Form XObject executions of one extraction.
type textBudget struct {
	remaining int
}

func newTextBudget() *textBudget {
	return &textBudget{remaining: maxDecodedTotalBytes}
}

func (b *textBudget) charge(n int) error {
	if b == nil {
		return nil
	}
	if n > b.remaining {
		return fmt.Errorf("%w: decoded page contents and resources exceed %d bytes", ErrTextLimitExceeded, maxDecodedTotalBytes)
	}
	b.remaining -= n
	return nil
}

func newPDFResourceObjects(ctx context.Context, page *importpdf.PageRef, budget *textBudget) *pdfResourceObjects {
	objects := &pdfResourceObjects{
		ctx:    ctx,
		bodies: make(map[streamObjectRef][]byte, page.ObjectCount()),
		parsed: make(map[streamObjectRef]pdfObject),
		budget: budget,
	}
	sources := make([]streamSourceObject, 0, page.ObjectCount())
	_ = page.ForEachObjectBorrowed(func(ref importpdf.ObjRef, body []byte) error {
		key := streamObjectRef{number: ref.ObjectNumber(), generation: ref.Generation()}
		objects.bodies[key] = body
		sources = append(sources, streamSourceObject{ref: key, body: body})
		return nil
	})
	objects.integers = indexIndirectIntegers(sources)
	return objects
}

// resolve follows indirect references to a direct value. Missing or
// unparsable objects read as null.
func (r *pdfResourceObjects) resolve(value pdfObject) pdfObject {
	for hops := 0; value.kind == pdfObjectRef; hops++ {
		if r == nil || hops >= maxObjectRefHops {
			return pdfObject{}
		}
		value = r.object(value.ref)
	}
	return value
}

func (r *pdfResourceObjects) object(ref streamObjectRef) pdfObject {
	if value, ok := r.parsed[ref]; ok {
		return value
	}
	body, ok := r.bodies[ref]
	if !ok {
		return pdfObject{}
	}
	value, _, err := parsePDFObjectOrRef(body, 0, 0)
	if err != nil {
		value = pdfObject{}
	}
	r.parsed[ref] = value
	return value
}

// stream returns the dictionary and decoded data of a stream object. Streams
// with filters other than a plain FlateDecode are reported as unavailable so
// encoded bytes are never interpreted as text.
func (r *pdfResourceObjects) stream(value pdfObject) (pdfObject, []byte, bool, error) {
	if r == nil || value.kind != pdfObjectRef {
		return pdfObject{}, nil, false, nil
	}
	if cached, ok := r.streams[value.ref]; ok {
		if !cached.ok {
			return cached.dict, nil, false, nil
		}
		// Every use is still charged: drawing a form again interprets its
		// content again.
		if err := r.budget.charge(len(cached.data)); err != nil {
			return cached.dict, nil, false, err
		}
		return cached.dict, cached.data, true, nil
	}
	dict, decoded, ok, err := r.decodeStream(value)
	if err != nil {
		return dict, nil, false, err
	}
	if r.streams == nil {
		r.streams = make(map[streamObjectRef]resourceStream)
	}
	r.streams[value.ref] = resourceStream{dict: dict, data: decoded, ok: ok}
	if !ok {
		return dict, nil, false, nil
	}
	if err := r.budget.charge(len(decoded)); err != nil {
		return dict, nil, false, err
	}
	return dict, decoded, true, nil
}

func (r *pdfResourceObjects) decodeStream(value pdfObject) (pdfObject, []byte, bool, error) {
	body, ok := r.bodies[value.ref]
	if !ok {
		return pdfObject{}, nil, false, nil
	}
	dict := r.object(value.ref)
	if dict.kind != pdfObjectDict {
		return pdfObject{}, nil, false, nil
	}
	raw, ok := resourceStreamData(body, r.integers)
	if !ok {
		return dict, nil, false, nil
	}
	flate, supported := resourceStreamFilter(r.resolve(dict.get("Filter")), r.resolve(dict.get("DecodeParms")))
	if !supported {
		return dict, nil, false, nil
	}
	if err := inspectContextErr(r.ctx); err != nil {
		return dict, nil, false, err
	}
	decoded := raw
	if flate {
		var err error
		decoded, err = inflateStreamWithLimitContext(r.ctx, raw, maxResourceStreamSize)
		if err != nil {
			if ctxErr := inspectContextErr(r.ctx); ctxErr != nil {
				return dict, nil, false, ctxErr
			}
			return dict, nil, false, nil
		}
	} else if len(decoded) > maxResourceStreamSize {
		return dict, nil, false, nil
	}
	return dict, decoded, true, nil
}

// resourceStreamData returns the raw stream bytes, falling back to the last
// endstream keyword when /Length does not reach it.
func resourceStreamData(body []byte, integers map[streamObjectRef]indirectInteger) ([]byte, bool) {
	if _, data, found, err := objectStream(body, integers); err == nil && found {
		return data, true
	}
	start := findStreamKeyword(body)
	if start < 0 {
		return nil, false
	}
	dataStart, err := streamDataStart(body, start+len("stream"))
	if err != nil {
		return nil, false
	}
	end := bytes.LastIndex(body, []byte("endstream"))
	if end < dataStart {
		return nil, false
	}
	if end > dataStart && body[end-1] == '\n' {
		end--
	}
	if end > dataStart && body[end-1] == '\r' {
		end--
	}
	return body[dataStart:end], true
}

func findStreamKeyword(body []byte) int {
	first, ok := nextStreamToken(body, 0)
	if !ok || first.kind != streamTokenDictStart {
		return -1
	}
	depth := 1
	pos := first.end
	for depth > 0 {
		token, ok := nextStreamToken(body, pos)
		if !ok {
			return -1
		}
		pos = token.end
		switch token.kind {
		case streamTokenDictStart:
			depth++
		case streamTokenDictEnd:
			depth--
		}
	}
	token, ok := nextStreamToken(body, pos)
	if !ok || token.kind != streamTokenWord || token.text != "stream" {
		return -1
	}
	return token.start
}

// resourceStreamFilter reports whether the stream needs Flate decoding and
// whether its filter chain is supported at all.
func resourceStreamFilter(filter, params pdfObject) (bool, bool) {
	if filter.kind == pdfObjectArray {
		switch len(filter.array) {
		case 0:
			filter = pdfObject{}
		case 1:
			filter = filter.array[0]
		default:
			return false, false
		}
	}
	if params.kind == pdfObjectArray && len(params.array) == 1 {
		params = params.array[0]
	}
	switch filter.kind {
	case pdfObjectNull:
		return false, true
	case pdfObjectName:
		if !isFlateFilterName(filter.name) {
			return false, false
		}
	default:
		return false, false
	}
	if params.kind == pdfObjectDict {
		if predictor := pdfObjectNumberOr(params.get("Predictor"), 1); predictor > 1 {
			return false, false
		}
	} else if params.kind != pdfObjectNull {
		return false, false
	}
	return true, true
}
