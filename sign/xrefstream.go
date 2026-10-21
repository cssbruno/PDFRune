// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign

import (
	"bytes"
	"compress/zlib"
	"context"
	"errors"
	"fmt"
	"io"
)

// This file reads PDF 1.5 cross-reference streams and object streams for the
// read-only resolver. Only the container streams themselves are decoded; the
// signature dictionary must still be an uncompressed object because its
// ByteRange and /Contents are file offsets.

// maxXrefContainerBytes bounds the bytes one resolver decodes from xref and
// object streams, so compressed sections cannot amplify a small input.
const maxXrefContainerBytes = 64 << 20

type pdfStreamObject struct {
	ref  pdfRef
	dict []byte
	data []byte
}

type pdfObjectStream struct {
	numbers []int
	offsets []int
	first   int
	decoded []byte
}

// loadXrefStreamContext adds the entries of the xref stream at offset that no
// newer revision defined and returns the highest object number it lists.
func (resolver *pdfXrefResolver) loadXrefStreamContext(ctx context.Context, offset, maxXrefEntries int) (int, error) {
	stream, err := resolver.readStreamObjectContext(ctx, offset, false)
	if err != nil {
		return -1, fmt.Errorf("pdfsigning: invalid xref stream: %w", err)
	}
	if err := requireDictionaryType(ctx, stream.dict, "/XRef"); err != nil {
		return -1, err
	}
	widthValues, err := directIntArrayEntry(ctx, stream.dict, "/W", 3)
	if err != nil {
		return -1, err
	}
	if len(widthValues) != 3 {
		return -1, errors.New("pdfsigning: invalid xref stream /W")
	}
	rowWidth := 0
	for _, width := range widthValues {
		if width > 8 {
			return -1, errors.New("pdfsigning: invalid xref stream /W")
		}
		rowWidth += width
	}
	if rowWidth == 0 {
		return -1, errors.New("pdfsigning: invalid xref stream /W")
	}
	size, hasSize, err := directIntEntry(ctx, stream.dict, "/Size")
	if err != nil {
		return -1, err
	}
	if !hasSize {
		return -1, errors.New("pdfsigning: xref stream /Size not found")
	}
	sections := []int{0, size}
	if _, hasIndex, err := findDictionaryEntryContext(ctx, stream.dict, "/Index"); err != nil {
		return -1, err
	} else if hasIndex {
		if sections, err = directIntArrayEntry(ctx, stream.dict, "/Index", 2*maxXrefEntries); err != nil {
			return -1, err
		}
		if len(sections)%2 != 0 {
			return -1, errors.New("pdfsigning: invalid xref stream /Index")
		}
	}
	totalEntries := 0
	for i := 0; i < len(sections); i += 2 {
		if err := validateXrefSubsection(sections[i], sections[i+1], &totalEntries, maxXrefEntries); err != nil {
			return -1, err
		}
	}
	decoded, err := resolver.decodeContainerStreamContext(ctx, stream)
	if err != nil {
		return -1, fmt.Errorf("pdfsigning: invalid xref stream: %w", err)
	}
	if len(decoded) < totalEntries*rowWidth {
		return -1, errors.New("pdfsigning: xref stream ended before its declared entries")
	}
	maximum := -1
	seenObjects := make(map[int]struct{}, totalEntries)
	pos := 0
	for i := 0; i < len(sections); i += 2 {
		first, count := sections[i], sections[i+1]
		if count > 0 {
			maximum = max(maximum, first+count-1)
		}
		for n := 0; n < count; n++ {
			if n%1024 == 0 {
				if err := signContextErr(ctx); err != nil {
					return -1, err
				}
			}
			kind := 1
			if widthValues[0] > 0 {
				kind = xrefStreamField(decoded[pos : pos+widthValues[0]])
			}
			second := xrefStreamField(decoded[pos+widthValues[0] : pos+widthValues[0]+widthValues[1]])
			third := xrefStreamField(decoded[pos+widthValues[0]+widthValues[1] : pos+rowWidth])
			pos += rowWidth
			objectNumber := first + n
			if _, duplicate := seenObjects[objectNumber]; duplicate {
				return -1, fmt.Errorf("pdfsigning: duplicate xref entry for object %d", objectNumber)
			}
			seenObjects[objectNumber] = struct{}{}
			if kind < 0 || second < 0 || third < 0 {
				return -1, errors.New("pdfsigning: invalid xref stream entry")
			}
			var entry effectiveXrefEntry
			switch kind {
			case 0:
				entry = effectiveXrefEntry{Generation: third}
			case 1:
				if second >= len(resolver.input) || third > 65535 {
					return -1, errors.New("pdfsigning: invalid xref stream entry")
				}
				entry = effectiveXrefEntry{Offset: second, Generation: third, InUse: true}
			case 2:
				if second >= maxPDFObjectCount || third >= maxPDFObjectCount {
					return -1, errors.New("pdfsigning: invalid xref stream entry")
				}
				entry = effectiveXrefEntry{InUse: true, Compressed: true, Stream: second, Index: third}
			default:
				// ISO 32000-1 7.5.8.3: other types reference the null object.
				entry = effectiveXrefEntry{}
			}
			if _, resolvedByNewerRevision := resolver.entries[objectNumber]; !resolvedByNewerRevision {
				resolver.entries[objectNumber] = entry
			}
		}
	}
	return maximum, nil
}

// xrefStreamField decodes a big-endian xref stream field, or -1 when the
// value does not fit in an int.
func xrefStreamField(data []byte) int {
	value := 0
	for _, b := range data {
		if value > int(^uint(0)>>1)>>8 {
			return -1
		}
		value = value<<8 | int(b)
	}
	return value
}

// compressedValueContext returns the value of a compressed object from its
// object stream. The bytes are not part of the file, so they carry no offset.
func (resolver *pdfXrefResolver) compressedValueContext(ctx context.Context, ref pdfRef, entry effectiveXrefEntry) ([]byte, error) {
	objectStream, err := resolver.objectStreamContext(ctx, entry.Stream)
	if err != nil {
		return nil, err
	}
	if entry.Index >= len(objectStream.numbers) {
		return nil, fmt.Errorf("pdfsigning: object stream %d has no slot %d", entry.Stream, entry.Index)
	}
	if objectStream.numbers[entry.Index] != ref.Object {
		return nil, fmt.Errorf("pdfsigning: object stream %d slot %d holds object %d, want %d", entry.Stream, entry.Index, objectStream.numbers[entry.Index], ref.Object)
	}
	end := len(objectStream.decoded)
	if entry.Index+1 < len(objectStream.offsets) {
		end = objectStream.first + objectStream.offsets[entry.Index+1]
	}
	body := objectStream.decoded[objectStream.first+objectStream.offsets[entry.Index] : end]
	start := skipPDFSpaces(body, 0)
	valueEnd, err := pdfValueEndContext(ctx, body, start)
	if err != nil {
		return nil, fmt.Errorf("pdfsigning: object %d in object stream %d: %w", ref.Object, entry.Stream, err)
	}
	if skipPDFSpaces(body, valueEnd) != len(body) {
		return nil, fmt.Errorf("pdfsigning: object %d in object stream %d has extra data", ref.Object, entry.Stream)
	}
	return body[start:valueEnd], nil
}

func (resolver *pdfXrefResolver) objectStreamContext(ctx context.Context, number int) (*pdfObjectStream, error) {
	if cached, ok := resolver.objectStreams[number]; ok {
		return cached, nil
	}
	ref := pdfRef{Object: number}
	offset, err := resolver.objectOffsetContext(ctx, ref)
	if err != nil {
		return nil, err
	}
	stream, err := resolver.readStreamObjectContext(ctx, offset, true)
	if err != nil {
		return nil, fmt.Errorf("pdfsigning: invalid object stream %d: %w", number, err)
	}
	if stream.ref != ref {
		return nil, fmt.Errorf("pdfsigning: xref points to object %d %d, want %d 0", stream.ref.Object, stream.ref.Generation, number)
	}
	if err := requireDictionaryType(ctx, stream.dict, "/ObjStm"); err != nil {
		return nil, err
	}
	count, hasCount, err := directIntEntry(ctx, stream.dict, "/N")
	if err != nil {
		return nil, err
	}
	first, hasFirst, err := directIntEntry(ctx, stream.dict, "/First")
	if err != nil {
		return nil, err
	}
	if !hasCount || !hasFirst || count > DefaultMaxXrefEntries {
		return nil, fmt.Errorf("pdfsigning: object stream %d has an invalid /N or /First", number)
	}
	decoded, err := resolver.decodeContainerStreamContext(ctx, stream)
	if err != nil {
		return nil, fmt.Errorf("pdfsigning: invalid object stream %d: %w", number, err)
	}
	if first > len(decoded) {
		return nil, fmt.Errorf("pdfsigning: object stream %d has an invalid /First", number)
	}
	header := decoded[:first]
	// Each header pair takes at least three bytes, which bounds /N before any
	// allocation sized by it.
	if count > (first+1)/3 {
		return nil, fmt.Errorf("pdfsigning: object stream %d has an invalid /N", number)
	}
	parsed := &pdfObjectStream{numbers: make([]int, count), offsets: make([]int, count), first: first, decoded: decoded}
	pos := 0
	for i := 0; i < count; i++ {
		objectNumber, next, ok := parseLeadingInt(header, skipPDFSpaces(header, pos))
		if !ok {
			return nil, fmt.Errorf("pdfsigning: object stream %d has an invalid header", number)
		}
		objectOffset, next, ok := parseLeadingInt(header, skipPDFSpaces(header, next))
		if !ok || objectOffset > len(decoded)-first || (i > 0 && objectOffset < parsed.offsets[i-1]) {
			return nil, fmt.Errorf("pdfsigning: object stream %d has an invalid header", number)
		}
		parsed.numbers[i], parsed.offsets[i] = objectNumber, objectOffset
		pos = next
	}
	if resolver.objectStreams == nil {
		resolver.objectStreams = make(map[int]*pdfObjectStream)
	}
	resolver.objectStreams[number] = parsed
	return parsed, nil
}

// objectDictionaryAtContext parses the "N G obj <<...>>" prefix of the
// object at offset and returns its reference, dictionary and dictionary start.
func objectDictionaryAtContext(ctx context.Context, input []byte, offset int) (pdfRef, []byte, int, error) {
	if offset < 0 || offset >= len(input) {
		return pdfRef{}, nil, 0, errors.New("pdfsigning: object offset outside PDF")
	}
	object, next, ok := parseLeadingInt(input, offset)
	if !ok {
		return pdfRef{}, nil, 0, errors.New("pdfsigning: object header not found")
	}
	generation, next, ok := parseLeadingInt(input, skipPDFSpaces(input, next))
	if !ok {
		return pdfRef{}, nil, 0, errors.New("pdfsigning: object generation not found")
	}
	pos := skipPDFSpaces(input, next)
	if !hasPDFKeywordAt(input, pos, "obj") {
		return pdfRef{}, nil, 0, errors.New("pdfsigning: object header marker not found")
	}
	start := skipPDFSpaces(input, pos+len("obj"))
	if start+1 >= len(input) || input[start] != '<' || input[start+1] != '<' {
		return pdfRef{}, nil, 0, errors.New("pdfsigning: object dictionary not found")
	}
	end, err := findDictionaryEndContext(ctx, input[start:])
	if err != nil {
		return pdfRef{}, nil, 0, err
	}
	return pdfRef{Object: object, Generation: generation}, input[start : start+end], start, nil
}

// readStreamObjectContext reads the stream object at offset. An indirect
// /Length is resolved only when allowed; xref streams require a direct one.
func (resolver *pdfXrefResolver) readStreamObjectContext(ctx context.Context, offset int, indirectLength bool) (pdfStreamObject, error) {
	input := resolver.input
	ref, dict, dictStart, err := objectDictionaryAtContext(ctx, input, offset)
	if err != nil {
		return pdfStreamObject{}, err
	}
	pos := skipPDFSpaces(input, dictStart+len(dict))
	if !hasPDFKeywordAt(input, pos, "stream") {
		return pdfStreamObject{}, errors.New("stream keyword not found")
	}
	// The stream keyword is followed by CRLF or LF, never CR alone.
	dataStart := pos + len("stream")
	switch {
	case bytes.HasPrefix(input[dataStart:], []byte("\r\n")):
		dataStart += 2
	case bytes.HasPrefix(input[dataStart:], []byte("\n")):
		dataStart++
	default:
		return pdfStreamObject{}, errors.New("stream keyword is not followed by an end-of-line")
	}
	lengthEntry, hasLength, err := findDictionaryEntryContext(ctx, dict, "/Length")
	if err != nil {
		return pdfStreamObject{}, err
	}
	if !hasLength {
		return pdfStreamObject{}, errors.New("stream /Length not found")
	}
	lengthValue := dict[lengthEntry.ValueStart:lengthEntry.ValueEnd]
	length, ok := parseExactNonnegativeInt(lengthValue)
	if !ok {
		lengthRef, isRef := parseReferenceValue(lengthValue)
		if !isRef || !indirectLength {
			return pdfStreamObject{}, errors.New("stream /Length is not a direct integer")
		}
		lengthOffset, err := resolver.objectOffsetContext(ctx, lengthRef)
		if err != nil {
			return pdfStreamObject{}, err
		}
		indirect, _, err := readIndirectValuePositionContext(ctx, input, lengthRef, lengthOffset)
		if err != nil {
			return pdfStreamObject{}, err
		}
		if length, ok = parseExactNonnegativeInt(indirect); !ok {
			return pdfStreamObject{}, errors.New("stream /Length is not an integer")
		}
	}
	if length > len(input)-dataStart {
		return pdfStreamObject{}, errors.New("stream /Length exceeds PDF size")
	}
	dataEnd := dataStart + length
	endstream := skipPDFSpaces(input, dataEnd)
	if !hasPDFKeywordAt(input, endstream, "endstream") {
		return pdfStreamObject{}, errors.New("endstream not found after stream /Length bytes")
	}
	if !hasPDFKeywordAt(input, skipPDFSpaces(input, endstream+len("endstream")), "endobj") {
		return pdfStreamObject{}, errors.New("object terminator not found after stream")
	}
	return pdfStreamObject{ref: ref, dict: dict, data: input[dataStart:dataEnd]}, nil
}

// decodeContainerStreamContext decodes an xref or object stream: no filter
// or a single FlateDecode, with an optional PNG predictor. Decoded bytes count
// against the resolver's container budget.
func (resolver *pdfXrefResolver) decodeContainerStreamContext(ctx context.Context, stream pdfStreamObject) ([]byte, error) {
	flate, err := containerStreamIsFlate(ctx, stream.dict)
	if err != nil {
		return nil, err
	}
	decoded := stream.data
	if flate {
		if ctx == nil {
			ctx = context.Background()
		}
		reader, err := zlib.NewReader(bytes.NewReader(stream.data))
		if err != nil {
			return nil, fmt.Errorf("FlateDecode: %w", err)
		}
		limit := resolver.containerBudget
		decoded, err = io.ReadAll(io.LimitReader(signingContextReader{ctx: ctx, r: reader}, int64(limit)+1))
		if err != nil {
			return nil, fmt.Errorf("FlateDecode: %w", err)
		}
		if len(decoded) > limit {
			return nil, errors.New("xref and object streams exceed maximum decoded size")
		}
		resolver.containerBudget -= len(decoded)
	}
	parms, hasParms, err := containerDecodeParms(ctx, stream.dict)
	if err != nil {
		return nil, err
	}
	if !hasParms {
		return decoded, nil
	}
	predictor, _, err := directIntEntryDefault(ctx, parms, "/Predictor", 1)
	if err != nil {
		return nil, err
	}
	if predictor == 1 {
		return decoded, nil
	}
	if predictor < 10 {
		return nil, fmt.Errorf("predictor %d is not supported", predictor)
	}
	columns, _, err := directIntEntryDefault(ctx, parms, "/Columns", 1)
	if err != nil {
		return nil, err
	}
	colors, _, err := directIntEntryDefault(ctx, parms, "/Colors", 1)
	if err != nil {
		return nil, err
	}
	bits, _, err := directIntEntryDefault(ctx, parms, "/BitsPerComponent", 8)
	if err != nil {
		return nil, err
	}
	return undoPNGPredictor(decoded, columns, colors, bits)
}

func containerStreamIsFlate(ctx context.Context, dict []byte) (bool, error) {
	entry, ok, err := findDictionaryEntryContext(ctx, dict, "/Filter")
	if err != nil || !ok {
		return false, err
	}
	value := dict[entry.ValueStart:entry.ValueEnd]
	if pdfNameValueEquals(value, "/FlateDecode") {
		return true, nil
	}
	if inner, ok := singleArrayElement(value); ok && pdfNameValueEquals(inner, "/FlateDecode") {
		return true, nil
	}
	return false, errors.New("only FlateDecode is supported in xref and object streams")
}

// containerDecodeParms returns the direct /DecodeParms dictionary, also when
// wrapped in a one-element array.
func containerDecodeParms(ctx context.Context, dict []byte) ([]byte, bool, error) {
	entry, ok, err := findDictionaryEntryContext(ctx, dict, "/DecodeParms")
	if err != nil || !ok {
		return nil, false, err
	}
	value := dict[entry.ValueStart:entry.ValueEnd]
	if inner, ok := singleArrayElement(value); ok {
		value = inner
	}
	pos := skipPDFSpaces(value, 0)
	if isPDFNull(value[pos:]) {
		return nil, false, nil
	}
	if pos+1 >= len(value) || value[pos] != '<' || value[pos+1] != '<' {
		return nil, false, errors.New("/DecodeParms is not a direct dictionary")
	}
	return value[pos:], true, nil
}

// singleArrayElement returns the only element of a direct one-element array.
func singleArrayElement(value []byte) ([]byte, bool) {
	pos := skipPDFSpaces(value, 0)
	if pos >= len(value) || value[pos] != '[' {
		return nil, false
	}
	start := skipPDFSpaces(value, pos+1)
	end, err := pdfValueEndContext(context.Background(), value, start)
	if err != nil {
		return nil, false
	}
	closing := skipPDFSpaces(value, end)
	if closing >= len(value) || value[closing] != ']' || skipPDFSpaces(value, closing+1) != len(value) {
		return nil, false
	}
	return value[start:end], true
}

func requireDictionaryType(ctx context.Context, dict []byte, name string) error {
	entry, ok, err := findDictionaryEntryContext(ctx, dict, "/Type")
	if err != nil {
		return err
	}
	if !ok || !pdfNameValueEquals(dict[entry.ValueStart:entry.ValueEnd], name) {
		return fmt.Errorf("pdfsigning: stream is not of type %s", name)
	}
	return nil
}

func directIntEntry(ctx context.Context, dict []byte, key string) (int, bool, error) {
	entry, ok, err := findDictionaryEntryContext(ctx, dict, key)
	if err != nil || !ok {
		return 0, false, err
	}
	value, valid := parseExactNonnegativeInt(dict[entry.ValueStart:entry.ValueEnd])
	if !valid {
		return 0, false, fmt.Errorf("pdfsigning: %s is not a direct non-negative integer", key)
	}
	return value, true, nil
}

func directIntEntryDefault(ctx context.Context, dict []byte, key string, fallback int) (int, bool, error) {
	value, ok, err := directIntEntry(ctx, dict, key)
	if err != nil || ok {
		return value, ok, err
	}
	return fallback, false, nil
}

// directIntArrayEntry parses a direct array of non-negative integers holding
// at most maxItems values.
func directIntArrayEntry(ctx context.Context, dict []byte, key string, maxItems int) ([]int, error) {
	entry, ok, err := findDictionaryEntryContext(ctx, dict, key)
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("pdfsigning: %s not found", key)
	}
	value := dict[entry.ValueStart:entry.ValueEnd]
	pos := skipPDFSpaces(value, 0)
	if pos >= len(value) || value[pos] != '[' {
		return nil, fmt.Errorf("pdfsigning: %s is not a direct array", key)
	}
	values := make([]int, 0, min(maxItems, 16))
	for pos = skipPDFSpaces(value, pos+1); pos < len(value) && value[pos] != ']'; pos = skipPDFSpaces(value, pos) {
		if len(values) >= maxItems {
			return nil, fmt.Errorf("pdfsigning: %s has too many values", key)
		}
		parsed, next, ok := parseLeadingInt(value, pos)
		if !ok || !isPDFTokenEnd(value, next) {
			return nil, fmt.Errorf("pdfsigning: %s holds a value that is not a non-negative integer", key)
		}
		values = append(values, parsed)
		pos = next
	}
	if pos >= len(value) || skipPDFSpaces(value, pos+1) != len(value) {
		return nil, fmt.Errorf("pdfsigning: invalid %s array", key)
	}
	return values, nil
}

// undoPNGPredictor reverses PNG row prediction (ISO 32000-1 7.4.4.4).
func undoPNGPredictor(data []byte, columns, colors, bits int) ([]byte, error) {
	if columns <= 0 || colors <= 0 || bits <= 0 || columns > 1<<20 || colors > 32 || bits > 16 {
		return nil, errors.New("predictor parameters are invalid")
	}
	rowBytes := (columns*colors*bits + 7) / 8
	pixelBytes := (colors*bits + 7) / 8
	if len(data) == 0 {
		return data, nil
	}
	if rowBytes >= len(data) {
		return nil, errors.New("predictor row exceeds the stream data")
	}
	out := make([]byte, 0, len(data)/(rowBytes+1)*rowBytes)
	previous := make([]byte, rowBytes)
	// A trailing partial row is ignored, as readers do.
	for pos := 0; pos+1+rowBytes <= len(data); pos += rowBytes + 1 {
		kind := data[pos]
		row := append([]byte(nil), data[pos+1:pos+1+rowBytes]...)
		for i := range row {
			var left, upLeft byte
			if i >= pixelBytes {
				left = row[i-pixelBytes]
				upLeft = previous[i-pixelBytes]
			}
			up := previous[i]
			switch kind {
			case 0:
			case 1:
				row[i] += left
			case 2:
				row[i] += up
			case 3:
				row[i] += byte((int(left) + int(up)) / 2)
			case 4:
				row[i] += paethPredictor(left, up, upLeft)
			default:
				return nil, fmt.Errorf("PNG predictor row type %d is invalid", kind)
			}
		}
		out = append(out, row...)
		previous = row
	}
	return out, nil
}

func paethPredictor(a, b, c byte) byte {
	p := int(a) + int(b) - int(c)
	pa, pb, pc := absInt(p-int(a)), absInt(p-int(b)), absInt(p-int(c))
	switch {
	case pa <= pb && pa <= pc:
		return a
	case pb <= pc:
		return b
	default:
		return c
	}
}

func absInt(value int) int {
	if value < 0 {
		return -value
	}
	return value
}
