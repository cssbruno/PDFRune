// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"sort"
	"strconv"
)

// errNeedsNormalization reports a source the classic-xref parser cannot read
// directly: it uses cross-reference streams, a hybrid XRefStm section, object
// streams, or the standard security handler.
var errNeedsNormalization = errors.New("PDF requires normalization before classic parsing")

type packedObjectRef struct {
	stream int
	index  int
}

// pdfNormalizer collects every in-use object of a modern or encrypted PDF so
// it can be rewritten as one classic-xref, unencrypted file. The classic parser
// remains the only code that builds a Source; this pass only removes the
// container formats and encryption that parser does not read.
type pdfNormalizer struct {
	doc     *Source
	packed  map[int]packedObjectRef
	skip    map[int]bool
	trailer pdfDict
	// decoded counts container-stream bytes inflated by this pass; it shares
	// one MaxDecodedStreamBytes budget so many small compressed xref or object
	// streams cannot expand into an unbounded amount of work.
	decoded int
}

func (n *pdfNormalizer) decodeContainer(ctx context.Context, dict pdfDict, data []byte) ([]byte, error) {
	decoded, err := decodeNormalizedStreamContext(ctx, dict, data, MaxDecodedStreamBytes-n.decoded)
	if err != nil {
		return nil, err
	}
	n.decoded += len(decoded)
	return decoded, nil
}

// normalizeSourceContext rewrites data into an equivalent classic PDF. The
// result keeps every in-use object (objects from object streams become plain
// indirect objects), drops cross-reference streams, object streams, and the
// encryption dictionary, and replaces encrypted strings and stream data with
// their decrypted bytes.
func normalizeSourceContext(ctx context.Context, data []byte, options ImportOptions) ([]byte, error) {
	n := &pdfNormalizer{
		doc: &Source{
			data:      data,
			offsets:   make(map[ObjRef]int),
			xrefSeen:  make(map[int]bool),
			cache:     make(map[ObjRef][]byte),
			resolving: make(map[ObjRef]bool),
			limits:    options,
		},
		packed: make(map[int]packedObjectRef),
		skip:   make(map[int]bool),
	}
	if err := n.collectXrefChain(ctx); err != nil {
		return nil, err
	}
	var security *pdfSecurityHandler
	if encryptValue, ok := n.trailer["Encrypt"]; ok && encryptValue.kind != pdfValueNull {
		encrypt, err := n.encryptDict(ctx, encryptValue)
		if err != nil {
			return nil, err
		}
		var firstID []byte
		if id := n.trailer["ID"]; id.kind == pdfValueArray && len(id.array) > 0 {
			firstID, _ = pdfStringBytes(id.array[0])
		}
		security, err = newPDFSecurityHandler(encrypt, firstID, options.Password)
		if err != nil {
			return nil, err
		}
	}
	if err := n.unpackObjectStreams(ctx, security); err != nil {
		return nil, err
	}
	return n.write(ctx, security, options.MaxSourceBytes)
}

func (n *pdfNormalizer) collectXrefChain(ctx context.Context) error {
	start, err := findPDFStartXref(n.doc.data)
	if err != nil {
		return err
	}
	seen := make(map[int]bool)
	pending := []int{start}
	for len(pending) > 0 {
		if err := importContextErr(ctx); err != nil {
			return err
		}
		offset := pending[0]
		pending = pending[1:]
		if offset <= 0 {
			continue
		}
		if offset >= len(n.doc.data) {
			return errors.New("PDF xref offset is invalid")
		}
		if seen[offset] {
			return errors.New("PDF import found cyclic xref chain")
		}
		if len(seen) >= MaxXrefChainLength {
			return errors.New("PDF import xref chain exceeds maximum size")
		}
		seen[offset] = true

		var trailer pdfDict
		if hasPDFWord(n.doc.data, skipPDFSpace(n.doc.data, offset), "xref") {
			trailer, _, err = n.doc.parseXrefAtContext(ctx, offset)
		} else {
			trailer, err = n.parseXrefStream(ctx, offset)
		}
		if err != nil {
			return err
		}
		if n.trailer == nil {
			n.trailer = trailer
		}
		// A hybrid file's XRefStm section is read after its classic table and
		// before Prev, so entries the table already defined keep precedence.
		next := make([]int, 0, 2)
		for _, key := range []string{"XRefStm", "Prev"} {
			value, ok := trailer[key]
			if !ok {
				continue
			}
			target, err := pdfValueNonnegativeInt(value)
			if err != nil {
				return fmt.Errorf("invalid PDF trailer %s offset: %w", key, err)
			}
			next = append(next, target)
		}
		pending = append(next, pending...)
	}
	if n.trailer == nil {
		return errors.New("PDF trailer was not found")
	}
	return nil
}

func (n *pdfNormalizer) parseXrefStream(ctx context.Context, offset int) (pdfDict, error) {
	ref, ok := indirectObjectRefAt(n.doc.data, offset)
	if !ok {
		return nil, errors.New("PDF xref offset does not point to an xref table or stream")
	}
	body, found, err := n.doc.objectBodyFromBytesContext(ctx, ref, n.doc.data[offset:])
	if err != nil {
		return nil, err
	}
	if !found {
		return nil, errors.New("PDF xref stream is missing endobj")
	}
	dict, raw, err := n.doc.parseStreamContext(ctx, body)
	if err != nil {
		return nil, fmt.Errorf("invalid PDF xref stream: %w", err)
	}
	if kind := dict["Type"]; kind.kind != pdfValueName || kind.name != "XRef" {
		return nil, errors.New("PDF xref stream is not of type XRef")
	}
	n.skip[ref.num] = true
	decoded, err := n.decodeContainer(ctx, dict, raw)
	if err != nil {
		return nil, fmt.Errorf("invalid PDF xref stream: %w", err)
	}
	widths, err := xrefStreamWidths(dict["W"])
	if err != nil {
		return nil, err
	}
	size, err := optionalPDFInt(dict, "Size", -1)
	if err != nil || size < 0 {
		return nil, errors.New("PDF xref stream Size is invalid")
	}
	sections := []int{0, size}
	if index := dict["Index"]; index.kind == pdfValueArray {
		if len(index.array)%2 != 0 {
			return nil, errors.New("PDF xref stream Index is invalid")
		}
		sections = sections[:0]
		for _, item := range index.array {
			value, err := pdfValueNonnegativeInt(item)
			if err != nil {
				return nil, errors.New("PDF xref stream Index is invalid")
			}
			sections = append(sections, value)
		}
	}
	rowWidth := widths[0] + widths[1] + widths[2]
	if rowWidth == 0 {
		return nil, errors.New("PDF xref stream W is invalid")
	}
	pos := 0
	for i := 0; i < len(sections); i += 2 {
		first, count := sections[i], sections[i+1]
		if count > MaxXrefEntries-n.doc.xrefEntries || first > MaxXrefEntries*16 {
			return nil, errors.New("PDF xref entry count exceeds maximum size")
		}
		n.doc.xrefEntries += count
		for j := 0; j < count; j++ {
			if err := importContextErr(ctx); err != nil {
				return nil, err
			}
			if pos+rowWidth > len(decoded) {
				return nil, errors.New("PDF xref stream ended before its declared entries")
			}
			kind := 1
			if widths[0] > 0 {
				kind = xrefField(decoded[pos : pos+widths[0]])
			}
			second := xrefField(decoded[pos+widths[0] : pos+widths[0]+widths[1]])
			third := xrefField(decoded[pos+widths[0]+widths[1] : pos+rowWidth])
			pos += rowWidth
			objectNumber := first + j
			if n.doc.xrefSeen[objectNumber] {
				continue
			}
			switch kind {
			case 0:
				n.doc.xrefSeen[objectNumber] = true
			case 1:
				if second >= len(n.doc.data) {
					return nil, errors.New("invalid PDF xref entry offset")
				}
				n.doc.xrefSeen[objectNumber] = true
				n.doc.offsets[ObjRef{num: objectNumber, gen: third}] = second
			case 2:
				n.doc.xrefSeen[objectNumber] = true
				n.packed[objectNumber] = packedObjectRef{stream: second, index: third}
			default:
				// ISO 32000 requires readers to treat unknown entry types as
				// references to the null object.
				n.doc.xrefSeen[objectNumber] = true
			}
		}
	}
	return dict, nil
}

func xrefStreamWidths(value pdfValue) ([3]int, error) {
	var widths [3]int
	if value.kind != pdfValueArray || len(value.array) != 3 {
		return widths, errors.New("PDF xref stream W is invalid")
	}
	for i, item := range value.array {
		width, err := pdfValueNonnegativeInt(item)
		if err != nil || width > 8 {
			return widths, errors.New("PDF xref stream W is invalid")
		}
		widths[i] = width
	}
	return widths, nil
}

func xrefField(data []byte) int {
	value := 0
	for _, b := range data {
		if value > (1<<53)>>8 {
			return -1
		}
		value = value<<8 | int(b)
	}
	return value
}

func indirectObjectRefAt(data []byte, offset int) (ObjRef, bool) {
	pos := skipPDFSpace(data, offset)
	num, _, next, ok := readPDFIntToken(data, pos)
	if !ok || num < 0 {
		return ObjRef{}, false
	}
	pos = skipPDFSpace(data, next)
	gen, _, next, ok := readPDFIntToken(data, pos)
	if !ok || gen < 0 {
		return ObjRef{}, false
	}
	if !hasPDFWord(data, skipPDFSpace(data, next), "obj") {
		return ObjRef{}, false
	}
	return ObjRef{num: num, gen: gen}, true
}

func (n *pdfNormalizer) encryptDict(ctx context.Context, value pdfValue) (pdfDict, error) {
	if value.kind == pdfValueDict {
		return value.dict, nil
	}
	ref, ok := pdfValueAsRef(value)
	if !ok {
		return nil, fmt.Errorf("%w: Encrypt is not a dictionary", ErrUnsupportedEncryption)
	}
	n.skip[ref.num] = true
	body, err := n.doc.objectBodyContext(ctx, ref)
	if err != nil {
		return nil, err
	}
	dict, err := parsePDFObjectDictContext(ctx, body)
	if err != nil {
		return nil, fmt.Errorf("invalid PDF Encrypt dictionary: %w", err)
	}
	return dict, nil
}

// unpackObjectStreams extracts every object stored in an object stream. The
// object bodies are placed in the scratch Source cache under generation 0, so
// stream lengths that reference them still resolve.
func (n *pdfNormalizer) unpackObjectStreams(ctx context.Context, security *pdfSecurityHandler) error {
	if len(n.packed) == 0 {
		return nil
	}
	streams := make(map[int][]int)
	for objectNumber, packed := range n.packed {
		streams[packed.stream] = append(streams[packed.stream], objectNumber)
	}
	typeOne := make(map[int]ObjRef, len(n.doc.offsets))
	for ref := range n.doc.offsets {
		typeOne[ref.num] = ref
	}
	streamNumbers := make([]int, 0, len(streams))
	for number := range streams {
		streamNumbers = append(streamNumbers, number)
	}
	sort.Ints(streamNumbers)
	for _, streamNumber := range streamNumbers {
		if err := importContextErr(ctx); err != nil {
			return err
		}
		if _, packed := n.packed[streamNumber]; packed {
			return errors.New("PDF object stream is itself stored in an object stream")
		}
		ref, ok := typeOne[streamNumber]
		if !ok {
			return fmt.Errorf("PDF object stream %d was not found", streamNumber)
		}
		n.skip[streamNumber] = true
		body, err := n.doc.objectBodyContext(ctx, ref)
		if err != nil {
			return err
		}
		dict, raw, err := n.doc.parseStreamContext(ctx, body)
		if err != nil {
			return fmt.Errorf("invalid PDF object stream %d: %w", streamNumber, err)
		}
		if kind := dict["Type"]; kind.kind != pdfValueName || kind.name != "ObjStm" {
			return fmt.Errorf("PDF object %d is not an object stream", streamNumber)
		}
		if security != nil {
			if raw, err = security.decryptStream(ref, raw); err != nil {
				return err
			}
		}
		decoded, err := n.decodeContainer(ctx, dict, raw)
		if err != nil {
			return fmt.Errorf("invalid PDF object stream %d: %w", streamNumber, err)
		}
		count, err := optionalPDFInt(dict, "N", -1)
		if err != nil || count < 0 || count > MaxXrefEntries {
			return fmt.Errorf("PDF object stream %d has an invalid N", streamNumber)
		}
		first, err := optionalPDFInt(dict, "First", -1)
		if err != nil || first < 0 || first > len(decoded) {
			return fmt.Errorf("PDF object stream %d has an invalid First", streamNumber)
		}
		numbers := make([]int, count)
		offsets := make([]int, count)
		pos := 0
		for i := 0; i < count; i++ {
			pos = skipPDFSpace(decoded[:first], pos)
			number, _, next, ok := readPDFIntToken(decoded[:first], pos)
			if !ok || number < 0 {
				return fmt.Errorf("PDF object stream %d has an invalid header", streamNumber)
			}
			pos = skipPDFSpace(decoded[:first], next)
			offset, _, next, ok := readPDFIntToken(decoded[:first], pos)
			if !ok || offset < 0 || first+offset > len(decoded) || (i > 0 && offset < offsets[i-1]) {
				return fmt.Errorf("PDF object stream %d has an invalid header", streamNumber)
			}
			pos = next
			numbers[i], offsets[i] = number, offset
		}
		for _, objectNumber := range streams[streamNumber] {
			index := n.packed[objectNumber].index
			if index < 0 || index >= count || numbers[index] != objectNumber {
				// A stale xref entry naming a slot that no longer holds the
				// object resolves to null, as in conforming readers.
				delete(n.packed, objectNumber)
				continue
			}
			end := len(decoded)
			if index+1 < count {
				end = first + offsets[index+1]
			}
			body := bytes.TrimSpace(decoded[first+offsets[index] : end])
			n.doc.cache[ObjRef{num: objectNumber}] = append([]byte{}, body...)
		}
	}
	return nil
}

func (n *pdfNormalizer) write(ctx context.Context, security *pdfSecurityHandler, maxBytes int64) ([]byte, error) {
	refs := make([]ObjRef, 0, len(n.doc.offsets)+len(n.packed))
	for ref := range n.doc.offsets {
		if !n.skip[ref.num] {
			refs = append(refs, ref)
		}
	}
	for objectNumber := range n.packed {
		if !n.skip[objectNumber] {
			refs = append(refs, ObjRef{num: objectNumber})
		}
	}
	sort.Slice(refs, func(i, j int) bool { return refs[i].num < refs[j].num })

	var out bytes.Buffer
	out.WriteString("%PDF-1.7\n%\xe2\xe3\xcf\xd3\n")
	offsets := make(map[int]ObjRef, len(refs))
	positions := make(map[int]int, len(refs))
	maxNumber := 0
	for _, ref := range refs {
		if err := importContextErr(ctx); err != nil {
			return nil, err
		}
		_, packed := n.packed[ref.num]
		body, err := n.doc.objectBodyContext(ctx, ref)
		if err != nil {
			return nil, err
		}
		if security != nil && !packed {
			if body, err = n.decryptObject(ctx, security, ref, body); err != nil {
				return nil, err
			}
		}
		offsets[ref.num] = ref
		positions[ref.num] = out.Len()
		if ref.num > maxNumber {
			maxNumber = ref.num
		}
		fmt.Fprintf(&out, "%d %d obj\n", ref.num, ref.gen)
		out.Write(body)
		out.WriteString("\nendobj\n")
		if int64(out.Len()) > maxBytes {
			return nil, ErrSourceTooLarge
		}
	}

	root, ok := pdfValueAsRef(n.trailer["Root"])
	if !ok {
		return nil, errors.New("PDF trailer does not contain a root catalog")
	}
	xrefOffset := out.Len()
	fmt.Fprintf(&out, "xref\n0 %d\n", maxNumber+1)
	out.WriteString("0000000000 65535 f\r\n")
	for number := 1; number <= maxNumber; number++ {
		ref, ok := offsets[number]
		if !ok {
			out.WriteString("0000000000 00000 f\r\n")
			continue
		}
		fmt.Fprintf(&out, "%010d %05d n\r\n", positions[number], ref.gen)
	}
	fmt.Fprintf(&out, "trailer\n<< /Size %d /Root %d %d R", maxNumber+1, root.num, root.gen)
	if info, ok := pdfValueAsRef(n.trailer["Info"]); ok && !n.skip[info.num] {
		if _, present := offsets[info.num]; present {
			fmt.Fprintf(&out, " /Info %d %d R", offsets[info.num].num, offsets[info.num].gen)
		}
	}
	if id := n.trailer["ID"]; id.kind == pdfValueArray {
		out.WriteString(" /ID ")
		out.Write(id.raw)
	}
	fmt.Fprintf(&out, " >>\nstartxref\n%d\n%%%%EOF\n", xrefOffset)
	if int64(out.Len()) > maxBytes {
		return nil, ErrSourceTooLarge
	}
	return out.Bytes(), nil
}

// decryptObject rewrites one encrypted indirect object: every string is
// replaced by its decrypted bytes and stream data is decrypted with a direct
// Length. Objects inside object streams are never encrypted individually.
func (n *pdfNormalizer) decryptObject(ctx context.Context, security *pdfSecurityHandler, ref ObjRef, body []byte) ([]byte, error) {
	decryptString := func(data []byte) ([]byte, error) { return security.decryptString(ref, data) }
	streamPos := findPDFStreamKeyword(body)
	if streamPos < 0 {
		parser := newPDFValueParserContext(ctx, body)
		value, err := parser.parseValue()
		if err != nil {
			return nil, fmt.Errorf("invalid encrypted PDF object %d %d R: %w", ref.num, ref.gen, err)
		}
		var out bytes.Buffer
		if err := writeNormalizedPDFValue(&out, value, decryptString); err != nil {
			return nil, err
		}
		return out.Bytes(), nil
	}
	dict, raw, err := n.doc.parseStreamContext(ctx, body)
	if err != nil {
		return nil, fmt.Errorf("invalid encrypted PDF stream %d %d R: %w", ref.num, ref.gen, err)
	}
	if filters, err := pdfStreamFilters(dict["Filter"]); err == nil && len(filters) > 0 && filters[0] == "Crypt" {
		return nil, fmt.Errorf("%w: per-stream crypt filters", ErrUnsupportedEncryption)
	}
	isMetadata := dict["Type"].kind == pdfValueName && dict["Type"].name == "Metadata"
	plain := raw
	if !isMetadata || security.encryptMetadata {
		if plain, err = security.decryptStream(ref, raw); err != nil {
			return nil, err
		}
	}
	dict["Length"] = pdfValue{kind: pdfValueNumber, number: float64(len(plain)), raw: []byte(strconv.Itoa(len(plain)))}
	var out bytes.Buffer
	if err := writeNormalizedPDFValue(&out, pdfValue{kind: pdfValueDict, dict: dict}, decryptString); err != nil {
		return nil, err
	}
	out.WriteString("\nstream\n")
	out.Write(plain)
	out.WriteString("\nendstream")
	return out.Bytes(), nil
}

// writeNormalizedPDFValue serializes a parsed value, re-encoding every string
// as a hexadecimal string after passing its bytes through transform.
func writeNormalizedPDFValue(out *bytes.Buffer, value pdfValue, transform func([]byte) ([]byte, error)) error {
	switch value.kind {
	case pdfValueDict:
		keys := make([]string, 0, len(value.dict))
		for key := range value.dict {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		out.WriteString("<<")
		for _, key := range keys {
			out.WriteByte('/')
			out.WriteString(encodePDFName(key))
			out.WriteByte(' ')
			if err := writeNormalizedPDFValue(out, value.dict[key], transform); err != nil {
				return err
			}
			out.WriteByte(' ')
		}
		out.WriteString(">>")
	case pdfValueArray:
		out.WriteByte('[')
		for i, item := range value.array {
			if i > 0 {
				out.WriteByte(' ')
			}
			if err := writeNormalizedPDFValue(out, item, transform); err != nil {
				return err
			}
		}
		out.WriteByte(']')
	case pdfValueRaw:
		if decoded, ok := pdfStringBytes(value); ok {
			plain, err := transform(decoded)
			if err != nil {
				return err
			}
			out.WriteByte('<')
			const digits = "0123456789abcdef"
			for _, b := range plain {
				out.WriteByte(digits[b>>4])
				out.WriteByte(digits[b&0x0f])
			}
			out.WriteByte('>')
			return nil
		}
		out.Write(value.raw)
	default:
		out.Write(value.raw)
	}
	return nil
}

func encodePDFName(name string) string {
	var out bytes.Buffer
	for i := 0; i < len(name); i++ {
		ch := name[i]
		if ch < 0x21 || ch > 0x7e || ch == '#' || isPDFDelimiter(ch) {
			fmt.Fprintf(&out, "#%02X", ch)
			continue
		}
		out.WriteByte(ch)
	}
	return out.String()
}

// decodeNormalizedStreamContext decodes the container streams the normalizer
// itself must read (xref and object streams): no filter or FlateDecode, with an
// optional PNG predictor.
func decodeNormalizedStreamContext(ctx context.Context, dict pdfDict, data []byte, limit int) ([]byte, error) {
	if limit <= 0 {
		return nil, errors.New("PDF xref and object streams exceed maximum decoded size")
	}
	filters, err := pdfStreamFilters(dict["Filter"])
	if err != nil {
		return nil, err
	}
	var decoded []byte
	switch {
	case len(filters) == 0:
		if len(data) > limit {
			return nil, errors.New("PDF xref and object streams exceed maximum decoded size")
		}
		decoded = data
	case len(filters) == 1 && isFlateFilter(filters[0]):
		if decoded, err = uncompressStreamContext(ctx, data, limit); err != nil {
			return nil, err
		}
	default:
		return nil, fmt.Errorf("filters %v are not supported in xref or object streams", filters)
	}
	parms := dict["DecodeParms"]
	if parms.kind == pdfValueArray && len(parms.array) == 1 {
		parms = parms.array[0]
	}
	if parms.kind != pdfValueDict {
		return decoded, nil
	}
	predictor, err := optionalPDFInt(parms.dict, "Predictor", 1)
	if err != nil {
		return nil, err
	}
	if predictor == 1 {
		return decoded, nil
	}
	if predictor < 10 {
		return nil, fmt.Errorf("PDF predictor %d is not supported", predictor)
	}
	columns, err := optionalPDFInt(parms.dict, "Columns", 1)
	if err != nil {
		return nil, err
	}
	colors, err := optionalPDFInt(parms.dict, "Colors", 1)
	if err != nil {
		return nil, err
	}
	bits, err := optionalPDFInt(parms.dict, "BitsPerComponent", 8)
	if err != nil {
		return nil, err
	}
	return undoPNGPredictor(decoded, columns, colors, bits)
}

func undoPNGPredictor(data []byte, columns, colors, bits int) ([]byte, error) {
	if columns <= 0 || colors <= 0 || bits <= 0 || columns > 1<<20 || colors > 32 || bits > 16 {
		return nil, errors.New("PDF predictor parameters are invalid")
	}
	rowBytes := (columns*colors*bits + 7) / 8
	if rowBytes >= len(data) {
		if len(data) == 0 {
			return data, nil
		}
		return nil, errors.New("PDF predictor row exceeds the stream data")
	}
	pixelBytes := (colors*bits + 7) / 8
	out := make([]byte, 0, len(data))
	previous := make([]byte, rowBytes)
	for pos := 0; pos < len(data); pos += rowBytes + 1 {
		if pos+1+rowBytes > len(data) {
			break
		}
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
				return nil, fmt.Errorf("PDF PNG predictor row type %d is invalid", kind)
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
