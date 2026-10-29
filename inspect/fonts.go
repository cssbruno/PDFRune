// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import (
	"sort"
	"strconv"
	"strings"
	"unicode/utf16"
)

const (
	maxCMapEntries       = 64 * 1024
	maxCodeBytes         = 4
	defaultGlyphWidth    = 0.5
	glyphUnitsPerEm      = 1000
	defaultCIDGlyphWidth = 1000
	// maxCMapTextBytes bounds one CMap destination (128 UTF-16 units, far
	// past any ligature); text is produced per glyph, so a destination of
	// megabytes would be copied for every glyph shown.
	maxCMapTextBytes = 256
	// maxCodeSpaces bounds the codespace ranges read from a CMap, which are
	// tried in turn for every glyph; real CMaps declare a handful.
	maxCodeSpaces = 256
)

// pdfFont decodes the character codes of one font resource to Unicode and
// reports their advance widths in text space units (fractions of an em).
type pdfFont struct {
	composite  bool
	codeSpaces []pdfCodeSpace
	toUnicode  *pdfToUnicode
	// simple holds the encoding-derived text of each single-byte code of a
	// simple font; composite fonts leave it empty.
	simple [256]string
	// utf16Codes marks a composite font whose CMap encodes UTF-16BE code
	// units directly (the predefined Uni*-UCS2-* and Uni*-UTF16-* CMaps).
	utf16Codes bool
	identity   bool
	widths     pdfFontWidths
}

type pdfCodeSpace struct {
	low, high [maxCodeBytes]byte
	length    int
}

type pdfFontWidths struct {
	known      bool
	firstChar  int
	simple     []float64
	missing    float64
	cidDefault float64
	cidSingle  map[uint32]float64
	cidRanges  []pdfCIDWidthRange
	scale      float64
}

type pdfCIDWidthRange struct {
	first, last uint32
	width       float64
}

// pdfToUnicode is a parsed /ToUnicode CMap. bfchar entries win over ranges.
type pdfToUnicode struct {
	chars  map[uint32]string
	ranges []pdfUnicodeRange
}

type pdfUnicodeRange struct {
	low, high uint32
	base      []uint16
	array     []string
}

// pdfGlyph is one decoded character code.
type pdfGlyph struct {
	text  string
	width float64
	space bool
}

// nextGlyph decodes the character code at the start of raw and returns the
// number of bytes it used.
func (f *pdfFont) nextGlyph(raw []byte) (pdfGlyph, int) {
	length := 1
	if f.composite {
		length = f.codeLength(raw)
	}
	code := uint32(0)
	for _, b := range raw[:length] {
		code = code<<8 | uint32(b)
	}
	glyph := pdfGlyph{width: f.widths.width(code, f), space: length == 1 && code == ' '}
	if f.toUnicode != nil {
		if text, ok := f.toUnicode.lookup(code); ok {
			glyph.text = text
			return glyph, length
		}
	}
	switch {
	case !f.composite:
		glyph.text = f.simple[code]
	case f.utf16Codes && length%2 == 0:
		units := make([]uint16, 0, length/2)
		for i := 0; i+1 < length; i += 2 {
			units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
		}
		glyph.text = string(utf16.Decode(units))
	}
	return glyph, length
}

// codeLength picks the code width of a composite font from its codespace
// ranges, defaulting to the two-byte codes of Identity-H and Identity-V.
func (f *pdfFont) codeLength(raw []byte) int {
	shortest := 0
	for _, space := range f.codeSpaces {
		if space.length > len(raw) {
			continue
		}
		if shortest == 0 || space.length < shortest {
			shortest = space.length
		}
		if space.matches(raw[:space.length]) {
			return space.length
		}
	}
	if shortest == 0 {
		shortest = min(2, len(raw))
	}
	return shortest
}

func (s pdfCodeSpace) matches(code []byte) bool {
	for i, b := range code {
		if b < s.low[i] || b > s.high[i] {
			return false
		}
	}
	return true
}

func (w *pdfFontWidths) width(code uint32, font *pdfFont) float64 {
	if !w.known {
		return defaultGlyphWidth
	}
	if !font.composite {
		index := int(code) - w.firstChar
		if index >= 0 && index < len(w.simple) {
			return w.simple[index] * w.scale
		}
		return w.missing * w.scale
	}
	if value, ok := w.cidSingle[code]; ok {
		return value * w.scale
	}
	index := sort.Search(len(w.cidRanges), func(i int) bool { return w.cidRanges[i].last >= code })
	if index < len(w.cidRanges) && w.cidRanges[index].first <= code {
		return w.cidRanges[index].width * w.scale
	}
	return w.cidDefault * w.scale
}

func (m *pdfToUnicode) lookup(code uint32) (string, bool) {
	if text, ok := m.chars[code]; ok {
		return text, true
	}
	index := sort.Search(len(m.ranges), func(i int) bool { return m.ranges[i].high >= code })
	for ; index < len(m.ranges) && m.ranges[index].low <= code; index++ {
		r := m.ranges[index]
		if code > r.high {
			continue
		}
		offset := code - r.low
		if r.array != nil {
			if int(offset) < len(r.array) {
				return r.array[offset], true
			}
			return "", false
		}
		if len(r.base) == 0 {
			return "", false
		}
		units := append([]uint16(nil), r.base...)
		units[len(units)-1] += uint16(offset)
		return string(utf16.Decode(units)), true
	}
	return "", false
}

// loadPDFFont builds a font decoder from a font dictionary. Fonts that cannot
// be decoded produce no text rather than misdecoded bytes.
func (r *pdfResourceObjects) loadPDFFont(fontObject pdfObject) (*pdfFont, error) {
	font := &pdfFont{}
	dict := r.resolve(fontObject)
	subtype := r.resolve(dict.get("Subtype")).name
	if toUnicode := dict.get("ToUnicode"); toUnicode.kind == pdfObjectRef {
		_, data, ok, err := r.stream(toUnicode)
		if err != nil {
			return nil, err
		}
		if ok {
			parsed, spaces, err := parseToUnicodeCMap(r.ctx, data)
			if err != nil {
				return nil, err
			}
			font.toUnicode = parsed
			font.codeSpaces = spaces
		}
	}
	if subtype == "Type0" {
		font.composite = true
		if err := r.loadCompositeEncoding(font, dict.get("Encoding")); err != nil {
			return nil, err
		}
		descendants := r.resolve(dict.get("DescendantFonts"))
		if descendants.kind == pdfObjectArray && len(descendants.array) > 0 {
			r.loadCIDWidths(font, r.resolve(descendants.array[0]))
		}
		return font, nil
	}
	font.simple = r.simpleFontEncoding(dict, subtype)
	r.loadSimpleWidths(font, dict, subtype)
	return font, nil
}

func (r *pdfResourceObjects) loadCompositeEncoding(font *pdfFont, encoding pdfObject) error {
	switch resolved := r.resolve(encoding); resolved.kind {
	case pdfObjectName:
		name := resolved.name
		font.identity = name == "Identity-H" || name == "Identity-V"
		font.utf16Codes = strings.HasPrefix(name, "Uni") && (strings.Contains(name, "UCS2") || strings.Contains(name, "UTF16"))
		if font.identity || font.utf16Codes {
			font.codeSpaces = []pdfCodeSpace{{high: [maxCodeBytes]byte{0xff, 0xff}, length: 2}}
		}
	case pdfObjectDict:
		_, data, ok, err := r.stream(encoding)
		if err != nil || !ok {
			return err
		}
		_, spaces, err := parseToUnicodeCMap(r.ctx, data)
		if err != nil {
			return err
		}
		if len(spaces) > 0 {
			font.codeSpaces = spaces
		}
	}
	return nil
}

func (r *pdfResourceObjects) loadCIDWidths(font *pdfFont, descendant pdfObject) {
	widths := &font.widths
	widths.scale = 1.0 / glyphUnitsPerEm
	widths.cidDefault = pdfObjectNumberOr(r.resolve(descendant.get("DW")), defaultCIDGlyphWidth)
	// CIDs equal codes only for the Identity CMaps; other CMaps keep the
	// estimated widths so layout does not trust a wrong lookup.
	widths.known = font.identity
	entries := r.resolve(descendant.get("W"))
	if entries.kind != pdfObjectArray {
		return
	}
	widths.cidSingle = make(map[uint32]float64)
	count := 0
	for i := 0; i < len(entries.array) && count < maxCMapEntries; {
		first, ok := pdfObjectInteger(r.resolve(entries.array[i]))
		if !ok || first < 0 || i+1 >= len(entries.array) {
			break
		}
		next := r.resolve(entries.array[i+1])
		if next.kind == pdfObjectArray {
			for j, value := range next.array {
				widths.cidSingle[uint32(first+j)] = pdfObjectNumberOr(r.resolve(value), widths.cidDefault)
				count++
			}
			i += 2
			continue
		}
		last, ok := pdfObjectInteger(next)
		if !ok || last < first || i+2 >= len(entries.array) {
			break
		}
		widths.cidRanges = append(widths.cidRanges, pdfCIDWidthRange{
			first: uint32(first), last: uint32(last),
			width: pdfObjectNumberOr(r.resolve(entries.array[i+2]), widths.cidDefault),
		})
		count++
		i += 3
	}
	sort.SliceStable(widths.cidRanges, func(i, j int) bool { return widths.cidRanges[i].first < widths.cidRanges[j].first })
}

func (r *pdfResourceObjects) loadSimpleWidths(font *pdfFont, dict pdfObject, subtype string) {
	widths := &font.widths
	widths.scale = 1.0 / glyphUnitsPerEm
	if subtype == "Type3" {
		matrix := r.resolve(dict.get("FontMatrix"))
		if matrix.kind == pdfObjectArray && len(matrix.array) == 6 {
			widths.scale = pdfObjectNumberOr(r.resolve(matrix.array[0]), widths.scale)
		}
	}
	values := r.resolve(dict.get("Widths"))
	first, ok := pdfObjectInteger(r.resolve(dict.get("FirstChar")))
	if values.kind != pdfObjectArray || !ok || first < 0 || first > 255 {
		standardFontWidths(widths, r.resolve(dict.get("BaseFont")).name)
		return
	}
	widths.known = true
	widths.firstChar = first
	widths.missing = pdfObjectNumberOr(r.resolve(r.resolve(dict.get("FontDescriptor")).get("MissingWidth")), 0)
	widths.simple = make([]float64, 0, min(len(values.array), 256))
	for _, value := range values.array[:min(len(values.array), 256)] {
		widths.simple = append(widths.simple, pdfObjectNumberOr(r.resolve(value), widths.missing))
	}
}

// simpleFontEncoding builds the code-to-text table of a simple font from its
// base encoding and /Differences.
func (r *pdfResourceObjects) simpleFontEncoding(dict pdfObject, subtype string) [256]string {
	var table [256]string
	baseFont := r.resolve(dict.get("BaseFont")).name
	if plus := strings.IndexByte(baseFont, '+'); plus >= 0 {
		baseFont = baseFont[plus+1:]
	}
	flags, _ := pdfObjectInteger(r.resolve(r.resolve(dict.get("FontDescriptor")).get("Flags")))
	symbolic := flags&4 != 0 && flags&32 == 0

	encoding := r.resolve(dict.get("Encoding"))
	baseName := ""
	switch encoding.kind {
	case pdfObjectName:
		baseName = encoding.name
	case pdfObjectDict:
		baseName = r.resolve(encoding.get("BaseEncoding")).name
	}
	var base *[256]rune
	fillFromWinAnsi := false
	switch {
	case baseName == "WinAnsiEncoding":
		base = &winAnsiEncoding
	case baseName == "MacRomanEncoding":
		base = &macRomanEncoding
	case baseName == "StandardEncoding":
		base = &standardEncoding
	case baseFont == "Symbol":
		base = &symbolEncoding
	case baseFont == "ZapfDingbats":
	case (subtype == "Type1" || subtype == "MMType1") && !symbolic:
		// Type 1 fonts default to StandardEncoding; codes it leaves
		// undefined are read as WinAnsi, which is what generators that omit
		// /Encoding usually meant.
		base = &standardEncoding
		fillFromWinAnsi = true
	default:
		base = &winAnsiEncoding
	}
	if base != nil {
		for code, value := range base {
			if value == 0 && fillFromWinAnsi {
				value = winAnsiEncoding[code]
			}
			if value != 0 {
				table[code] = string(value)
			}
		}
	}

	differences := r.resolve(encoding.get("Differences"))
	if differences.kind != pdfObjectArray {
		return table
	}
	code := -1
	for _, item := range differences.array {
		item = r.resolve(item)
		switch item.kind {
		case pdfObjectNumber:
			if value, ok := pdfObjectInteger(item); ok {
				code = value
			} else {
				code = -1
			}
		case pdfObjectName:
			if code >= 0 && code <= 255 {
				table[code], _ = glyphNameText(item.name)
			}
			if code >= 0 {
				code++
			}
		}
	}
	return table
}

// glyphNameText maps a glyph name to Unicode with the Adobe Glyph List rules:
// a suffix after '.' is dropped, '_' joins ligature components, and uniXXXX
// or uXXXX[XX] names carry their code points.
func glyphNameText(name string) (string, bool) {
	if dot := strings.IndexByte(name, '.'); dot >= 0 {
		name = name[:dot]
	}
	if name == "" {
		return "", false
	}
	var text strings.Builder
	for component := range strings.SplitSeq(name, "_") {
		value, ok := glyphComponentText(component)
		if !ok {
			return "", false
		}
		text.WriteString(value)
	}
	return text.String(), true
}

func glyphComponentText(component string) (string, bool) {
	if value, ok := adobeGlyphNames[component]; ok {
		return string(value), true
	}
	if hexDigits, ok := strings.CutPrefix(component, "uni"); ok && len(hexDigits) >= 4 && len(hexDigits)%4 == 0 {
		var text strings.Builder
		for i := 0; i < len(hexDigits); i += 4 {
			value, err := strconv.ParseUint(hexDigits[i:i+4], 16, 16)
			if err != nil || (value >= 0xd800 && value <= 0xdfff) {
				return "", false
			}
			text.WriteRune(rune(value))
		}
		return text.String(), true
	}
	if hexDigits, ok := strings.CutPrefix(component, "u"); ok && len(hexDigits) >= 4 && len(hexDigits) <= 6 {
		value, err := strconv.ParseUint(hexDigits, 16, 32)
		if err != nil || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff) {
			return "", false
		}
		return string(rune(value)), true
	}
	return "", false
}

// helveticaWidths are the Helvetica AFM advances for codes 32 to 126.
var helveticaWidths = [95]float64{
	278, 278, 355, 556, 556, 889, 667, 191, 333, 333, 389, 584, 278, 333, 278, 278,
	556, 556, 556, 556, 556, 556, 556, 556, 556, 556, 278, 278, 584, 584, 584, 556,
	1015, 667, 667, 722, 722, 667, 611, 778, 722, 278, 500, 667, 556, 833, 722, 778,
	667, 778, 722, 667, 611, 722, 667, 944, 667, 667, 611, 278, 278, 278, 469, 556,
	333, 556, 556, 500, 556, 556, 278, 556, 556, 222, 222, 500, 222, 833, 556, 556,
	556, 556, 333, 500, 278, 556, 500, 722, 500, 500, 500, 334, 260, 334, 584,
}

// standardFontWidths fills the widths of a standard 14 font written without
// /Widths, which generators such as PaperRune do. Helvetica (and Arial, which
// shares its metrics) and Courier are exact for ASCII; other codes use the
// font's typical letter width. Other fonts keep estimated widths.
func standardFontWidths(widths *pdfFontWidths, baseFont string) {
	if plus := strings.IndexByte(baseFont, '+'); plus >= 0 {
		baseFont = baseFont[plus+1:]
	}
	var ascii [95]float64
	other := 556.0
	switch {
	case strings.HasPrefix(baseFont, "Courier"):
		for i := range ascii {
			ascii[i] = 600
		}
		other = 600
	case baseFont == "Helvetica" || baseFont == "Helvetica-Oblique" || baseFont == "Arial" || baseFont == "ArialMT":
		ascii = helveticaWidths
	default:
		return
	}
	widths.known = true
	widths.firstChar = 0
	widths.missing = other
	widths.simple = make([]float64, 256)
	for code := range widths.simple {
		widths.simple[code] = other
		if code >= 32 && code <= 126 {
			widths.simple[code] = ascii[code-32]
		}
	}
}
