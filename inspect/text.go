// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import (
	"context"
	"errors"
	"fmt"
	"math"
	"strconv"
	"strings"
	"unicode/utf8"
)

const (
	// spaceAdjustment is the TJ displacement, in thousandths of an em, at or
	// below which a gap reads as a word break.
	spaceAdjustment = -200
	// Layout thresholds are fractions of the font size in device space.
	lineBreakFraction  = 0.5
	wordGapFraction    = 0.15
	backtrackFraction  = 0.5
	defaultFontSize    = 1
	horizontalScaleMax = 100
)

type pdfMatrix [6]float64

var identityMatrix = pdfMatrix{1, 0, 0, 1, 0, 0}

func (m pdfMatrix) multiply(n pdfMatrix) pdfMatrix {
	return pdfMatrix{
		m[0]*n[0] + m[1]*n[2], m[0]*n[1] + m[1]*n[3],
		m[2]*n[0] + m[3]*n[2], m[2]*n[1] + m[3]*n[3],
		m[4]*n[0] + m[5]*n[2] + n[4], m[4]*n[1] + m[5]*n[3] + n[5],
	}
}

// translate returns translate(tx, ty) x m.
func (m pdfMatrix) translate(tx, ty float64) pdfMatrix {
	m[4] += tx*m[0] + ty*m[2]
	m[5] += tx*m[1] + ty*m[3]
	return m
}

type pdfOperandKind uint8

const (
	pdfOperandOther pdfOperandKind = iota
	pdfOperandNumber
	pdfOperandName
	pdfOperandString
	pdfOperandArray
)

// pdfOperand is one pending content-stream operand. Strings keep their raw
// bytes so the current font decodes them when the operator runs.
type pdfOperand struct {
	kind   pdfOperandKind
	number float64
	name   string
	raw    []byte
	items  []pdfArrayItem
}

type pdfArrayItem struct {
	raw      []byte
	adjust   float64
	isString bool
}

type pdfMarkedContentFrame struct {
	actualText bool
	// replacement is emitted before the first glyph it replaces, or at EMC
	// when the span draws no text.
	replacement string
	emitted     bool
}

// textGraphicsState is the part of the graphics state that positions text.
type textGraphicsState struct {
	ctm       pdfMatrix
	charSpace float64
	wordSpace float64
	scale     float64
	leading   float64
	fontSize  float64
	font      *pdfFont
	hasFont   bool
}

// textExtractor interprets page and Form XObject content streams, decodes
// shown strings through their fonts, and separates runs by layout.
type textExtractor struct {
	ctx     context.Context
	scanner *pdfTextScanner
	out     strings.Builder
	objects *pdfResourceObjects
	fonts   map[streamObjectRef]*pdfFont
	// directFonts holds fonts written inside this extractor's resources, by
	// resource name; without it each Tf rebuilt their /W or /Differences.
	directFonts map[string]*pdfFont

	state         textGraphicsState
	stack         []textGraphicsState
	stackFloor    int
	stackOverflow int
	inText        bool
	tm, tlm       pdfMatrix

	resources pdfObject
	forms     map[streamObjectRef]bool
	formDepth int

	suppressedTextDepth int
	actualTextFrame     *pdfMarkedContentFrame

	hasLast         bool
	lastEnd         [2]float64
	lastSize        float64
	lastKnownWidths bool
	moved           bool
	pendingSpace    bool
}

func newTextExtractor(ctx context.Context, objects *pdfResourceObjects, fonts map[streamObjectRef]*pdfFont, resources pdfObject) *textExtractor {
	if fonts == nil {
		fonts = make(map[streamObjectRef]*pdfFont)
	}
	return &textExtractor{
		ctx:       ctx,
		scanner:   newPDFTextScanner(ctx),
		objects:   objects,
		fonts:     fonts,
		state:     textGraphicsState{ctm: identityMatrix, scale: 1},
		resources: resources,
		forms:     make(map[streamObjectRef]bool),
	}
}

func textFromContentStreamContext(ctx context.Context, stream []byte) (string, error) {
	extractor := newTextExtractor(ctx, nil, nil, pdfObject{})
	if err := extractor.run(stream); err != nil {
		return "", err
	}
	if err := inspectContextErr(ctx); err != nil {
		return "", err
	}
	return extractor.out.String(), nil
}

// run interprets one content stream. A malformed inline image ends the
// stream but keeps the text extracted before it.
func (e *textExtractor) run(stream []byte) error {
	operands := make([]pdfOperand, 0, textTokenCapacity)
	markedContent := make([]*pdfMarkedContentFrame, 0, textTokenCapacity)
	operandCount := 0
	pendingActualText := false
	actualText := ""
	actualTextPresent := false
	defer func() {
		for i := len(markedContent) - 1; i >= 0; i-- {
			e.endMarkedContent(markedContent[i])
		}
	}()

	resetOperands := func() {
		operands = operands[:0]
		operandCount = 0
		pendingActualText = false
		actualText = ""
		actualTextPresent = false
	}
	addOperand := func(operand pdfOperand) error {
		operandCount++
		if operandCount > maxTextOperands {
			return fmt.Errorf("%w: pending operand count exceeds %d", ErrTextLimitExceeded, maxTextOperands)
		}
		if len(operands) < textTokenCapacity {
			operands = append(operands, operand)
			return nil
		}
		copy(operands, operands[1:])
		operands[len(operands)-1] = operand
		return nil
	}
	addString := func(raw []byte) error {
		if pendingActualText {
			actualText, actualTextPresent = decodePDFTextBytes(raw), true
		}
		pendingActualText = false
		return addOperand(pdfOperand{kind: pdfOperandString, raw: raw})
	}

	for i := 0; i < len(stream); {
		if err := e.scanner.check(i); err != nil {
			return err
		}
		var err error
		i, err = skipPDFWhitespaceAndCommentsContext(e.scanner, stream, i)
		if err != nil {
			return err
		}
		if i >= len(stream) {
			break
		}

		switch stream[i] {
		case '(':
			raw, next, err := readPDFLiteralStringContext(e.scanner, stream, i, maxExtractedTextBytes)
			if err != nil {
				return err
			}
			if err := addString(raw); err != nil {
				return err
			}
			i = next
		case '<':
			if i+1 < len(stream) && stream[i+1] == '<' {
				i += 2
				continue
			}
			raw, next, err := readPDFHexStringContext(e.scanner, stream, i, maxExtractedTextBytes)
			if err != nil {
				return err
			}
			if err := addString(raw); err != nil {
				return err
			}
			i = next
		case '[':
			items, next, err := readPDFArrayOperandContext(e.scanner, stream, i, maxExtractedTextBytes)
			if err != nil {
				return err
			}
			pendingActualText = false
			if err := addOperand(pdfOperand{kind: pdfOperandArray, items: items}); err != nil {
				return err
			}
			i = next
		case '/':
			name, next := readPDFName(stream, i)
			pendingActualText = name == "ActualText"
			if err := addOperand(pdfOperand{kind: pdfOperandName, name: name}); err != nil {
				return err
			}
			i = next
		default:
			word, next := readPDFWord(stream, i)
			if word == "" {
				i++
				continue
			}

			if number, ok := parsePDFNumber(word); ok {
				pendingActualText = false
				if err := addOperand(pdfOperand{kind: pdfOperandNumber, number: number}); err != nil {
					return err
				}
				i = next
				continue
			}
			if isPDFOperandWord(word) {
				pendingActualText = false
				if err := addOperand(pdfOperand{}); err != nil {
					return err
				}
				i = next
				continue
			}

			switch word {
			case "BDC":
				frame := &pdfMarkedContentFrame{actualText: actualTextPresent, replacement: actualText}
				if len(markedContent) >= maxTextNestingDepth {
					return fmt.Errorf("%w: marked-content nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
				}
				if frame.actualText {
					if e.suppressedTextDepth == 0 {
						e.actualTextFrame = frame
					}
					e.suppressedTextDepth++
				}
				markedContent = append(markedContent, frame)
			case "BMC":
				if len(markedContent) >= maxTextNestingDepth {
					return fmt.Errorf("%w: marked-content nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
				}
				markedContent = append(markedContent, &pdfMarkedContentFrame{})
			case "EMC":
				if len(markedContent) > 0 {
					frame := markedContent[len(markedContent)-1]
					markedContent = markedContent[:len(markedContent)-1]
					if err := e.endMarkedContent(frame); err != nil {
						return err
					}
				}
			case "q":
				e.saveState()
			case "Q":
				e.restoreState()
			case "cm":
				if m, ok := matrixOperand(operands); ok {
					e.state.ctm = m.multiply(e.state.ctm)
					e.moved = true
				}
			case "BT":
				e.inText = true
				e.tm, e.tlm = identityMatrix, identityMatrix
				e.moved = true
			case "ET":
				e.inText = false
			case "Tf":
				if len(operands) >= 2 && operands[len(operands)-2].kind == pdfOperandName {
					e.state.fontSize = numberOperand(operands, 1, e.state.fontSize)
					if err := e.selectFont(operands[len(operands)-2].name); err != nil {
						return err
					}
				}
			case "Tc":
				e.state.charSpace = numberOperand(operands, 1, e.state.charSpace)
			case "Tw":
				e.state.wordSpace = numberOperand(operands, 1, e.state.wordSpace)
			case "Tz":
				e.state.scale = numberOperand(operands, 1, e.state.scale*horizontalScaleMax) / horizontalScaleMax
			case "TL":
				e.state.leading = numberOperand(operands, 1, e.state.leading)
			case "Td", "TD":
				if len(operands) >= 2 && operands[len(operands)-1].kind == pdfOperandNumber && operands[len(operands)-2].kind == pdfOperandNumber {
					tx, ty := operands[len(operands)-2].number, operands[len(operands)-1].number
					if word == "TD" {
						e.state.leading = -ty
					}
					e.moveLine(tx, ty)
				}
			case "Tm":
				if m, ok := matrixOperand(operands); ok {
					e.tm, e.tlm = m, m
					e.moved = true
				}
			case "T*":
				e.moveLine(0, -e.state.leading)
			case "Tj", "'", "\"", "TJ":
				if word == "\"" && len(operands) >= 3 {
					e.state.wordSpace = numberOperand(operands, 3, e.state.wordSpace)
					e.state.charSpace = numberOperand(operands, 2, e.state.charSpace)
				}
				if word != "Tj" && word != "TJ" {
					e.moveLine(0, -e.state.leading)
				}
				if e.inText && len(operands) > 0 {
					if err := e.show(operands[len(operands)-1], word == "TJ"); err != nil {
						return err
					}
				}
			case "Do":
				if len(operands) > 0 && operands[len(operands)-1].kind == pdfOperandName {
					if err := e.doXObject(operands[len(operands)-1].name); err != nil {
						return err
					}
				}
			case "BI":
				inlineEnd, err := skipPDFInlineImage(e.scanner, stream, next)
				if err != nil {
					if errors.Is(err, ErrTextLimitExceeded) || inspectContextErr(e.ctx) != nil {
						return err
					}
					return nil
				}
				next = inlineEnd
			}
			resetOperands()
			i = next
		}
	}
	return nil
}

func (e *textExtractor) endMarkedContent(frame *pdfMarkedContentFrame) error {
	if !frame.actualText {
		return nil
	}
	e.suppressedTextDepth--
	if e.actualTextFrame != frame {
		return nil
	}
	e.actualTextFrame = nil
	if frame.emitted {
		return nil
	}
	frame.emitted = true
	return appendExtractedText(&e.out, frame.replacement)
}

func (e *textExtractor) saveState() {
	if len(e.stack) >= maxTextNestingDepth {
		e.stackOverflow++
		return
	}
	e.stack = append(e.stack, e.state)
}

func (e *textExtractor) restoreState() {
	if e.stackOverflow > 0 {
		e.stackOverflow--
		return
	}
	if len(e.stack) <= e.stackFloor {
		return
	}
	e.state = e.stack[len(e.stack)-1]
	e.stack = e.stack[:len(e.stack)-1]
	e.moved = true
}

func (e *textExtractor) moveLine(tx, ty float64) {
	e.tlm = e.tlm.translate(tx, ty)
	e.tm = e.tlm
	e.moved = true
}

// selectFont resolves a /Font resource name. A name the resources do not
// define keeps the legacy byte decoding used for streams without fonts.
func (e *textExtractor) selectFont(name string) error {
	e.state.font, e.state.hasFont = nil, false
	if e.objects == nil {
		return nil
	}
	fontObject := e.objects.resolve(e.objects.resolve(e.resources.get("Font")).get(name))
	if fontObject.kind != pdfObjectDict {
		return nil
	}
	reference := e.objects.resolve(e.resources.get("Font")).get(name)
	if reference.kind == pdfObjectRef {
		if font, ok := e.fonts[reference.ref]; ok {
			e.state.font, e.state.hasFont = font, true
			return nil
		}
	} else if font, ok := e.directFonts[name]; ok {
		e.state.font, e.state.hasFont = font, true
		return nil
	}
	font, err := e.objects.loadPDFFont(fontObject)
	if err != nil {
		return err
	}
	if reference.kind == pdfObjectRef {
		e.fonts[reference.ref] = font
	} else {
		if e.directFonts == nil {
			e.directFonts = make(map[string]*pdfFont)
		}
		e.directFonts[name] = font
	}
	e.state.font, e.state.hasFont = font, true
	return nil
}

// show renders a Tj, ', ", or TJ operand.
func (e *textExtractor) show(operand pdfOperand, array bool) error {
	if array {
		if operand.kind != pdfOperandArray {
			return nil
		}
		first := true
		for _, item := range operand.items {
			if !item.isString {
				e.advance(-item.adjust / glyphUnitsPerEm * e.state.fontSize * e.state.scale)
				if item.adjust <= spaceAdjustment {
					e.pendingSpace = true
				}
				continue
			}
			if err := e.showString(item.raw, first); err != nil {
				return err
			}
			first = false
		}
		return nil
	}
	if operand.kind != pdfOperandString {
		return nil
	}
	return e.showString(operand.raw, true)
}

func (e *textExtractor) advance(tx float64) {
	e.tm = e.tm.translate(tx, 0)
}

// showString decodes one string through the current font. startsRun marks
// the first string of an operator, where layout decides on a separator.
func (e *textExtractor) showString(raw []byte, startsRun bool) error {
	if startsRun {
		e.pendingSpace = false
		if separator := e.separator(); separator != "" {
			if err := e.writeSeparator(separator); err != nil {
				return err
			}
		}
	} else if e.pendingSpace {
		e.pendingSpace = false
		if err := e.writeSeparator(" "); err != nil {
			return err
		}
	}
	if e.suppressedTextDepth > 0 && e.actualTextFrame != nil && !e.actualTextFrame.emitted {
		e.actualTextFrame.emitted = true
		if err := appendExtractedText(&e.out, e.actualTextFrame.replacement); err != nil {
			return err
		}
	}
	visible := e.suppressedTextDepth == 0
	size := e.state.fontSize
	knownWidths := false

	if !e.state.hasFont {
		text := decodePDFTextBytes(raw)
		if visible {
			if err := appendExtractedText(&e.out, text); err != nil {
				return err
			}
		}
		for _, r := range text {
			tx := defaultGlyphWidth*size + e.state.charSpace
			if r == ' ' {
				tx += e.state.wordSpace
			}
			e.advance(tx * e.state.scale)
		}
	} else {
		font := e.state.font
		knownWidths = font.widths.known
		for pos, glyphs := 0, 0; pos < len(raw); glyphs++ {
			if glyphs%textContextCheckBytes == 0 {
				if err := inspectContextErr(e.ctx); err != nil {
					return err
				}
			}
			glyph, length := font.nextGlyph(raw[pos:])
			pos += length
			if visible && glyph.text != "" {
				if err := e.appendGlyphText(glyph.text); err != nil {
					return err
				}
			}
			tx := glyph.width*size + e.state.charSpace
			if glyph.space {
				tx += e.state.wordSpace
			}
			e.advance(tx * e.state.scale)
		}
	}

	device := e.tm.multiply(e.state.ctm)
	e.hasLast = true
	e.lastEnd = [2]float64{device[4], device[5]}
	e.lastSize = e.deviceFontSize(device)
	e.lastKnownWidths = knownWidths
	e.moved = false
	return nil
}

// separator compares where a run starts with where the previous run ended:
// a baseline change is a line break, and a forward gap or an explicit move
// on the same line is a word break.
func (e *textExtractor) separator() string {
	if !e.hasLast {
		return ""
	}
	device := e.tm.multiply(e.state.ctm)
	size := max(e.deviceFontSize(device), e.lastSize)
	dirX, dirY := device[0], device[1]
	if length := math.Hypot(dirX, dirY); length > 0 && !math.IsInf(length, 0) {
		dirX, dirY = dirX/length, dirY/length
	} else {
		dirX, dirY = 1, 0
	}
	dx, dy := device[4]-e.lastEnd[0], device[5]-e.lastEnd[1]
	along := dx*dirX + dy*dirY
	across := dy*dirX - dx*dirY
	if math.IsNaN(along) || math.IsNaN(across) {
		return ""
	}
	switch {
	case math.Abs(across) > lineBreakFraction*size:
		return "\n"
	case along > wordGapFraction*size || along < -backtrackFraction*size:
		return " "
	case e.moved && !(e.lastKnownWidths && e.state.hasFont && e.state.font.widths.known):
		// Without real glyph widths the previous run's end is a guess, so an
		// explicit move on the same line is read as a word break.
		return " "
	}
	return ""
}

func (e *textExtractor) deviceFontSize(device pdfMatrix) float64 {
	size := math.Abs(e.state.fontSize) * math.Hypot(device[2], device[3])
	if size <= 0 || math.IsNaN(size) || math.IsInf(size, 0) {
		return defaultFontSize
	}
	return size
}

func (e *textExtractor) writeSeparator(separator string) error {
	if e.suppressedTextDepth > 0 && (e.actualTextFrame == nil || e.actualTextFrame.emitted) {
		return nil
	}
	if e.out.Len() == 0 {
		return nil
	}
	text := e.out.String()
	last, _ := utf8.DecodeLastRuneInString(text)
	if last == ' ' || last == '\n' || last == '\t' || last == '\r' {
		return nil
	}
	return appendExtractedText(&e.out, separator)
}

// appendGlyphText writes font-decoded text without control characters, with
// no-break spaces as spaces and Latin ligatures spelled out.
func (e *textExtractor) appendGlyphText(text string) error {
	for _, r := range text {
		switch {
		case r < ' ' || (r >= 0x7f && r <= 0x9f) || r == utf8.RuneError || r == 0xfffe || r == 0xffff:
			continue
		case r >= 0xfb00 && r <= 0xfb06:
			if err := appendExtractedText(&e.out, latinLigatures[r-0xfb00]); err != nil {
				return err
			}
			continue
		case r == 0xa0:
			r = ' '
		}
		if utf8.RuneLen(r) > maxExtractedTextBytes-e.out.Len() {
			return fmt.Errorf("%w: extracted text exceeds %d bytes", ErrTextLimitExceeded, maxExtractedTextBytes)
		}
		e.out.WriteRune(r)
	}
	return nil
}

// latinLigatures spells out U+FB00 through U+FB06.
var latinLigatures = [...]string{"ff", "fi", "fl", "ffi", "ffl", "st", "st"}

// doXObject runs a Form XObject with its own resources, falling back to the
// current ones. Images and other XObjects carry no text.
func (e *textExtractor) doXObject(name string) error {
	if e.objects == nil {
		return nil
	}
	reference := e.objects.resolve(e.resources.get("XObject")).get(name)
	if reference.kind != pdfObjectRef || e.forms[reference.ref] || e.formDepth >= maxFormXObjectDepth {
		return nil
	}
	dict := e.objects.object(reference.ref)
	if e.objects.resolve(dict.get("Subtype")).name != "Form" {
		return nil
	}
	_, content, ok, err := e.objects.stream(reference)
	if err != nil || !ok {
		return err
	}

	// The form runs on a copy of the graphics state and cannot pop the
	// states its caller saved.
	savedState, savedResources := e.state, e.resources
	savedInText, savedTM, savedTLM := e.inText, e.tm, e.tlm
	savedFloor, savedOverflow := e.stackFloor, e.stackOverflow
	e.stackFloor, e.stackOverflow = len(e.stack), 0
	if resources := e.objects.resolve(dict.get("Resources")); resources.kind == pdfObjectDict {
		e.resources = resources
	}
	if matrix, ok := matrixFromObject(e.objects.resolve(dict.get("Matrix")), e.objects); ok {
		e.state.ctm = matrix.multiply(e.state.ctm)
	}
	savedCheck := e.scanner.nextContextCheck
	e.scanner.nextContextCheck = 0
	e.forms[reference.ref] = true
	e.formDepth++
	err = e.run(content)
	e.formDepth--
	delete(e.forms, reference.ref)
	e.scanner.nextContextCheck = savedCheck

	e.stack = e.stack[:e.stackFloor]
	e.stackFloor, e.stackOverflow = savedFloor, savedOverflow
	e.state, e.resources = savedState, savedResources
	e.inText, e.tm, e.tlm = savedInText, savedTM, savedTLM
	return err
}

func matrixOperand(operands []pdfOperand) (pdfMatrix, bool) {
	if len(operands) < 6 {
		return pdfMatrix{}, false
	}
	var m pdfMatrix
	for i, operand := range operands[len(operands)-6:] {
		if operand.kind != pdfOperandNumber {
			return pdfMatrix{}, false
		}
		m[i] = operand.number
	}
	return m, true
}

func matrixFromObject(value pdfObject, objects *pdfResourceObjects) (pdfMatrix, bool) {
	if value.kind != pdfObjectArray || len(value.array) != 6 {
		return pdfMatrix{}, false
	}
	var m pdfMatrix
	for i, item := range value.array {
		item = objects.resolve(item)
		if item.kind != pdfObjectNumber {
			return pdfMatrix{}, false
		}
		m[i] = item.number
	}
	return m, true
}

// numberOperand returns the operand fromEnd places from the end of the
// pending operands when it is a number.
func numberOperand(operands []pdfOperand, fromEnd int, fallback float64) float64 {
	if fromEnd > len(operands) || operands[len(operands)-fromEnd].kind != pdfOperandNumber {
		return fallback
	}
	return operands[len(operands)-fromEnd].number
}

func parsePDFNumber(word string) (float64, bool) {
	if word == "" || !strings.ContainsRune("+-.0123456789", rune(word[0])) {
		return 0, false
	}
	value, err := strconv.ParseFloat(word, 64)
	if err != nil || math.IsNaN(value) || math.IsInf(value, 0) {
		return 0, false
	}
	return value, true
}

// readPDFArrayOperandContext reads a content-stream array, keeping the raw
// bytes of its strings and the values of its numbers for TJ.
func readPDFArrayOperandContext(scanner *pdfTextScanner, data []byte, pos, maxBytes int) ([]pdfArrayItem, int, error) {
	var items []pdfArrayItem
	pos++
	depth := 1
	elements := 0
	totalBytes := 0

	for pos < len(data) && depth > 0 {
		if err := scanner.check(pos); err != nil {
			return nil, pos, err
		}
		var err error
		pos, err = skipPDFWhitespaceAndCommentsContext(scanner, data, pos)
		if err != nil {
			return nil, pos, err
		}
		if pos >= len(data) {
			break
		}

		var raw []byte
		isString := false
		switch data[pos] {
		case '[':
			depth++
			if depth > maxTextNestingDepth {
				return nil, pos, fmt.Errorf("%w: array nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
			}
			elements++
			pos++
		case ']':
			depth--
			pos++
		case '(':
			raw, pos, err = readPDFLiteralStringContext(scanner, data, pos, maxBytes)
			isString = true
		case '<':
			if pos+1 < len(data) && data[pos+1] == '<' {
				pos += 2
				continue
			}
			raw, pos, err = readPDFHexStringContext(scanner, data, pos, maxBytes)
			isString = true
		default:
			word, next := readPDFWord(data, pos)
			elements++
			if number, ok := parsePDFNumber(word); ok && depth == 1 {
				items = append(items, pdfArrayItem{adjust: number})
			}
			pos = max(next, pos+1)
		}
		if err != nil {
			return nil, pos, err
		}
		if isString {
			elements++
			totalBytes += len(raw)
			if totalBytes > maxBytes {
				return nil, pos, fmt.Errorf("%w: array text exceeds %d bytes", ErrTextLimitExceeded, maxBytes)
			}
			items = append(items, pdfArrayItem{raw: raw, isString: true})
		}
		if elements > maxTextArrayElements {
			return nil, pos, fmt.Errorf("%w: array element count exceeds %d", ErrTextLimitExceeded, maxTextArrayElements)
		}
	}

	return items, pos, nil
}
