// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

// Package inspect provides lightweight PDF inspection helpers.
package inspect

import (
	"bytes"
	"compress/zlib"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"unicode"
	"unicode/utf16"
	"unicode/utf8"

	"github.com/cssbruno/pdfrune/importpdf"
	"golang.org/x/text/encoding/charmap"
)

const (
	maxDecodedStreamBytes = 64 * 1024 * 1024
	maxDecodedStreamCount = 4096
	maxDecodedTotalBytes  = 128 * 1024 * 1024
	textTokenCapacity     = 8
	maxTextOperands       = 256
	maxTextArrayElements  = 64 * 1024
	maxTextNestingDepth   = 256
	maxExtractedTextBytes = 16 * 1024 * 1024
	textContextCheckBytes = 1024
	pdfOctalBase          = 8
	utf16BOMBytes         = 2
)

// ErrTextLimitExceeded reports that PDF text extraction exceeded a bounded
// operand, nesting, token, or output limit.
var ErrTextLimitExceeded = errors.New("pdf text extraction limit exceeded")

// ValidateStructure checks that data can be parsed as an unencrypted classic
// PDF with at least one importable page.
func ValidateStructure(data []byte) error {
	return ValidateStructureContext(context.Background(), data)
}

// ValidateStructureContext checks that data can be parsed as an unencrypted
// classic PDF with at least one importable page and honors ctx during parsing.
func ValidateStructureContext(ctx context.Context, data []byte) error {
	count, err := PageCountContext(ctx, data)
	if err != nil {
		return err
	}
	if count == 0 {
		return errors.New("pdf has no pages")
	}
	return nil
}

// PageCount returns the number of pages PDFRune can parse from data.
func PageCount(data []byte) (int, error) {
	return PageCountContext(context.Background(), data)
}

// PageCountContext returns the number of pages PDFRune can parse from data
// and honors ctx while importing the page tree.
func PageCountContext(ctx context.Context, data []byte) (int, error) {
	source, err := importpdf.OpenBytesWithOptionsContext(ctx, data, importpdf.ImportOptions{})
	if err != nil {
		return 0, fmt.Errorf("parse pdf: %w", err)
	}
	return source.PageCount(), nil
}

// FirstPageSizePoints returns the first MediaBox dimensions in PDF points.
func FirstPageSizePoints(data []byte) (float64, float64, error) {
	source, err := importpdf.OpenBytes(data)
	if err != nil {
		return 0, 0, fmt.Errorf("parse pdf: %w", err)
	}
	size, ok := source.PageSizes()[1]["MediaBox"]
	if !ok {
		return 0, 0, errors.New("pdf MediaBox not found")
	}
	return size.Wd, size.Ht, nil
}

// Text extracts literal text operators from PDF content streams.
func Text(data []byte) (string, error) {
	return TextContext(context.Background(), data)
}

// TextContext extracts literal text operators from page content streams and
// honors ctx during page parsing and text tokenization. Non-page streams such
// as metadata, fonts, images, and attachments are not treated as document text.
func TextContext(ctx context.Context, data []byte) (string, error) {
	if err := inspectContextErr(ctx); err != nil {
		return "", err
	}
	source, err := importpdf.OpenBytesWithOptionsContext(ctx, data, importpdf.ImportOptions{})
	if err != nil {
		return "", fmt.Errorf("parse pdf text: %w", err)
	}

	var text strings.Builder
	totalBytes := 0
	for pageNumber := 1; pageNumber <= source.PageCount(); pageNumber++ {
		if err := inspectContextErr(ctx); err != nil {
			return "", err
		}
		if pageNumber > maxDecodedStreamCount {
			return "", errors.New("pdf page content stream count exceeds maximum size")
		}
		page, err := source.PageContext(ctx, pageNumber, "MediaBox")
		if err != nil {
			return "", fmt.Errorf("parse pdf page %d: %w", pageNumber, err)
		}
		content, err := page.ContentBorrowedWithContext(ctx)
		if err != nil {
			return "", fmt.Errorf("parse pdf page %d: %w", pageNumber, err)
		}
		if len(content) > maxDecodedTotalBytes-totalBytes {
			return "", errors.New("decoded pdf page contents exceed maximum size")
		}
		totalBytes += len(content)
		streamText, err := textFromContentStreamContext(ctx, content)
		if err != nil {
			return "", err
		}
		if len(streamText) > maxExtractedTextBytes-text.Len() {
			return "", fmt.Errorf("%w: document text exceeds %d bytes", ErrTextLimitExceeded, maxExtractedTextBytes)
		}
		text.WriteString(streamText)
	}
	return text.String(), nil
}

// PageText extracts text from one importable PDF page.
func PageText(data []byte, pageNum int) (string, error) {
	return PageTextContext(context.Background(), data, pageNum)
}

// PageTextContext extracts text from one importable PDF page while honoring
// ctx.
func PageTextContext(ctx context.Context, data []byte, pageNum int) (string, error) {
	if err := inspectContextErr(ctx); err != nil {
		return "", err
	}
	if pageNum < 1 {
		return "", errors.New("pdf page number must be positive")
	}

	source, err := importpdf.OpenBytesWithOptionsContext(ctx, data, importpdf.ImportOptions{})
	if err != nil {
		return "", fmt.Errorf("parse pdf page: %w", err)
	}
	page, err := source.PageContext(ctx, pageNum, "MediaBox")
	if err != nil {
		return "", fmt.Errorf("parse pdf page: %w", err)
	}
	if page == nil {
		return "", fmt.Errorf("pdf page %d not found", pageNum)
	}
	content, err := page.ContentWithContext(ctx)
	if err != nil {
		return "", fmt.Errorf("parse pdf page: %w", err)
	}
	return textFromContentStreamContext(ctx, content)
}

// DecodedStreams returns raw or Flate-decoded PDF streams in file order.
func DecodedStreams(data []byte) ([][]byte, error) {
	return DecodedStreamsContext(context.Background(), data)
}

// DecodedStreamsContext returns raw or Flate-decoded PDF streams in file order
// and honors ctx while scanning and decoding streams.
func DecodedStreamsContext(ctx context.Context, data []byte) ([][]byte, error) {
	return decodedStreamsContext(ctx, data, maxDecodedStreamBytes, maxDecodedTotalBytes, maxDecodedStreamCount)
}

func decodedStreamsContext(ctx context.Context, data []byte, maxStreamBytes, maxTotalBytes, maxStreams int) ([][]byte, error) {
	if err := inspectContextErr(ctx); err != nil {
		return nil, err
	}
	if maxStreamBytes < 0 || maxTotalBytes < 0 || maxStreams < 0 {
		return nil, errors.New("pdf stream limits are invalid")
	}
	source, err := importpdf.OpenBytesWithOptionsContext(ctx, data, importpdf.ImportOptions{})
	if err != nil {
		return nil, fmt.Errorf("parse pdf streams: %w", err)
	}
	return scanDecodedStreamsContext(ctx, source, maxStreamBytes, maxTotalBytes, maxStreams)
}

func inspectContextErr(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	return ctx.Err()
}

func decodeStreamWithLimitContext(ctx context.Context, dict []byte, stream []byte, maxBytes int) ([]byte, error) {
	if err := inspectContextErr(ctx); err != nil {
		return nil, err
	}
	if hasFlateFilter(dict) {
		return inflateStreamWithLimitContext(ctx, stream, maxBytes)
	}
	if len(stream) > maxBytes {
		return nil, errors.New("pdf stream exceeds maximum size")
	}
	return append([]byte(nil), stream...), nil
}

func hasFlateFilter(dict []byte) bool {
	if hasNonNullDecodeParms(dict) {
		return false
	}
	pos := 0
	depth := 0
	found := false
	flate := false
	for {
		token, ok := nextStreamToken(dict, pos)
		if !ok {
			return found && flate
		}
		pos = token.end
		switch token.kind {
		case streamTokenDictStart:
			depth++
		case streamTokenDictEnd:
			depth--
		case streamTokenName:
			if depth != 1 || decodeStreamName(token.text) != "Filter" {
				continue
			}
			if found {
				return false
			}
			found = true
			value, ok := nextStreamToken(dict, pos)
			if !ok {
				return false
			}
			if value.kind == streamTokenName {
				flate = isFlateFilterName(value.text)
				pos = value.end
				continue
			}
			if value.kind != streamTokenArrayStart {
				pos = value.end
				continue
			}
			count := 0
			valid := true
			for {
				value, ok = nextStreamToken(dict, value.end)
				if !ok {
					return false
				}
				if value.kind == streamTokenArrayEnd {
					flate = valid && count == 1 && flate
					pos = value.end
					break
				}
				if value.kind != streamTokenName {
					valid = false
					continue
				}
				count++
				flate = isFlateFilterName(value.text)
			}
		}
	}
}

func hasNonNullDecodeParms(dict []byte) bool {
	pos := 0
	depth := 0
	for {
		token, ok := nextStreamToken(dict, pos)
		if !ok {
			return false
		}
		pos = token.end
		switch token.kind {
		case streamTokenDictStart:
			depth++
		case streamTokenDictEnd:
			depth--
		case streamTokenName:
			if depth != 1 || decodeStreamName(token.text) != "DecodeParms" {
				continue
			}
			value, ok := nextStreamToken(dict, pos)
			return !ok || value.kind != streamTokenWord || value.text != "null"
		}
	}
}

func isFlateFilterName(name string) bool {
	name = decodeStreamName(name)
	return name == "FlateDecode" || name == "Fl"
}

func inflateStreamWithLimitContext(ctx context.Context, stream []byte, maxBytes int) ([]byte, error) {
	if err := inspectContextErr(ctx); err != nil {
		return nil, err
	}
	reader, err := zlib.NewReader(bytes.NewReader(stream))
	if err != nil {
		return nil, fmt.Errorf("decode flate stream: %w", err)
	}
	defer func() {
		_ = reader.Close()
	}()

	decoded, err := io.ReadAll(io.LimitReader(inspectContextReader{ctx: ctx, r: reader}, int64(maxBytes)+1))
	if err != nil {
		return nil, fmt.Errorf("read flate stream: %w", err)
	}
	if len(decoded) > maxBytes {
		return nil, errors.New("decoded pdf stream exceeds maximum size")
	}
	return decoded, nil
}

type inspectContextReader struct {
	ctx context.Context
	r   io.Reader
}

func (r inspectContextReader) Read(p []byte) (int, error) {
	if err := inspectContextErr(r.ctx); err != nil {
		return 0, err
	}
	n, err := r.r.Read(p)
	if err != nil {
		return n, err
	}
	if n == 0 {
		return n, inspectContextErr(r.ctx)
	}
	return n, nil
}

type pdfTextToken struct {
	text   string
	isText bool
}

type pdfMarkedContentFrame struct {
	actualText bool
}

type pdfTextScanner struct {
	ctx              context.Context
	nextContextCheck int
}

func newPDFTextScanner(ctx context.Context) *pdfTextScanner {
	return &pdfTextScanner{ctx: ctx}
}

func (s *pdfTextScanner) check(pos int) error {
	if pos < s.nextContextCheck {
		return nil
	}
	if err := inspectContextErr(s.ctx); err != nil {
		return err
	}
	s.nextContextCheck = pos + textContextCheckBytes
	return nil
}

func textFromContentStreamContext(ctx context.Context, stream []byte) (string, error) {
	var out strings.Builder
	scanner := newPDFTextScanner(ctx)
	tokens := make([]pdfTextToken, 0, textTokenCapacity)
	markedContent := make([]pdfMarkedContentFrame, 0, textTokenCapacity)
	inText := false
	suppressedTextDepth := 0
	operandCount := 0
	pendingActualText := false
	actualText := ""
	actualTextPresent := false

	resetOperands := func() {
		tokens = tokens[:0]
		operandCount = 0
		pendingActualText = false
		actualText = ""
		actualTextPresent = false
	}
	addOperand := func(token pdfTextToken) error {
		operandCount++
		if operandCount > maxTextOperands {
			return fmt.Errorf("%w: pending operand count exceeds %d", ErrTextLimitExceeded, maxTextOperands)
		}
		if !token.isText {
			return nil
		}
		if len(tokens) < textTokenCapacity {
			tokens = append(tokens, token)
			return nil
		}
		copy(tokens, tokens[1:])
		tokens[len(tokens)-1] = token
		return nil
	}

	for i := 0; i < len(stream); {
		if err := scanner.check(i); err != nil {
			return "", err
		}
		var err error
		i, err = skipPDFWhitespaceAndCommentsContext(scanner, stream, i)
		if err != nil {
			return "", err
		}
		if i >= len(stream) {
			break
		}

		switch stream[i] {
		case '(':
			raw, next, err := readPDFLiteralStringContext(scanner, stream, i, maxExtractedTextBytes)
			if err != nil {
				return "", err
			}
			text := decodePDFTextBytes(raw)
			if len(text) > maxExtractedTextBytes {
				return "", fmt.Errorf("%w: text token exceeds %d bytes", ErrTextLimitExceeded, maxExtractedTextBytes)
			}
			if pendingActualText {
				actualText, actualTextPresent = text, true
			}
			pendingActualText = false
			if err := addOperand(pdfTextToken{text: text, isText: true}); err != nil {
				return "", err
			}
			i = next
		case '<':
			if i+1 < len(stream) && stream[i+1] == '<' {
				i += 2
				continue
			}
			raw, next, err := readPDFHexStringContext(scanner, stream, i, maxExtractedTextBytes)
			if err != nil {
				return "", err
			}
			text := decodePDFTextBytes(raw)
			if len(text) > maxExtractedTextBytes {
				return "", fmt.Errorf("%w: text token exceeds %d bytes", ErrTextLimitExceeded, maxExtractedTextBytes)
			}
			if pendingActualText {
				actualText, actualTextPresent = text, true
			}
			pendingActualText = false
			if err := addOperand(pdfTextToken{text: text, isText: true}); err != nil {
				return "", err
			}
			i = next
		case '[':
			text, next, err := readPDFArrayTextContext(scanner, stream, i, maxExtractedTextBytes)
			if err != nil {
				return "", err
			}
			pendingActualText = false
			if err := addOperand(pdfTextToken{text: text, isText: true}); err != nil {
				return "", err
			}
			i = next
		case '/':
			name, next := readPDFName(stream, i)
			if pendingActualText {
				pendingActualText = false
			}
			if name == "ActualText" {
				pendingActualText = true
			}
			if err := addOperand(pdfTextToken{}); err != nil {
				return "", err
			}
			i = next
		default:
			word, next := readPDFWord(stream, i)
			if word == "" {
				i++
				continue
			}

			if isPDFOperandWord(word) {
				pendingActualText = false
				if err := addOperand(pdfTextToken{}); err != nil {
					return "", err
				}
				i = next
				continue
			}

			switch word {
			case "BDC":
				frame := pdfMarkedContentFrame{actualText: actualTextPresent}
				if frame.actualText {
					if suppressedTextDepth == 0 {
						if err := appendExtractedText(&out, actualText); err != nil {
							return "", err
						}
					}
					suppressedTextDepth++
				}
				if len(markedContent) >= maxTextNestingDepth {
					return "", fmt.Errorf("%w: marked-content nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
				}
				markedContent = append(markedContent, frame)
			case "BMC":
				if len(markedContent) >= maxTextNestingDepth {
					return "", fmt.Errorf("%w: marked-content nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
				}
				markedContent = append(markedContent, pdfMarkedContentFrame{})
			case "EMC":
				if len(markedContent) > 0 {
					frame := markedContent[len(markedContent)-1]
					markedContent = markedContent[:len(markedContent)-1]
					if frame.actualText {
						suppressedTextDepth--
					}
				}
			case "BT":
				inText = true
			case "ET":
				inText = false
			case "Tj", "'", "\"", "TJ":
				if inText && suppressedTextDepth == 0 {
					if err := appendExtractedText(&out, lastTextToken(tokens)); err != nil {
						return "", err
					}
				}
			case "BI":
				inlineEnd, err := skipPDFInlineImage(scanner, stream, next)
				if err != nil {
					return "", err
				}
				next = inlineEnd
			}
			resetOperands()
			i = next
		}
	}

	if err := inspectContextErr(ctx); err != nil {
		return "", err
	}
	return out.String(), nil
}

func appendExtractedText(out *strings.Builder, text string) error {
	if len(text) > maxExtractedTextBytes-out.Len() {
		return fmt.Errorf("%w: extracted text exceeds %d bytes", ErrTextLimitExceeded, maxExtractedTextBytes)
	}
	out.WriteString(text)
	return nil
}

func isPDFOperandWord(word string) bool {
	if word == "true" || word == "false" || word == "null" {
		return true
	}
	if word == "" || !strings.ContainsRune("+-.0123456789", rune(word[0])) {
		return false
	}
	_, err := strconv.ParseFloat(word, 64)
	return err == nil
}

func skipPDFInlineImage(scanner *pdfTextScanner, data []byte, pos int) (int, error) {
	dictionaryTokens := 0
	declaredLength := -1
	wantsLength := false

	for pos < len(data) {
		if err := scanner.check(pos); err != nil {
			return pos, err
		}
		var err error
		pos, err = skipPDFWhitespaceAndCommentsContext(scanner, data, pos)
		if err != nil {
			return pos, err
		}
		if pos >= len(data) {
			break
		}

		switch data[pos] {
		case '(':
			_, next, err := readPDFLiteralStringContext(scanner, data, pos, maxExtractedTextBytes)
			if err != nil {
				return pos, err
			}
			pos = next
			wantsLength = false
		case '<':
			if pos+1 < len(data) && data[pos+1] == '<' {
				pos += 2
				continue
			}
			_, next, err := readPDFHexStringContext(scanner, data, pos, maxExtractedTextBytes)
			if err != nil {
				return pos, err
			}
			pos = next
			wantsLength = false
		case '[':
			_, next, err := readPDFArrayTextContext(scanner, data, pos, maxExtractedTextBytes)
			if err != nil {
				return pos, err
			}
			pos = next
			wantsLength = false
		case '/':
			name, next := readPDFName(data, pos)
			wantsLength = name == "Length"
			pos = next
		default:
			word, next := readPDFWord(data, pos)
			if word == "" {
				pos++
				continue
			}
			if word == "ID" {
				dataStart, err := inlineImageDataStart(data, next)
				if err != nil {
					return pos, err
				}
				return inlineImageEnd(scanner, data, dataStart, declaredLength)
			}
			if wantsLength {
				if length, err := strconv.Atoi(word); err == nil && length >= 0 {
					declaredLength = length
				}
			}
			wantsLength = false
			pos = next
		}

		dictionaryTokens++
		if dictionaryTokens > maxTextOperands {
			return pos, fmt.Errorf("%w: inline-image dictionary exceeds %d tokens", ErrTextLimitExceeded, maxTextOperands)
		}
	}
	return pos, errors.New("pdf inline image is missing ID")
}

func inlineImageDataStart(data []byte, pos int) (int, error) {
	if pos >= len(data) || !isPDFWhitespace(data[pos]) {
		return pos, errors.New("pdf inline image ID must be followed by whitespace")
	}
	if data[pos] == '\r' && pos+1 < len(data) && data[pos+1] == '\n' {
		return pos + 2, nil
	}
	return pos + 1, nil
}

func inlineImageEnd(scanner *pdfTextScanner, data []byte, start, declaredLength int) (int, error) {
	if declaredLength >= 0 && declaredLength <= len(data)-start {
		pos, err := skipPDFWhitespaceAndCommentsContext(scanner, data, start+declaredLength)
		if err != nil {
			return pos, err
		}
		word, next := readPDFWord(data, pos)
		if word == "EI" {
			return next, nil
		}
	}

	for pos := start; pos+1 < len(data); pos++ {
		if err := scanner.check(pos); err != nil {
			return pos, err
		}
		if data[pos] != 'E' || data[pos+1] != 'I' || (pos > start && !isPDFWhitespace(data[pos-1])) {
			continue
		}
		after := pos + 2
		if after < len(data) && !isPDFWhitespace(data[after]) && !isPDFDelimiter(data[after]) {
			continue
		}
		plausible, err := inlineImageContinuationIsPlausible(scanner, data, after)
		if err != nil {
			return pos, err
		}
		if plausible {
			return after, nil
		}
	}
	return len(data), errors.New("pdf inline image is missing a valid EI terminator")
}

func inlineImageContinuationIsPlausible(scanner *pdfTextScanner, data []byte, pos int) (bool, error) {
	var err error
	pos, err = skipPDFWhitespaceAndCommentsContext(scanner, data, pos)
	if err != nil {
		return false, err
	}
	if pos >= len(data) {
		return true, nil
	}
	word, _ := readPDFWord(data, pos)
	if word == "" {
		return false, nil
	}
	switch word {
	case "b", "B", "b*", "B*", "BDC", "BMC", "BT", "BX", "c", "cm", "CS", "cs", "d", "d0", "d1", "Do", "DP", "EMC", "ET", "EX", "f", "F", "f*", "G", "g", "gs", "h", "i", "j", "J", "K", "k", "l", "m", "M", "MP", "n", "q", "Q", "re", "RG", "rg", "ri", "s", "S", "SC", "sc", "SCN", "scn", "sh", "T*", "Tc", "Td", "TD", "Tf", "Tj", "TJ", "TL", "Tm", "Tr", "Ts", "Tw", "Tz", "v", "w", "W", "W*", "y", "'", "\"":
		return true, nil
	default:
		return false, nil
	}
}

func lastTextToken(tokens []pdfTextToken) string {
	if len(tokens) == 0 {
		return ""
	}
	for i := len(tokens); i > 0; i-- {
		if tokens[i-1].isText {
			return tokens[i-1].text
		}
	}
	return ""
}

func skipPDFWhitespaceAndComments(data []byte, pos int) int {
	for pos < len(data) {
		switch data[pos] {
		case 0, '\t', '\n', '\f', '\r', ' ':
			pos++
		case '%':
			for pos < len(data) && data[pos] != '\n' && data[pos] != '\r' {
				pos++
			}
		default:
			return pos
		}
	}
	return pos
}

func skipPDFWhitespaceAndCommentsContext(scanner *pdfTextScanner, data []byte, pos int) (int, error) {
	for pos < len(data) {
		if err := scanner.check(pos); err != nil {
			return pos, err
		}
		switch data[pos] {
		case 0, '\t', '\n', '\f', '\r', ' ':
			pos++
		case '%':
			for pos < len(data) && data[pos] != '\n' && data[pos] != '\r' {
				if err := scanner.check(pos); err != nil {
					return pos, err
				}
				pos++
			}
		default:
			return pos, nil
		}
	}
	return pos, nil
}

func readPDFWord(data []byte, pos int) (string, int) {
	start := pos
	for pos < len(data) && !isPDFDelimiter(data[pos]) && !isPDFWhitespace(data[pos]) {
		pos++
	}
	return string(data[start:pos]), pos
}

func readPDFName(data []byte, pos int) (string, int) {
	pos++
	start := pos
	for pos < len(data) && !isPDFDelimiter(data[pos]) && !isPDFWhitespace(data[pos]) {
		pos++
	}
	return decodeStreamName(string(data[start:pos])), pos
}

func isPDFDelimiter(c byte) bool {
	switch c {
	case '(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return true
	default:
		return false
	}
}

func isPDFWhitespace(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\f', '\r', ' ':
		return true
	default:
		return false
	}
}

func readPDFArrayTextContext(scanner *pdfTextScanner, data []byte, pos, maxBytes int) (string, int, error) {
	var out strings.Builder
	pos++
	depth := 1
	elements := 0

	for pos < len(data) && depth > 0 {
		if err := scanner.check(pos); err != nil {
			return "", pos, err
		}
		var err error
		pos, err = skipPDFWhitespaceAndCommentsContext(scanner, data, pos)
		if err != nil {
			return "", pos, err
		}
		if pos >= len(data) {
			break
		}

		switch data[pos] {
		case '[':
			depth++
			if depth > maxTextNestingDepth {
				return "", pos, fmt.Errorf("%w: array nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
			}
			elements++
			pos++
		case ']':
			depth--
			pos++
		case '(':
			raw, next, err := readPDFLiteralStringContext(scanner, data, pos, maxBytes)
			if err != nil {
				return "", pos, err
			}
			if err := appendArrayText(&out, decodePDFTextBytes(raw), maxBytes); err != nil {
				return "", pos, err
			}
			elements++
			pos = next
		case '<':
			if pos+1 < len(data) && data[pos+1] == '<' {
				pos += 2
				continue
			}
			raw, next, err := readPDFHexStringContext(scanner, data, pos, maxBytes)
			if err != nil {
				return "", pos, err
			}
			if err := appendArrayText(&out, decodePDFTextBytes(raw), maxBytes); err != nil {
				return "", pos, err
			}
			elements++
			pos = next
		default:
			_, next := readPDFWord(data, pos)
			elements++
			if next <= pos {
				pos++
			} else {
				pos = next
			}
		}
		if elements > maxTextArrayElements {
			return "", pos, fmt.Errorf("%w: array element count exceeds %d", ErrTextLimitExceeded, maxTextArrayElements)
		}
	}

	return out.String(), pos, nil
}

func readPDFLiteralString(data []byte, pos int) ([]byte, int) {
	raw, next, _ := readPDFLiteralStringContext(newPDFTextScanner(context.Background()), data, pos, len(data))
	return raw, next
}

func appendArrayText(out *strings.Builder, text string, maxBytes int) error {
	if len(text) > maxBytes-out.Len() {
		return fmt.Errorf("%w: array text exceeds %d bytes", ErrTextLimitExceeded, maxBytes)
	}
	out.WriteString(text)
	return nil
}

func readPDFLiteralStringContext(scanner *pdfTextScanner, data []byte, pos, maxBytes int) ([]byte, int, error) {
	var out []byte
	pos++
	depth := 1

	for pos < len(data) && depth > 0 {
		if err := scanner.check(pos); err != nil {
			return nil, pos, err
		}
		c := data[pos]
		pos++

		switch c {
		case '\\':
			if pos >= len(data) {
				break
			}
			escaped := data[pos]
			pos++

			switch escaped {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '(', ')', '\\':
				out = append(out, escaped)
			case '\r':
				if pos < len(data) && data[pos] == '\n' {
					pos++
				}
			case '\n':
			default:
				if escaped >= '0' && escaped <= '7' {
					value := int(escaped - '0')
					for count := 1; count < 3 && pos < len(data) && data[pos] >= '0' && data[pos] <= '7'; count++ {
						value = value*pdfOctalBase + int(data[pos]-'0')
						pos++
					}
					out = append(out, byte(value))
				} else {
					out = append(out, escaped)
				}
			}
		case '(':
			depth++
			if depth > maxTextNestingDepth {
				return nil, pos, fmt.Errorf("%w: literal-string nesting exceeds %d", ErrTextLimitExceeded, maxTextNestingDepth)
			}
			out = append(out, c)
		case ')':
			depth--
			if depth > 0 {
				out = append(out, c)
			}
		default:
			out = append(out, c)
		}
		if len(out) > maxBytes {
			return nil, pos, fmt.Errorf("%w: literal string exceeds %d bytes", ErrTextLimitExceeded, maxBytes)
		}
	}

	return out, pos, nil
}

func readPDFHexString(data []byte, pos int) ([]byte, int) {
	raw, next, _ := readPDFHexStringContext(newPDFTextScanner(context.Background()), data, pos, len(data))
	return raw, next
}

func readPDFHexStringContext(scanner *pdfTextScanner, data []byte, pos, maxBytes int) ([]byte, int, error) {
	pos++
	hexText := make([]byte, 0, min(len(data)-pos, maxBytes*2))
	for pos < len(data) && data[pos] != '>' {
		if err := scanner.check(pos); err != nil {
			return nil, pos, err
		}
		c := data[pos]
		pos++
		if !isPDFWhitespace(c) {
			hexText = append(hexText, c)
			if len(hexText) > maxBytes*2 {
				return nil, pos, fmt.Errorf("%w: hexadecimal string exceeds %d bytes", ErrTextLimitExceeded, maxBytes)
			}
		}
	}
	if len(hexText)%2 != 0 {
		hexText = append(hexText, '0')
	}

	out := make([]byte, hex.DecodedLen(len(hexText)))
	if _, err := hex.Decode(out, hexText); err != nil {
		out = nil
	}
	if pos < len(data) && data[pos] == '>' {
		pos++
	}
	return out, pos, nil
}

func decodePDFTextBytes(raw []byte) string {
	if len(raw) >= utf16BOMBytes && raw[0] == 0xfe && raw[1] == 0xff {
		if text, ok := decodeUTF16BE(raw[utf16BOMBytes:]); ok {
			return text
		}
	}
	if looksLikeBOMLessUTF16BE(raw) {
		if text, ok := decodeUTF16BE(raw); ok {
			return text
		}
	}

	text, err := charmap.Windows1252.NewDecoder().String(string(raw))
	if err != nil {
		return string(raw)
	}
	return text
}

func looksLikeBOMLessUTF16BE(raw []byte) bool {
	if len(raw) < 6 || len(raw)%2 != 0 {
		return false
	}
	pairs := len(raw) / 2
	zeroHighBytes := 0
	hasNonASCII := false
	for i := 0; i < len(raw); i += 2 {
		if raw[i] == 0 {
			zeroHighBytes++
		}
		if raw[i] != 0 || raw[i+1] >= utf8.RuneSelf {
			hasNonASCII = true
		}
	}
	if !hasNonASCII || zeroHighBytes < 2 || zeroHighBytes*3 < pairs*2 {
		return false
	}
	text, ok := decodeUTF16BE(raw)
	if !ok {
		return false
	}
	for _, r := range text {
		if unicode.IsControl(r) && r != '\t' && r != '\n' && r != '\r' {
			return false
		}
	}
	return true
}

func decodeUTF16BE(raw []byte) (string, bool) {
	if len(raw)%2 != 0 {
		return "", false
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i < len(raw); i += 2 {
		unit := uint16(raw[i])<<8 | uint16(raw[i+1])
		if 0xd800 <= unit && unit <= 0xdbff {
			if i+3 >= len(raw) {
				return "", false
			}
			next := uint16(raw[i+2])<<8 | uint16(raw[i+3])
			if next < 0xdc00 || next > 0xdfff {
				return "", false
			}
		} else if 0xdc00 <= unit && unit <= 0xdfff {
			if i < 2 {
				return "", false
			}
			previous := uint16(raw[i-2])<<8 | uint16(raw[i-1])
			if previous < 0xd800 || previous > 0xdbff {
				return "", false
			}
		}
		units = append(units, unit)
	}
	return string(utf16.Decode(units)), true
}
