// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package inspect

import (
	"context"
	"sort"
	"unicode/utf16"
)

type cmapSection uint8

const (
	cmapNone cmapSection = iota
	cmapCodeSpace
	cmapBFChar
	cmapBFRange
)

type cmapOperand struct {
	raw     []byte
	array   [][]byte
	isArray bool
	name    string
}

// parseToUnicodeCMap reads the codespace ranges and the bfchar and bfrange
// mappings of a CMap stream. Entries past maxCMapEntries are ignored; other
// CMap operators, including usecmap and cidrange, carry no text.
func parseToUnicodeCMap(ctx context.Context, data []byte) (*pdfToUnicode, []pdfCodeSpace, error) {
	scanner := newPDFTextScanner(ctx)
	cmap := &pdfToUnicode{chars: make(map[uint32]string)}
	var spaces []pdfCodeSpace
	section := cmapNone
	operands := make([]cmapOperand, 0, 3)
	entries := 0

	push := func(operand cmapOperand) {
		if len(operands) == cap(operands) {
			copy(operands, operands[1:])
			operands = operands[:len(operands)-1]
		}
		operands = append(operands, operand)
	}
	for pos := 0; pos < len(data); {
		var err error
		if pos, err = skipPDFWhitespaceAndCommentsContext(scanner, data, pos); err != nil {
			return nil, nil, err
		}
		if pos >= len(data) {
			break
		}
		switch data[pos] {
		case '<':
			if pos+1 < len(data) && data[pos+1] == '<' {
				pos += 2
				continue
			}
			raw, next, err := readPDFHexStringContext(scanner, data, pos, maxDecodedStreamBytes)
			if err != nil {
				return nil, nil, err
			}
			push(cmapOperand{raw: raw})
			pos = next
		case '(':
			raw, next, err := readPDFLiteralStringContext(scanner, data, pos, maxDecodedStreamBytes)
			if err != nil {
				return nil, nil, err
			}
			push(cmapOperand{raw: raw})
			pos = next
		case '[':
			var array [][]byte
			pos++
			for pos < len(data) && data[pos] != ']' {
				if pos, err = skipPDFWhitespaceAndCommentsContext(scanner, data, pos); err != nil {
					return nil, nil, err
				}
				if pos >= len(data) || data[pos] == ']' {
					break
				}
				if data[pos] != '<' {
					_, next := readPDFWord(data, pos)
					pos = max(next, pos+1)
					continue
				}
				raw, next, err := readPDFHexStringContext(scanner, data, pos, maxDecodedStreamBytes)
				if err != nil {
					return nil, nil, err
				}
				if len(array) < maxCMapEntries {
					array = append(array, raw)
				}
				pos = next
			}
			push(cmapOperand{array: array, isArray: true})
			pos++
		case '/':
			name, next := readPDFName(data, pos)
			push(cmapOperand{name: name})
			pos = next
		default:
			word, next := readPDFWord(data, pos)
			if word == "" {
				pos++
				continue
			}
			pos = next
			switch word {
			case "begincodespacerange":
				section = cmapCodeSpace
			case "beginbfchar":
				section = cmapBFChar
			case "beginbfrange":
				section = cmapBFRange
			case "endcodespacerange", "endbfchar", "endbfrange":
				section = cmapNone
			}
			operands = operands[:0]
			continue
		}

		if entries >= maxCMapEntries {
			continue
		}
		switch section {
		case cmapCodeSpace:
			if len(operands) == 2 {
				if space, ok := newPDFCodeSpace(operands[0].raw, operands[1].raw); ok && len(spaces) < maxCodeSpaces {
					spaces = append(spaces, space)
				}
				entries++
				operands = operands[:0]
			}
		case cmapBFChar:
			if len(operands) == 2 {
				if code, ok := cmapCode(operands[0].raw); ok {
					if operands[1].name != "" {
						cmap.chars[code], _ = glyphNameText(operands[1].name)
					} else {
						cmap.chars[code] = utf16BEText(operands[1].raw)
					}
				}
				entries++
				operands = operands[:0]
			}
		case cmapBFRange:
			if len(operands) == 3 {
				entries += addCMapRange(cmap, operands)
				operands = operands[:0]
			}
		}
	}
	sort.SliceStable(cmap.ranges, func(i, j int) bool { return cmap.ranges[i].low < cmap.ranges[j].low })
	sort.SliceStable(spaces, func(i, j int) bool { return spaces[i].length < spaces[j].length })
	return cmap, spaces, nil
}

func addCMapRange(cmap *pdfToUnicode, operands []cmapOperand) int {
	low, okLow := cmapCode(operands[0].raw)
	high, okHigh := cmapCode(operands[1].raw)
	if !okLow || !okHigh || high < low {
		return 1
	}
	destination := operands[2]
	if destination.isArray {
		count := min(uint64(high-low)+1, uint64(len(destination.array)))
		array := make([]string, count)
		for i := range array {
			array[i] = utf16BEText(destination.array[i])
		}
		cmap.ranges = append(cmap.ranges, pdfUnicodeRange{low: low, high: high, array: array})
		return 1 + len(array)
	}
	units := utf16BEUnits(destination.raw)
	if len(units) == 0 {
		return 1
	}
	cmap.ranges = append(cmap.ranges, pdfUnicodeRange{low: low, high: high, base: units})
	return 1
}

func newPDFCodeSpace(low, high []byte) (pdfCodeSpace, bool) {
	if len(low) == 0 || len(low) > maxCodeBytes || len(low) != len(high) {
		return pdfCodeSpace{}, false
	}
	space := pdfCodeSpace{length: len(low)}
	copy(space.low[:], low)
	copy(space.high[:], high)
	return space, true
}

func cmapCode(raw []byte) (uint32, bool) {
	if len(raw) == 0 || len(raw) > maxCodeBytes {
		return 0, false
	}
	code := uint32(0)
	for _, b := range raw {
		code = code<<8 | uint32(b)
	}
	return code, true
}

// utf16BEUnits reads CMap destination bytes as UTF-16BE; a single byte is
// read as one code unit.
func utf16BEUnits(raw []byte) []uint16 {
	if len(raw) > maxCMapTextBytes {
		return nil
	}
	if len(raw) == 1 {
		return []uint16{uint16(raw[0])}
	}
	units := make([]uint16, 0, len(raw)/2)
	for i := 0; i+1 < len(raw); i += 2 {
		units = append(units, uint16(raw[i])<<8|uint16(raw[i+1]))
	}
	return units
}

func utf16BEText(raw []byte) string {
	return string(utf16.Decode(utf16BEUnits(raw)))
}
