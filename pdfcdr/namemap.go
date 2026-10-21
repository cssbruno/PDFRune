// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfcdr

import "errors"

// A resource category key such as /Shading or /ColorSpace names a map of
// producer-chosen names inside a /Resources dictionary, but the same key holds
// the object itself elsewhere: a shading pattern's /Shading is a shading
// dictionary or stream. Keys of a name map are exempt from the removal policy,
// so a value is treated as a name map only when it has the shape of one: a
// dictionary, not a stream, whose values are all references, dictionaries,
// arrays, names or null. Anything holding a number, string or boolean at the
// top level is a real object and gets the full policy. Treating a name map as
// an ordinary object is the safe failure, at worst dropping or refusing an
// oddly named resource.

var errNameMapBudget = errors.New("PDF name-map check exceeds its budget")

// nameMapCheckBudget bounds the bytes all name-map checks of one scanner may
// read; each check reads the value it classifies, and nested values can be
// checked again at every level.
func nameMapCheckBudget(data []byte) int {
	return 4*len(data) + 1<<16
}

// objectIsResourceNameMap reports whether an indirect object body has the
// shape of a resource-name map: a lone dictionary, never a stream.
func objectIsResourceNameMap(body []byte) bool {
	budget := nameMapCheckBudget(body)
	end, ok := resourceNameMapEnd(body, 0, &budget)
	if !ok {
		return false
	}
	tail := &pdfValueScanner{data: body, pos: end}
	tail.skipSpace()
	return tail.pos == len(body)
}

// looksLikeResourceNameMap reports whether the direct value at pos in data has
// the shape of a resource-name map. budget is shared by the checks of one
// object.
func looksLikeResourceNameMap(data []byte, pos int, budget *int) bool {
	_, ok := resourceNameMapEnd(data, pos, budget)
	return ok
}

func resourceNameMapEnd(data []byte, pos int, budget *int) (int, bool) {
	s := &pdfValueScanner{data: data, pos: pos}
	s.skipSpace()
	if !s.has("<<") {
		return 0, false
	}
	s.pos += 2
	for {
		s.skipSpace()
		if s.has(">>") {
			s.pos += 2
			*budget -= s.pos - pos
			return s.pos, *budget >= 0
		}
		if s.pos >= len(data) || data[s.pos] != '/' {
			return 0, false
		}
		s.nameEnd()
		s.skipSpace()
		if s.pos >= len(data) {
			return 0, false
		}
		switch ch := data[s.pos]; {
		case ch == '/':
			s.nameEnd()
		case ch == '[' || s.has("<<"):
			if err := s.skipValue(0, budget, pos); err != nil {
				return 0, false
			}
		case ch == '<' || ch == '(':
			return 0, false
		case pdfDigit(ch) || ch == '+' || ch == '-' || ch == '.':
			start := s.pos
			end := indirectReferenceEnd(data, start, s.tokenEnd())
			if end == s.pos {
				return 0, false // a number
			}
			s.pos = end
		default:
			start := s.pos
			if string(data[start:s.tokenEnd()]) != "null" {
				return 0, false
			}
		}
	}
}

// skipValue moves past the value at s.pos without sanitizing it.
func (s *pdfValueScanner) skipValue(depth int, budget *int, origin int) error {
	if depth >= maxPDFValueNesting {
		return errors.New("PDF value nesting exceeds maximum size")
	}
	if *budget-(s.pos-origin) < 0 {
		return errNameMapBudget
	}
	s.skipSpace()
	if s.pos >= len(s.data) {
		return errors.New("unexpected end of PDF value")
	}
	switch {
	case s.has("<<"):
		s.pos += 2
		for {
			s.skipSpace()
			if s.has(">>") {
				s.pos += 2
				return nil
			}
			if s.pos >= len(s.data) || s.data[s.pos] != '/' {
				return errors.New("unterminated PDF dictionary")
			}
			s.nameEnd()
			if err := s.skipValue(depth+1, budget, origin); err != nil {
				return err
			}
		}
	case s.data[s.pos] == '[':
		s.pos++
		for {
			s.skipSpace()
			if s.pos >= len(s.data) {
				return errors.New("unterminated PDF array")
			}
			if s.data[s.pos] == ']' {
				s.pos++
				return nil
			}
			if err := s.skipValue(depth+1, budget, origin); err != nil {
				return err
			}
		}
	case s.data[s.pos] == '<':
		_, err := s.hexStringEnd()
		return err
	case s.data[s.pos] == '(':
		_, err := s.literalStringEnd()
		return err
	case s.data[s.pos] == '/':
		s.nameEnd()
		return nil
	default:
		start := s.pos
		end := s.tokenEnd()
		if end == start {
			return errors.New("invalid PDF token")
		}
		s.pos = indirectReferenceEnd(s.data, start, end)
		return nil
	}
}
