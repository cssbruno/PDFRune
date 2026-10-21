// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfcdr

import (
	"bytes"

	"github.com/cssbruno/pdfrune/importpdf"
)

// inlinedStreamParameterKeys may hold an indirect reference in producer
// output, but reconstruction accepts only direct values for them so a decoding
// parameter cannot be shared with, or changed through, another object.
var inlinedStreamParameterKeys = map[string]bool{
	"DecodeParms": true,
	"Filter":      true,
}

// inlineStreamParameterRefs replaces a top-level /Filter or /DecodeParms
// indirect reference with the referenced object's value when that value is a
// plain direct value: not a stream and without references of its own. Any
// other input is returned unchanged, and the sanitizer then rejects what it
// still cannot accept.
func inlineStreamParameterRefs(body []byte, objects map[importpdf.ObjRef][]byte) []byte {
	scanner := &pdfValueScanner{
		data:             body,
		resourceNameRefs: make(map[refKey]bool),
		normalRefCounts:  make(map[refKey]int),
	}
	scanner.skipSpace()
	if !scanner.has("<<") {
		return body
	}
	scanner.pos += 2
	type replacement struct {
		start, end int
		value      []byte
	}
	var replacements []replacement
	for {
		scanner.skipSpace()
		if scanner.has(">>") || scanner.pos >= len(body) || body[scanner.pos] != '/' {
			break
		}
		keyStart := scanner.pos + 1
		keyEnd := scanner.nameEnd()
		key, err := canonicalPDFName(body[keyStart:keyEnd])
		if err != nil {
			return body
		}
		scanner.skipSpace()
		valueStart := scanner.pos
		_, valueEnd, _, err := scanner.sanitizeValue()
		if err != nil {
			return body
		}
		scanner.pos = valueEnd
		if !inlinedStreamParameterKeys[key] {
			continue
		}
		ref, ok := singleIndirectRefKey(body[valueStart:valueEnd])
		if !ok {
			continue
		}
		target, ok := objectBodyByKey(ref, objects)
		if !ok {
			continue
		}
		target = bytes.TrimSpace(target)
		if len(target) == 0 || bytes.Contains(target, []byte("stream")) {
			continue
		}
		// A parameter dictionary may keep its /JBIG2Globals stream reference;
		// the sanitizer accepts exactly that reference and nothing else.
		if refs := len(indirectRefKeys(target)) > 0; refs && (key != "DecodeParms" || !decodeParmsRefsAllowed(target)) {
			continue
		}
		replacements = append(replacements, replacement{start: valueStart, end: valueEnd, value: target})
	}
	if len(replacements) == 0 {
		return body
	}
	out := make([]byte, 0, len(body))
	previous := 0
	for _, r := range replacements {
		out = append(out, body[previous:r.start]...)
		out = append(out, ' ')
		out = append(out, r.value...)
		out = append(out, ' ')
		previous = r.end
	}
	return append(out, body[previous:]...)
}

func objectBodyByKey(key refKey, objects map[importpdf.ObjRef][]byte) ([]byte, bool) {
	ref, ok := resourceObjectRef(key, objects)
	if !ok {
		return nil, false
	}
	return objects[ref], true
}
