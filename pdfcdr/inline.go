// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package pdfcdr

import (
	"bytes"
)

// inlinedStreamParameterKeys may hold an indirect reference in producer
// output, but reconstruction accepts only direct values for them so a decoding
// parameter cannot be shared with, or changed through, another object. A
// direct /Length also lets the stream check repair a missing end-of-line
// marker before endstream.
var inlinedStreamParameterKeys = map[string]bool{
	"DecodeParms": true,
	"Filter":      true,
	"Length":      true,
}

// inlineStreamParameterRefs replaces a top-level /Filter, /DecodeParms or /Length
// indirect reference with the referenced object's value when that value is a
// plain direct value: not a stream and without references of its own. Any
// other input is returned unchanged, and the sanitizer then rejects what it
// still cannot accept.
func inlineStreamParameterRefs(body []byte, lookup func(refKey) ([]byte, bool)) []byte {
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
	// A repeated key is refused by the sanitizer; inlining it first would
	// copy the target once per repetition (1000 keys naming a 1 MB value
	// built a 1 GB body before that refusal).
	inlined := make(map[string]bool, len(inlinedStreamParameterKeys))
	for entries := 0; ; entries++ {
		scanner.skipSpace()
		if scanner.has(">>") || scanner.pos >= len(body) || body[scanner.pos] != '/' {
			break
		}
		if entries >= maxPDFDictEntries {
			return body
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
		if inlined[key] {
			return body
		}
		inlined[key] = true
		ref, ok := singleIndirectRefKey(body[valueStart:valueEnd])
		if !ok {
			continue
		}
		target, ok := lookup(ref)
		if !ok {
			continue
		}
		// The target is spliced as its parsed value, never as raw text: a
		// trailing comment ("57 % len") would swallow the keys after it, and
		// trailing tokens ("1 /Filter /DCTDecode") would add keys.
		target, ok = singleDirectValue(target)
		if !ok || bytes.Contains(target, []byte("stream")) {
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

// singleDirectValue returns the one value data holds, re-serialized without
// comments, or false when data is empty or holds anything after the value.
func singleDirectValue(data []byte) ([]byte, bool) {
	scanner := &pdfValueScanner{
		data:             data,
		resourceNameRefs: make(map[refKey]bool),
		normalRefCounts:  make(map[refKey]int),
	}
	scanner.skipSpace()
	if scanner.pos >= len(data) {
		return nil, false
	}
	value, end, drop, err := scanner.sanitizeValue()
	if err != nil || drop {
		return nil, false
	}
	scanner.pos = end
	scanner.skipSpace()
	if scanner.pos != len(data) {
		return nil, false
	}
	return value, true
}
