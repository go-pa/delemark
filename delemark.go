package delemark

import (
	"bufio"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"unsafe"
)

// Marker replaces every detected secret span. Chosen so it doesn't
// match any rule's keyword pre-filter — see TestMarkerIsNotASecret
// for the safety property that makes [Redact] idempotent.
const Marker = "[REDACTED]"

// Match describes a single secret span detected in an input. Start
// and End are byte offsets into the original text and delimit the
// same span [Redact] would replace with [Marker]: when the matching
// rule defines a (?P<secret>…) named subgroup, the span covers only
// that subgroup; otherwise it covers the whole match. Value is the
// substring text[Start:End] for caller convenience.
type Match struct {
	Start int
	End   int
	Value string
}

// Find returns every secret span detected in text, in left-to-right
// order. Overlapping matches are deduplicated: when two rules flag
// overlapping spans (e.g. a Grafana legacy `eyJrIjoi…` token whose
// suffix also matches the generic JWT shape) Find keeps the longest
// span and drops the shorter one, so each underlying secret is
// reported once.
//
// Find is safe for concurrent use. The returned slice is freshly
// allocated and owned by the caller.
func Find(text string) []Match {
	return dedupOverlapping(findMatches(text))
}

// scanPrelude runs the shared pre-filter behind [Find], [Redact],
// and [Contains]: the Aho–Corasick pass over text. ok is false when
// no rule could possibly match — empty input, or no keyword hit and
// no always-run rules — letting callers return without touching any
// regex.
func scanPrelude(text string) (rs *ruleSet, found kwMask, ok bool) {
	if text == "" {
		return nil, kwMask{}, false
	}
	rs = compiledRuleSet()
	found = rs.ac.scan(text)
	if found.empty() && !rs.hasAlwaysRun {
		return nil, kwMask{}, false
	}
	return rs, found, true
}

func findMatches(text string) []Match {
	rs, found, ok := scanPrelude(text)
	if !ok {
		return nil
	}
	var matches []Match
	for i := range rs.rules {
		r := &rs.rules[i]
		if !r.passes(found, text) {
			continue
		}
		compiled := r.compile()
		for _, m := range compiled.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := redactSpan(m, compiled.secretIdx)
			if e <= s {
				continue
			}
			value := text[s:e]
			if compiled.validator != nil && !compiled.validator(value) {
				continue
			}
			matches = append(matches, Match{Start: s, End: e, Value: value})
		}
	}
	return matches
}

// sortMatches orders matches by Start ascending, breaking ties by
// End descending so that at equal starts the longest span comes
// first — the order both [dedupOverlapping] and [mergeOverlapping]
// rely on for their single greedy pass.
func sortMatches(matches []Match) {
	slices.SortFunc(matches, func(a, b Match) int {
		if a.Start != b.Start {
			return a.Start - b.Start
		}
		return b.End - a.End
	})
}

// dedupOverlapping collapses overlapping matches to one per underlying
// span, keeping the longest. After sorting by Start asc, End desc, a
// greedy walk drops anything contained in the last kept match, and a
// later-starting match that overlaps the last kept one replaces it
// when it is longer (unless that would also swallow the match before
// it). Touching spans (m.Start == lastEnd) are kept: they represent
// two distinct secrets concatenated without a separator, and merging
// them would hide the second one. The relative left-to-right order of
// surviving matches is preserved.
func dedupOverlapping(matches []Match) []Match {
	if len(matches) < 2 {
		return matches
	}
	sortMatches(matches)
	out := matches[:0]
	for _, m := range matches {
		if len(out) == 0 || m.Start >= out[len(out)-1].End {
			out = append(out, m)
			continue
		}
		last := out[len(out)-1]
		if m.End-m.Start > last.End-last.Start &&
			(len(out) == 1 || m.Start >= out[len(out)-2].End) {
			out[len(out)-1] = m
		}
	}
	return out
}

// Contains reports whether text matches any built-in secret rule.
// It is safe for concurrent use.
func Contains(text string) bool {
	rs, found, ok := scanPrelude(text)
	if !ok {
		return false
	}
	for i := range rs.rules {
		r := &rs.rules[i]
		if !r.passes(found, text) {
			continue
		}
		compiled := r.compile()
		if compiled.validator == nil {
			if compiled.re.MatchString(text) {
				return true
			}
			continue
		}
		for _, m := range compiled.re.FindAllStringSubmatchIndex(text, -1) {
			s, e := redactSpan(m, compiled.secretIdx)
			if compiled.validator(text[s:e]) {
				return true
			}
		}
	}
	return false
}

// FindBytes is like [Find] but accepts a []byte. It does not copy
// the input: each returned [Match.Value] aliases b. Callers must
// not mutate b for as long as those Value strings are in use.
//
// Use this when scanning a buffer (file contents, HTTP body, log
// chunk) you'd otherwise pass through string(b) — that conversion
// always copies, FindBytes does not.
func FindBytes(b []byte) []Match {
	if len(b) == 0 {
		return nil
	}
	return Find(unsafe.String(unsafe.SliceData(b), len(b)))
}

// ContainsBytes is like [Contains] but accepts a []byte without
// copying it. b is read but never mutated.
func ContainsBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return Contains(unsafe.String(unsafe.SliceData(b), len(b)))
}

// Redact returns a copy of text with every detected secret span
// replaced by [Marker]. When a rule defines a (?P<secret>…) named
// subgroup, only that span is replaced (so callers still see
// "AWS_SECRET_ACCESS_KEY=[REDACTED]"); otherwise the whole match is
// replaced.
//
// Idempotent: [Marker] does not match any rule, so calling Redact
// twice yields the same result. Safe for concurrent use.
func Redact(text string) string {
	matches := mergeOverlapping(findMatches(text))
	if len(matches) == 0 {
		return text
	}
	size := len(text)
	for _, m := range matches {
		size -= m.End - m.Start
	}
	if len(matches) <= (math.MaxInt-size)/len(Marker) {
		size += len(matches) * len(Marker)
	} else {
		// Let the builder handle growth if the final size overflows.
		size = len(text)
	}
	var b strings.Builder
	b.Grow(size)
	cursor := 0
	for _, m := range matches {
		b.WriteString(text[cursor:m.Start])
		b.WriteString(Marker)
		cursor = m.End
	}
	b.WriteString(text[cursor:])
	return b.String()
}

func mergeOverlapping(matches []Match) []Match {
	if len(matches) < 2 {
		return matches
	}
	sortMatches(matches)
	out := matches[:0]
	for _, m := range matches {
		if len(out) == 0 || m.Start >= out[len(out)-1].End {
			out = append(out, m)
			continue
		}
		if m.End > out[len(out)-1].End {
			out[len(out)-1].End = m.End
			out[len(out)-1].Value = ""
		}
	}
	return out
}

// redactSpan returns the [start, end) byte offsets that should be
// replaced by [Marker] for a given regex match. When the rule
// declares a (?P<secret>…) named subgroup that participated in the
// match, only that span is replaced — preserving the framing text
// (e.g. "AWS_SECRET_ACCESS_KEY=" or "postgresql://app:") so log
// readers can still tell what was redacted. Otherwise the whole
// match span is replaced.
func redactSpan(m []int, secretIdx int) (start, end int) {
	if secretIdx >= 0 && m[2*secretIdx] >= 0 {
		return m[2*secretIdx], m[2*secretIdx+1]
	}
	return m[0], m[1]
}

var reEmail = regexp.MustCompile(`\b[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}\b`)

// StreamOptions configures streaming redaction.
type StreamOptions struct {
	RedactEmail bool
	Marker      string // replacement marker (default: Marker "[REDACTED]")
}

// RedactWith redacts secrets and optionally email addresses with a custom marker.
func RedactWith(text string, opts StreamOptions) string {
	res := Redact(text)
	marker := opts.Marker
	if marker != "" && marker != Marker {
		res = strings.ReplaceAll(res, Marker, marker)
	}
	if opts.RedactEmail {
		if marker == "" {
			marker = Marker
		}
		res = reEmail.ReplaceAllString(res, marker)
	}
	return res
}

// Stream reads from reader line by line, applies Redact, and writes to writer.
func Stream(reader io.Reader, writer io.Writer) error {
	return StreamWithOptions(reader, writer, StreamOptions{})
}

// StreamWithOptions reads from reader line by line and writes redacted content to writer with options.
func StreamWithOptions(reader io.Reader, writer io.Writer, opts StreamOptions) error {
	marker := opts.Marker
	if marker == "" {
		marker = Marker
	}
	bufReader := bufio.NewReader(reader)
	inPEMBlock := false

	for {
		line, err := bufReader.ReadString('\n')
		if len(line) > 0 {
			if inPEMBlock {
				if strings.Contains(line, "-----END") && strings.Contains(strings.ToUpper(line), "PRIVATE KEY") {
					inPEMBlock = false
				}
				// Skip interior lines of multi-line private key
			} else if strings.Contains(line, "-----BEGIN") && strings.Contains(strings.ToUpper(line), "PRIVATE KEY") {
				if strings.Contains(line, "-----END") && strings.Contains(strings.ToUpper(line), "PRIVATE KEY") {
					// Single line PEM
					redacted := RedactWith(line, opts)
					if _, writeErr := io.WriteString(writer, redacted); writeErr != nil {
						return writeErr
					}
				} else {
					// Multi-line PEM start
					inPEMBlock = true
					if _, writeErr := io.WriteString(writer, "-----BEGIN PRIVATE KEY-----\n"+marker+"\n-----END PRIVATE KEY-----\n"); writeErr != nil {
						return writeErr
					}
				}
			} else {
				redacted := RedactWith(line, opts)
				if _, writeErr := io.WriteString(writer, redacted); writeErr != nil {
					return writeErr
				}
			}
		}

		if err != nil {
			if err == io.EOF {
				break
			}
			return err
		}
	}
	return nil
}
