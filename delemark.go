package delemark

import (
	"bufio"
	"cmp"
	"fmt"
	"io"
	"math"
	"regexp"
	"slices"
	"strings"
	"sync"
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

// An Option configures a [Redactor] made by [New].
type Option func(*config)

// config is what the options of [New] set.
type config struct {
	skip        []string
	marker      string
	redactEmail bool
}

// WithSkip leaves rules out, each named by its id or by one of its
// tags: "pii" for payment cards, IBANs and US SSNs, a vendor's name,
// such as "github", for all of its rules, or a category such as
// "connection-string" or "webhook". [Rules] and [Tags] list them.
// Rules added to the catalogue later run unless they are skipped too.
// The names of every WithSkip add up.
func WithSkip(names ...string) Option {
	return func(c *config) { c.skip = append(c.skip, names...) }
}

// WithMarker replaces every redacted span with marker rather than
// [Marker]; empty is [Marker]. A marker that some rule matches makes
// [Redactor.Redact] no longer idempotent.
func WithMarker(marker string) Option {
	return func(c *config) { c.marker = marker }
}

// WithEmail redacts email addresses as well, when redact is true.
// [Redactor.Find] and [Redactor.Contains] do not look for them.
func WithEmail(redact bool) Option {
	return func(c *config) { c.redactEmail = redact }
}

// A Redactor detects and redacts secrets with the rules the options of
// [New] leave in. It is safe for concurrent use. The package-level
// functions use one with every rule, and so does the zero Redactor.
type Redactor struct {
	// ac is the keyword pre-filter of every rule, nil in the zero
	// Redactor.
	ac    *acAutomaton
	rules []*compiledRule
	// index finds the rules the keywords of an input can pass.
	index ruleIndex
	// alwaysRun is whether a rule of rules bypasses the keyword
	// pre-filter. Without one, an input without a keyword runs no regex.
	alwaysRun bool
	// collapsePEM is whether the private-key rule is among rules, which
	// [Redactor.Stream] then applies across lines.
	collapsePEM bool
	marker      string
	redactEmail bool
}

// privateKeyRule is the id of the rule [Redactor.Stream] applies to
// multi-line private keys.
const privateKeyRule = "private-key"

// New returns a Redactor configured by opts, applied in order. Without
// options it runs every rule, as the package-level functions do. It
// fails when a name given to [WithSkip] is neither a rule's id nor a
// tag.
func New(opts ...Option) (*Redactor, error) {
	var c config
	for _, opt := range opts {
		if opt != nil {
			opt(&c)
		}
	}
	rs := compiledRuleSet()
	// used records which names of c.skip named a rule.
	used := make(map[string]bool, len(c.skip))
	for _, name := range c.skip {
		used[name] = false
	}
	r := &Redactor{
		ac:          rs.ac,
		rules:       make([]*compiledRule, 0, len(rs.rules)),
		index:       newRuleIndex(rs.keywords),
		marker:      cmp.Or(c.marker, Marker),
		redactEmail: c.redactEmail,
	}
	for i := range rs.rules {
		cr := &rs.rules[i]
		skipped := false
		if len(used) > 0 {
			if _, ok := used[cr.id]; ok {
				used[cr.id], skipped = true, true
			}
			for _, tag := range cr.tags {
				if _, ok := used[tag]; ok {
					used[tag], skipped = true, true
				}
			}
		}
		if skipped {
			continue
		}
		r.index.add(len(r.rules), cr)
		r.rules = append(r.rules, cr)
		if cr.kwBits.empty() {
			r.alwaysRun = true
		}
		if cr.id == privateKeyRule {
			r.collapsePEM = true
		}
	}
	for _, name := range c.skip {
		if !used[name] {
			return nil, fmt.Errorf("delemark: no rule or tag is named %q", name)
		}
	}
	return r, nil
}

// defaultRedactor runs every rule. It is built on first use, like the
// rule set it shares.
var defaultRedactor = sync.OnceValue(func() *Redactor {
	r, err := New()
	if err != nil {
		panic(err)
	}
	return r
})

// orDefault returns r, or the default Redactor when r is the zero
// Redactor.
func (r *Redactor) orDefault() *Redactor {
	if r.ac == nil {
		return defaultRedactor()
	}
	return r
}

// A Rule describes one of the built-in rules.
type Rule struct {
	// ID names the rule in [WithSkip].
	ID string
	// Tags are the categories the rule is in, which [WithSkip] also
	// accepts.
	Tags []string
}

// Rules returns the built-in rules, in the order they run.
func Rules() []Rule {
	rs := compiledRuleSet()
	out := make([]Rule, len(rs.rules))
	for i, r := range rs.rules {
		out[i] = Rule{ID: r.id, Tags: slices.Clone(r.tags)}
	}
	return out
}

// Tags returns the tags of the built-in rules, sorted, each once.
func Tags() []string {
	var out []string
	for _, r := range compiledRuleSet().rules {
		out = append(out, r.tags...)
	}
	slices.Sort(out)
	return slices.Compact(out)
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
	return defaultRedactor().Find(text)
}

// Find is [Find] with r's rules.
func (r *Redactor) Find(text string) []Match {
	r = r.orDefault()
	return dedupOverlapping(r.findMatches(text))
}

// scanPrelude runs the shared pre-filter behind [Find], [Redact],
// and [Contains]: the Aho–Corasick pass over text. ok is false when
// no rule could possibly match — empty input, or no keyword hit and
// no always-run rule among r's — letting callers return without
// touching any regex.
func (r *Redactor) scanPrelude(text string) (found kwMask, ok bool) {
	if text == "" {
		return kwMask{}, false
	}
	found = r.ac.scan(text)
	if found.empty() && !r.alwaysRun {
		return kwMask{}, false
	}
	return found, true
}

func (r *Redactor) findMatches(text string) []Match {
	found, ok := r.scanPrelude(text)
	if !ok {
		return nil
	}
	var matches []Match
	cand := r.index.candidates(&found)
	for i := range cand.all() {
		cr := r.rules[i]
		if !cr.passes(found, text) {
			continue
		}
		compiled := cr.compile()
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
	return keepEscapes(text, matches)
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
	return defaultRedactor().Contains(text)
}

// Contains is [Contains] with r's rules.
func (r *Redactor) Contains(text string) bool {
	r = r.orDefault()
	found, ok := r.scanPrelude(text)
	if !ok {
		return false
	}
	cand := r.index.candidates(&found)
	for i := range cand.all() {
		cr := r.rules[i]
		if !cr.passes(found, text) {
			continue
		}
		compiled := cr.compile()
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
	return defaultRedactor().FindBytes(b)
}

// FindBytes is [FindBytes] with r's rules.
func (r *Redactor) FindBytes(b []byte) []Match {
	if len(b) == 0 {
		return nil
	}
	return r.Find(unsafe.String(unsafe.SliceData(b), len(b)))
}

// ContainsBytes is like [Contains] but accepts a []byte without
// copying it. b is read but never mutated.
func ContainsBytes(b []byte) bool {
	return defaultRedactor().ContainsBytes(b)
}

// ContainsBytes is [ContainsBytes] with r's rules.
func (r *Redactor) ContainsBytes(b []byte) bool {
	if len(b) == 0 {
		return false
	}
	return r.Contains(unsafe.String(unsafe.SliceData(b), len(b)))
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
	return defaultRedactor().Redact(text)
}

// Redact is [Redact] with r's rules, replacing spans with r's marker,
// and redacting email addresses too if r does.
func (r *Redactor) Redact(text string) string {
	r = r.orDefault()
	res := replaceSpans(text, mergeOverlapping(r.findMatches(text)), r.marker)
	if r.redactEmail {
		res = reEmail.ReplaceAllLiteralString(res, r.marker)
	}
	return res
}

// replaceSpans returns text with every span of matches, which are
// sorted and do not overlap, replaced by marker.
func replaceSpans(text string, matches []Match, marker string) string {
	if len(matches) == 0 {
		return text
	}
	size := len(text)
	for _, m := range matches {
		size -= m.End - m.Start
	}
	if marker == "" || len(matches) <= (math.MaxInt-size)/len(marker) {
		size += len(matches) * len(marker)
	} else {
		// Let the builder handle growth if the final size overflows.
		size = len(text)
	}
	var b strings.Builder
	b.Grow(size)
	cursor := 0
	for _, m := range matches {
		b.WriteString(text[cursor:m.Start])
		b.WriteString(marker)
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

// keepEscape returns end, the end of a span, moved back off a backslash
// that escapes the byte after the span. Replacing that backslash would
// leave the byte unescaped: a JSON string holding `secret\"` would end
// at the quote. Whether the last backslash escapes the next byte goes
// by the whole run of backslashes ending at end, those before the span
// too. A span that ends on whole escapes, an even run, stays as it is.
func keepEscape(text string, end int) int {
	run := 0
	for i := end - 1; i >= 0 && text[i] == '\\'; i-- {
		run++
	}
	if run%2 == 1 {
		return end - 1
	}
	return end
}

// keepEscapes moves the end of every match off a backslash, as
// keepEscape does, and drops a match that leaves nothing. It runs apart
// from the rule loop, and only on inputs with matches.
func keepEscapes(text string, matches []Match) []Match {
	kept := matches[:0]
	for _, m := range matches {
		if end := keepEscape(text, m.End); end != m.End {
			m.End, m.Value = end, text[m.Start:end]
		}
		if m.End > m.Start {
			kept = append(kept, m)
		}
	}
	return kept
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
//
// Deprecated: Use [New] with [WithEmail] and [WithMarker], which can
// also skip rules.
type StreamOptions struct {
	RedactEmail bool
	Marker      string // replacement marker (default: Marker "[REDACTED]")
}

// fromStreamOptions returns the Redactor the deprecated functions taking opts
// stand for: every rule, with opts' marker and email setting.
func fromStreamOptions(opts StreamOptions) *Redactor {
	r := *defaultRedactor()
	r.marker = cmp.Or(opts.Marker, Marker)
	r.redactEmail = opts.RedactEmail
	return &r
}

// RedactWith redacts secrets and optionally email addresses with a custom marker.
//
// Deprecated: Use [Redactor.Redact] of a Redactor made by [New].
func RedactWith(text string, opts StreamOptions) string {
	return fromStreamOptions(opts).Redact(text)
}

// Stream reads from reader line by line, applies Redact, and writes to writer.
func Stream(reader io.Reader, writer io.Writer) error {
	return defaultRedactor().Stream(reader, writer)
}

// StreamWithOptions reads from reader line by line and writes redacted content to writer with options.
//
// Deprecated: Use [Redactor.Stream] of a Redactor made by [New].
func StreamWithOptions(reader io.Reader, writer io.Writer, opts StreamOptions) error {
	return fromStreamOptions(opts).Stream(reader, writer)
}

// isPEMLine reports whether line has a private key's BEGIN or END
// armour, as named by dash.
func isPEMLine(line, dash string) bool {
	return strings.Contains(line, dash) && strings.Contains(strings.ToUpper(line), "PRIVATE KEY")
}

// Stream reads from reader line by line and writes the lines to writer,
// redacted by r. Unless the private-key rule is skipped, interior lines
// of a multi-line private key are left out, the key replaced by r's
// marker.
func (r *Redactor) Stream(reader io.Reader, writer io.Writer) error {
	r = r.orDefault()
	bufReader := bufio.NewReader(reader)
	inPEMBlock := false

	for {
		line, err := bufReader.ReadString('\n')
		if len(line) > 0 {
			out := ""
			switch {
			case inPEMBlock:
				// Skip interior lines of multi-line private key
				inPEMBlock = !isPEMLine(line, "-----END")
			case r.collapsePEM && isPEMLine(line, "-----BEGIN") && !isPEMLine(line, "-----END"):
				// Multi-line PEM start
				inPEMBlock = true
				out = "-----BEGIN PRIVATE KEY-----\n" + r.marker + "\n-----END PRIVATE KEY-----\n"
			default:
				out = r.Redact(line)
			}
			if out != "" {
				if _, writeErr := io.WriteString(writer, out); writeErr != nil {
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
