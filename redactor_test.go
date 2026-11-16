package delemark_test

import (
	"bytes"
	"slices"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pa/delemark"
)

// testMarker is the marker the tests' literal expectations are written
// in, so they do not change with [delemark.Marker].
const testMarker = "[REDACTED]"

// testRedactor redacts like the package-level functions, but with
// testMarker.
var testRedactor = func() *delemark.Redactor {
	r, err := delemark.New(delemark.WithMarker(testMarker))
	if err != nil {
		panic(err)
	}
	return r
}()

// newRedactor returns a Redactor made with opts, with testMarker
// unless opts set a marker of their own.
func newRedactor(tb testing.TB, opts ...delemark.Option) *delemark.Redactor {
	tb.Helper()
	r, err := delemark.New(append([]delemark.Option{delemark.WithMarker(testMarker)}, opts...)...)
	require.NoError(tb, err)
	return r
}

func TestRuleIDsAreUnique(t *testing.T) {
	t.Parallel()

	ids := map[string]bool{}
	for _, r := range delemark.Rules() {
		require.NotEmpty(t, r.ID)
		assert.Falsef(t, ids[r.ID], "rule id %q is not unique", r.ID)
		ids[r.ID] = true
	}
}

// TestTagsDoNotOverlapIDs: ids and tags share one namespace in
// WithSkip, so a tag named like a rule would make that name skip more
// than the rule.
func TestTagsDoNotOverlapIDs(t *testing.T) {
	t.Parallel()

	ids := map[string]bool{}
	for _, r := range delemark.Rules() {
		ids[r.ID] = true
	}
	for _, tag := range delemark.Tags() {
		assert.Falsef(t, ids[tag], "tag %q is also a rule id", tag)
	}
}

// TestEveryRuleHasATag: a rule is at least in its vendor's tag, or a
// category's such as connection-string, so that every rule can be
// skipped along with its kind.
func TestEveryRuleHasATag(t *testing.T) {
	t.Parallel()

	for _, r := range delemark.Rules() {
		assert.NotEmptyf(t, r.Tags, "rule %q has no tag", r.ID)
		assert.Lenf(t, slices.Compact(slices.Clone(r.Tags)), len(r.Tags), "rule %q repeats a tag", r.ID)
	}
}

func TestRulesAndTags(t *testing.T) {
	t.Parallel()

	var ids []string
	for _, r := range delemark.Rules() {
		ids = append(ids, r.ID)
	}
	tags := delemark.Tags()
	assert.True(t, slices.IsSorted(tags))
	assert.Equal(t, slices.Compact(slices.Clone(tags)), tags)
	assert.Subset(t, tags, []string{"pii", "aws", "github", "gitlab", "new-relic", "openai",
		"connection-string", "webhook", "crypto-key", "jwt", "url-credentials",
		"false-positive-high"})
	for _, name := range append(ids, delemark.Tags()...) {
		_, err := delemark.New(delemark.WithSkip(name))
		assert.NoErrorf(t, err, "skipping %q", name)
	}
}

// TestVendorTagsCoverTheirRules: a rule whose id starts with a tag
// and a dash, such as gitlab-pat, carries that tag, so that a rule
// added for a vendor joins its tag.
func TestVendorTagsCoverTheirRules(t *testing.T) {
	t.Parallel()

	for _, r := range delemark.Rules() {
		for _, tag := range delemark.Tags() {
			if strings.HasPrefix(r.ID, tag+"-") {
				assert.Containsf(t, r.Tags, tag, "rule %q", r.ID)
			}
		}
	}
}

func TestSkipVendorTag(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("docker"))
	token := "dckr_pat_" + strings.Repeat("A", 27)
	input := "docker " + token + " db postgres://app:s3cr3tpass@db/app"
	assert.Equal(t, "docker "+token+" db postgres://app:[REDACTED]@db/app", r.Redact(input))
}

func TestWithSkipAddsUp(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("us-ssn"), nil, delemark.WithSkip("docker"))
	token := "dckr_pat_" + strings.Repeat("A", 27)
	input := "ssn 123-45-6789 docker " + token + " card 4111 1111 1111 1111"
	assert.Equal(t, "ssn 123-45-6789 docker "+token+" card [REDACTED]", r.Redact(input))
}

func TestSkipCategoryTag(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("connection-string"))
	input := "db postgres://app:s3cr3tpass@db/app docker dckr_pat_" + strings.Repeat("A", 27)
	assert.Equal(t, "db postgres://app:s3cr3tpass@db/app docker [REDACTED]", r.Redact(input))
}

func TestNewRejectsUnknownNames(t *testing.T) {
	t.Parallel()

	_, err := delemark.New(delemark.WithSkip("pii", "us_ssn"))
	require.EqualError(t, err, `delemark: no rule or tag is named "us_ssn"`)
}

func TestDefaultRedactorMatchesPackageFunctions(t *testing.T) {
	t.Parallel()

	r, err := delemark.New()
	require.NoError(t, err)
	for _, in := range []string{
		"",
		"nothing to see",
		"card 4111 1111 1111 1111 db postgres://app:s3cr3tpass@db:5432/app",
		"docker token: dckr_pat_" + strings.Repeat("A", 27),
	} {
		assert.Equal(t, delemark.Redact(in), r.Redact(in))
		assert.Equal(t, delemark.Find(in), r.Find(in))
		assert.Equal(t, delemark.Contains(in), r.Contains(in))
	}
}

func TestSkipTagLeavesPersonalData(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("pii"))
	for _, value := range []string{
		"4111 1111 1111 1111",
		"GB82 WEST 1234 5698 7654 32",
		"123-45-6789",
	} {
		input := "value=" + value + " end"
		require.NotEqualf(t, input, delemark.Redact(input), "the default redacts %q", value)
		assert.Equalf(t, input, r.Redact(input), "skipping pii must leave %q", value)
		assert.False(t, r.Contains(input))
		assert.Empty(t, r.Find(input))
	}
}

func TestSkipTagStillRedactsSecrets(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("pii"))
	token := "dckr_pat_" + strings.Repeat("A", 27)
	input := "card 4111 1111 1111 1111 token " + token + " db postgres://app:s3cr3tpass@db:5432/app"
	assert.Equal(t, "card 4111 1111 1111 1111 token [REDACTED] db postgres://app:[REDACTED]@db:5432/app", r.Redact(input))
}

func TestSkipRuleByID(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("us-ssn"))
	input := "duration_ns=345678901 card=4111 1111 1111 1111"
	assert.Equal(t, "duration_ns=345678901 card=[REDACTED]", r.Redact(input))
}

func TestRedactorMarkerAndEmail(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("pii"), delemark.WithEmail(true), delemark.WithMarker("***"))
	input := "ssn 123-45-6789 mail ops@example.com pass postgres://app:s3cr3tpass@db/app"
	assert.Equal(t, "ssn 123-45-6789 mail *** pass postgres://app:***@db/app", r.Redact(input))
}

func TestRedactorStream(t *testing.T) {
	t.Parallel()

	r := newRedactor(t, delemark.WithSkip("pii"))
	var out bytes.Buffer
	in := "iban DE89 3704 0044 0532 0130 00\nkey postgres://app:s3cr3tpass@db/app\n" +
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
	require.NoError(t, r.Stream(strings.NewReader(in), &out))
	assert.Equal(t, "iban DE89 3704 0044 0532 0130 00\nkey postgres://app:[REDACTED]@db/app\n"+
		"-----BEGIN PRIVATE KEY-----\n[REDACTED]\n-----END PRIVATE KEY-----\n", out.String())
}

// TestRedactorStreamSkipPrivateKey: with the private-key rule skipped,
// Stream leaves a multi-line key alone, as Redact does.
func TestRedactorStreamSkipPrivateKey(t *testing.T) {
	t.Parallel()

	key := "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----\n"
	for _, name := range []string{"private-key", "crypto-key"} {
		r := newRedactor(t, delemark.WithSkip(name))
		var out bytes.Buffer
		require.NoError(t, r.Stream(strings.NewReader(key), &out))
		assert.Equalf(t, key, out.String(), "skipping %q", name)
		assert.Equalf(t, key, r.Redact(key), "skipping %q", name)
	}
}

// TestRedactorMarkerIsLiteral: a marker is written as is, a $ in it
// expanding to nothing.
func TestRedactorMarkerIsLiteral(t *testing.T) {
	t.Parallel()

	for _, marker := range []string{"$X", "$1", "${0}"} {
		r := newRedactor(t, delemark.WithEmail(true), delemark.WithMarker(marker))
		assert.Equal(t, "mail "+marker+" pass postgres://app:"+marker+"@db/app",
			r.Redact("mail bob@example.com pass postgres://app:s3cr3tpass@db/app"))
	}
}

// TestZeroRedactor: the zero Redactor runs every rule, as New() does.
func TestZeroRedactor(t *testing.T) {
	t.Parallel()

	var r delemark.Redactor
	input := "token dckr_pat_" + strings.Repeat("A", 27) + " mail bob@example.com"
	assert.Equal(t, delemark.Redact(input), r.Redact(input))
	assert.True(t, r.Contains(input))
	assert.Equal(t, delemark.Find(input), r.Find(input))
	var out bytes.Buffer
	require.NoError(t, r.Stream(strings.NewReader(input+"\n"), &out))
	assert.Equal(t, delemark.Redact(input)+"\n", out.String())
}

// TestRedactWithMatchesRedactor: the deprecated functions give what a
// Redactor of the same options gives.
func TestRedactWithMatchesRedactor(t *testing.T) {
	t.Parallel()

	opts := delemark.StreamOptions{RedactEmail: true, Marker: "***"}
	r := newRedactor(t, delemark.WithEmail(true), delemark.WithMarker("***"))
	input := "already [REDACTED] mail bob@example.com pass postgres://app:s3cr3tpass@db/app\n"
	assert.Equal(t, r.Redact(input), delemark.RedactWith(input, opts))
	var got, want bytes.Buffer
	require.NoError(t, delemark.StreamWithOptions(strings.NewReader(input), &got, opts))
	require.NoError(t, r.Stream(strings.NewReader(input), &want))
	assert.Equal(t, want.String(), got.String())
}

// logLine is a typical application log line: its date and hour are a
// ten-digit run, which passes the SSN rule's prefilter.
const logLine = `2026-11-16 12:34:56,789 INFO django.request: GET /api/v1/users/ HTTP/1.1 200 1234`

func BenchmarkRedactLogLine(b *testing.B) {
	b.ReportAllocs()
	for b.Loop() {
		_ = delemark.Redact(logLine)
	}
}

func BenchmarkRedactorSkipPIILogLine(b *testing.B) {
	r := newRedactor(b, delemark.WithSkip("pii"))
	b.ReportAllocs()
	for b.Loop() {
		_ = r.Redact(logLine)
	}
}
