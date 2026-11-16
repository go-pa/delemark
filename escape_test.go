package delemark_test

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/go-pa/delemark"
)

// A span never takes the backslash of an escape whose escaped byte it
// leaves: that would end a JSON string at an escaped quote. An even run
// of backslashes is whole escapes, and is redacted with the rest.
func TestRedactKeepsEscapes(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct{ in, want string }{
		{`{"v":"POSTGRES_PASSWORD=s3cr3tpassw0rd\"quoted\""}`, `{"v":"POSTGRES_PASSWORD=[REDACTED]\"quoted\""}`},
		{`POSTGRES_PASSWORD=s3cr3tpassw0rd\\\"x"`, `POSTGRES_PASSWORD=[REDACTED]\"x"`},
		{`POSTGRES_PASSWORD=s3cr3tpassw0rd\\ x`, `POSTGRES_PASSWORD=[REDACTED] x`},
	} {
		assert.Equal(t, tc.want, testRedactor.Redact(tc.in))
		assert.True(t, delemark.Contains(tc.in))
	}

	matches := delemark.Find(`POSTGRES_PASSWORD=s3cr3tpassw0rd\"`)
	require.Len(t, matches, 1)
	assert.Equal(t, "s3cr3tpassw0rd", matches[0].Value)
}

// Every known token, redacted inside a JSON string, leaves it valid
// JSON: alone, among other text, under a key that names it, and before
// escapes.
func TestRedactKeepsJSONValid(t *testing.T) {
	t.Parallel()

	samples := []string{
		"postgres://app:s3cr3tpass@db.internal:5432/app",
		"mysql://root:hunter2hunter2@db:3306/x",
		"redis://:p4ssw0rdp4ss@cache:6379/0",
		"https://user:supersecret@example.com/path?x=1",
		"https://example.com/cb?token=abcdef0123456789abcdef&x=1",
		"POSTGRES_PASSWORD=s3cr3tpassw0rd",
		"-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEAu1SU1LfVLPHCozMxH2Mo4lgOEePzNm0tRgeLezV6ffAt0gun\n-----END RSA PRIVATE KEY-----",
	}
	for _, tc := range knownTokens {
		samples = append(samples, tc.text)
	}
	quote := func(s string) string {
		b, err := json.Marshal(s)
		require.NoError(t, err)
		return string(b)
	}
	for _, sample := range samples {
		for _, doc := range []string{
			`{"v":` + quote(sample) + `}`,
			`{"msg":` + quote("connecting with "+sample+" now") + `}`,
			`{"password":` + quote(sample) + `,"token":` + quote(sample) + `,"api_key":` + quote(sample) + `}`,
			`{"v":` + quote(sample+`"quoted"`) + `}`,
			`{"v":` + quote(sample+`\`) + `}`,
			`{"v":` + quote(sample+"\nnext\ttab") + `}`,
		} {
			out := delemark.Redact(doc)
			assert.Truef(t, json.Valid([]byte(out)), "redacting %s gave %s", doc, out)
		}
	}
}
