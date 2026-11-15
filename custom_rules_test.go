package delemark_test

import (
	"testing"

	"github.com/go-pa/delemark"
	"github.com/stretchr/testify/require"
)

func TestCustomRules(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected string
	}{
		{
			name:     "Divio PAK",
			input:    "deploy with token divio_pak_dGVzdC1zZWNyZXQta2V5LXRva2VuLWZvci1kaXZpby0 and done",
			expected: "deploy with token [REDACTED] and done",
		},
		{
			name:     "Exoscale API Key ID",
			input:    "EXOSCALE key EXO29147e9f89102b7ac1e88514 active",
			expected: "EXOSCALE key [REDACTED] active",
		},
		{
			name:     "Exoscale Authorization Header",
			input:    "Authorization: EXO2-HMAC-SHA256 credential=EXO29147e9f89102b7ac1e88514,expires=1700000000",
			expected: "Authorization: EXO2-HMAC-SHA256 credential=[REDACTED],expires=1700000000",
		},
		{
			name:     "Exoscale Contextual Secret",
			input:    `exoscale_secret = "abcdef1234567890abcdef1234567890"`,
			expected: `exoscale_secret = "[REDACTED]"`,
		},
		{
			name:     "Cloudflare Modern User API Token",
			input:    "token: cfut_abcdefghijklmnopqrstuvwxyz01234567890123456789",
			expected: "token: [REDACTED]",
		},
		{
			name:     "Cloudflare Modern Global API Key",
			input:    "cf key cfk_abcdefghijklmnopqrstuvwxyz01234567890123456789",
			expected: "cf key [REDACTED]",
		},
		{
			name:     "Nessus API Keys Header",
			input:    "X-ApiKeys: accessKey=0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef; secretKey=fedcba9876543210fedcba9876543210fedcba9876543210fedcba9876543210;",
			expected: "X-ApiKeys: accessKey=[REDACTED]; secretKey=[REDACTED];",
		},
		{
			name:     "Nessus Contextual Key",
			input:    `nessus_key: 0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef`,
			expected: `nessus_key: [REDACTED]`,
		},
		{
			name:     "Postgres Environment Variable PGPASSWORD",
			input:    `export PGPASSWORD="MySuperSecretPostgresPassword123"`,
			expected: `export PGPASSWORD="[REDACTED]"`,
		},
		{
			name:     "Postgres Environment Variable POSTGRES_PASSWORD",
			input:    `POSTGRES_PASSWORD=databaseSecretPass`,
			expected: `POSTGRES_PASSWORD=[REDACTED]`,
		},
		{
			name:     "Postgres .pgpass line",
			input:    `db.example.com:5432:mydb:myuser:secretPassInFile`,
			expected: `db.example.com:5432:mydb:myuser:[REDACTED]`,
		},
		{
			name:     "Authenticated URL HTTP Basic Auth",
			input:    `git clone https://admin:mysecretpassword@github.com/myorg/repo.git`,
			expected: `git clone https://admin:[REDACTED]@github.com/myorg/repo.git`,
		},
		{
			name:     "Authenticated URL Secret Query Parameter",
			input:    `https://api.example.com/v1/webhook?access_token=superSecretTokenVal&format=json`,
			expected: `https://api.example.com/v1/webhook?access_token=[REDACTED]&format=json`,
		},
		{
			name:     "URL Query AWS Signature",
			input:    `https://s3.amazonaws.com/bucket/file?x-amz-signature=abcdef1234567890abcdef1234567890`,
			expected: `https://s3.amazonaws.com/bucket/file?x-amz-signature=[REDACTED]`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := delemark.Redact(tt.input)
			require.Equal(t, tt.expected, got)
		})
	}
}

func TestNegativeFalsePositives(t *testing.T) {
	negatives := []string{
		// Uppercase English constant starting with EXO should NOT match
		"EXOPLANETARY_SYSTEM_RESEARCH_PAPER_2026",
		// Harmless query params should NOT match
		"https://example.com/search?key=books&page=2",
		// Divio PAK with invalid length should NOT match
		"divio_pak_short",
		"divio_pak_abc1234567890xyz_prod",
		// Code assignments should NOT match
		"user.password = req.body.password",
		"if (password == \"\")",
		// Standard URLs without credentials should NOT match
		"http://localhost:8080/api/users",
		"https://github.com/go-pa/delemark",
	}

	for _, input := range negatives {
		t.Run(input, func(t *testing.T) {
			got := delemark.Redact(input)
			require.Equal(t, input, got, "expected false positive check to preserve original text")
		})
	}
}
