package delemark_test

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"

	"github.com/go-pa/delemark"
)

func TestRedactOutputSizes(t *testing.T) {
	t.Parallel()

	body := strings.Repeat("A", 64<<10)
	for _, tc := range []struct {
		name, input, want string
	}{
		{"clean", "unchanged text", "unchanged text"},
		{"expanding", strings.Repeat("redis://:a@host\n", 100), strings.Repeat("redis://:"+delemark.Marker+"@host\n", 100)},
		{"shrinking", "-----BEGIN PRIVATE KEY-----\n" + body + "\n-----END PRIVATE KEY-----", "-----BEGIN PRIVATE KEY-----" + delemark.Marker + "-----END PRIVATE KEY-----"},
		{"touching", strings.Repeat("dckr_pat_"+strings.Repeat("a", 27), 2), strings.Repeat(delemark.Marker, 2)},
		{"overlapping", "glpat-" + strings.Repeat("a", 40) + ".ab1234567", delemark.Marker},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := delemark.Redact(tc.input)
			assert.Equal(t, tc.want, got)
			assert.Equal(t, got, delemark.Redact(got))
		})
	}
}

func BenchmarkRedactOutputSizes(b *testing.B) {
	for _, tc := range []struct {
		name, input string
	}{
		{"shrinking", "-----BEGIN PRIVATE KEY-----\n" + strings.Repeat("A", 64<<10) + "\n-----END PRIVATE KEY-----"},
		{"expanding", strings.Repeat("redis://:a@host\n", 100)},
	} {
		b.Run(tc.name, func(b *testing.B) {
			delemark.Redact(tc.input) // Warm lazy rule compilation.
			b.ReportAllocs()
			for b.Loop() {
				delemark.Redact(tc.input)
			}
		})
	}
}
