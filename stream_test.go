package delemark_test

import (
	"bytes"
	"strings"
	"testing"

	"github.com/go-pa/delemark"
	"github.com/stretchr/testify/require"
)

func TestEmailRedaction(t *testing.T) {
	input := "Send support email to support@example.com or ops.team+alert@cloud.corp.net."

	// Without email redaction
	gotNoEmail := delemark.Redact(input)
	require.Equal(t, input, gotNoEmail)

	// With email redaction
	gotEmail := delemark.RedactWith(input, delemark.StreamOptions{RedactEmail: true, Marker: testMarker})
	expected := "Send support email to [REDACTED] or [REDACTED]."
	require.Equal(t, expected, gotEmail)
}

func TestCustomPlaceholderAndStream(t *testing.T) {
	token := "dckr_pat_" + strings.Repeat("A", 27)
	input := "Docker token " + token + "\nUser email alice@example.com\n"
	var out bytes.Buffer

	err := delemark.StreamWithOptions(strings.NewReader(input), &out, delemark.StreamOptions{
		RedactEmail: true,
		Marker:      "***",
	})
	require.NoError(t, err)

	expected := "Docker token ***\nUser email ***\n"
	require.Equal(t, expected, out.String())
}

func TestStreamBasic(t *testing.T) {
	token := "dckr_pat_" + strings.Repeat("A", 27)
	input := "Normal line 1\nDocker token " + token + "\nNormal line 2\n"
	var out bytes.Buffer

	err := testRedactor.Stream(strings.NewReader(input), &out)
	require.NoError(t, err)

	expected := "Normal line 1\nDocker token [REDACTED]\nNormal line 2\n"
	require.Equal(t, expected, out.String())
}
