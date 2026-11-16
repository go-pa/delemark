package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/go-pa/delemark"
)

// testPlaceholder sets the marker the tests' literal expectations are
// written in, so they do not change with [delemark.Marker].
const testPlaceholder = "-placeholder=[REDACTED]"

func TestCLIBasicStdin(t *testing.T) {
	token := "dckr_pat_" + strings.Repeat("A", 27)
	stdin := strings.NewReader("docker token: " + token + "\n")
	var stdout, stderr bytes.Buffer

	code := run([]string{testPlaceholder}, stdin, &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Empty(t, stderr.String())
	require.Equal(t, "docker token: [REDACTED]\n", stdout.String())
}

func TestCLIEmailFlag(t *testing.T) {
	stdin := strings.NewReader("contact test@example.com for info\n")

	// Without -email
	var stdout1, stderr1 bytes.Buffer
	code1 := run(nil, stdin, &stdout1, &stderr1)
	require.Equal(t, 0, code1)
	require.Equal(t, "contact test@example.com for info\n", stdout1.String())

	// With -email
	stdin = strings.NewReader("contact test@example.com for info\n")
	var stdout2, stderr2 bytes.Buffer
	code2 := run([]string{testPlaceholder, "-email"}, stdin, &stdout2, &stderr2)
	require.Equal(t, 0, code2)
	require.Equal(t, "contact [REDACTED] for info\n", stdout2.String())
}

func TestCLICustomPlaceholder(t *testing.T) {
	token := "dckr_pat_" + strings.Repeat("A", 27)
	stdin := strings.NewReader("docker token: " + token + "\n")
	var stdout, stderr bytes.Buffer

	code := run([]string{"-placeholder=***HIDDEN***"}, stdin, &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Equal(t, "docker token: ***HIDDEN***\n", stdout.String())
}

func TestCLIFileArgs(t *testing.T) {
	token := "dckr_pat_" + strings.Repeat("A", 27)
	tmpDir := t.TempDir()
	filePath := filepath.Join(tmpDir, "sample.txt")
	err := os.WriteFile(filePath, []byte("line with token "+token+"\n"), 0644)
	require.NoError(t, err)

	var stdout, stderr bytes.Buffer
	code := run([]string{testPlaceholder, filePath}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Empty(t, stderr.String())
	require.Equal(t, "line with token [REDACTED]\n", stdout.String())
}

func TestCLIHelp(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-help"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Contains(t, stdout.String(), "Usage:")
}

func TestCLISkipFlag(t *testing.T) {
	const line = "card 4111 1111 1111 1111 db postgres://app:s3cr3tpass@db/app\n"

	var stdout, stderr bytes.Buffer
	code := run([]string{testPlaceholder}, strings.NewReader(line), &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Equal(t, "card [REDACTED] db postgres://app:[REDACTED]@db/app\n", stdout.String())

	stdout.Reset()
	code = run([]string{testPlaceholder, "-skip", "pii"}, strings.NewReader(line), &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Empty(t, stderr.String())
	require.Equal(t, "card 4111 1111 1111 1111 db postgres://app:[REDACTED]@db/app\n", stdout.String())

	stdout.Reset()
	code = run([]string{"-skip", "pii,nope"}, strings.NewReader(line), &stdout, &stderr)
	require.Equal(t, 2, code)
	require.Empty(t, stdout.String())
	require.Contains(t, stderr.String(), `no rule or tag is named "nope"`)
}

func TestCLIListRules(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-list-rules"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Contains(t, stdout.String(), "aws-access-key-id aws\n")
	require.Contains(t, stdout.String(), "private-key crypto-key\n")
	require.Contains(t, stdout.String(), "us-ssn pii,false-positive-high\n")
}

func TestCLIListTags(t *testing.T) {
	var stdout, stderr bytes.Buffer
	code := run([]string{"-list-tags"}, strings.NewReader(""), &stdout, &stderr)
	require.Equal(t, 0, code)
	require.Empty(t, stderr.String())
	require.Equal(t, strings.Join(delemark.Tags(), "\n")+"\n", stdout.String())
	require.Contains(t, stdout.String(), "\npii\n")
}
