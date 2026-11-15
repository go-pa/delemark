package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/stretchr/testify/require"
)

func TestCLIBasicStdin(t *testing.T) {
	token := "dckr_pat_" + strings.Repeat("A", 27)
	stdin := strings.NewReader("docker token: " + token + "\n")
	var stdout, stderr bytes.Buffer

	code := run(nil, stdin, &stdout, &stderr)
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
	code2 := run([]string{"-email"}, stdin, &stdout2, &stderr2)
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
	code := run([]string{filePath}, strings.NewReader(""), &stdout, &stderr)
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
