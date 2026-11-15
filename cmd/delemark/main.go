package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/go-pa/delemark"
)

func printUsage(w io.Writer) {
	fmt.Fprintf(w, `delemark - fast secret and sensitive data stream redactor

Usage:
  delemark [options] [file...]

If no files are specified, or if "-" is given, delemark reads from standard input.
Output is written to standard output.

Options:
  -email
    	Redact email addresses in addition to secret keys (default: false)
  -placeholder string
    	Replacement marker for redacted secrets (default: "[REDACTED]")
  -h, -help
    	Show this help message

Examples:
  # Redact secrets from standard input:
  cat server.log | delemark

  # Redact secrets and email addresses:
  delemark -email < config.env

  # Redact a file with custom placeholder:
  delemark -placeholder="***" credentials.json

  # Real-time log monitoring:
  tail -f app.log | delemark -email
`)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var (
		redactEmail bool
		placeholder string
		showHelp    bool
	)

	fs := flag.NewFlagSet("delemark", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&redactEmail, "email", false, "Redact email addresses")
	fs.StringVar(&placeholder, "placeholder", delemark.Marker, "Replacement marker for redacted secrets")
	fs.BoolVar(&showHelp, "help", false, "Show help")
	fs.BoolVar(&showHelp, "h", false, "Show help")

	fs.Usage = func() {
		printUsage(stderr)
	}

	if err := fs.Parse(args); err != nil {
		return 2
	}

	if showHelp {
		printUsage(stdout)
		return 0
	}

	opts := delemark.StreamOptions{
		RedactEmail: redactEmail,
		Marker:      placeholder,
	}

	files := fs.Args()
	if len(files) == 0 {
		if err := delemark.StreamWithOptions(stdin, stdout, opts); err != nil {
			fmt.Fprintf(stderr, "delemark: error reading stdin: %v\n", err)
			return 1
		}
		return 0
	}

	exitCode := 0
	for _, filename := range files {
		if filename == "-" {
			if err := delemark.StreamWithOptions(stdin, stdout, opts); err != nil {
				fmt.Fprintf(stderr, "delemark: error reading stdin: %v\n", err)
				exitCode = 1
			}
			continue
		}

		f, err := os.Open(filename)
		if err != nil {
			fmt.Fprintf(stderr, "delemark: %s: %v\n", filename, err)
			exitCode = 1
			continue
		}

		err = delemark.StreamWithOptions(f, stdout, opts)
		f.Close()
		if err != nil {
			fmt.Fprintf(stderr, "delemark: %s: error processing: %v\n", filename, err)
			exitCode = 1
		}
	}

	return exitCode
}

func main() {
	os.Exit(run(os.Args[1:], os.Stdin, os.Stdout, os.Stderr))
}
