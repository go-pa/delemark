package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"strings"

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
  -skip names
    	Comma-separated rule ids or tags to leave out, e.g. "pii" or "us-ssn"
  -list-rules
    	List the rule ids and their tags, then exit
  -list-tags
    	List the tags, then exit
  -placeholder string
    	Replacement marker for redacted secrets (default: "REDACTED")
  -h, -help
    	Show this help message

Examples:
  # Redact secrets from standard input:
  cat server.log | delemark

  # Redact secrets and email addresses:
  delemark -email < config.env

  # Redact credentials only, leaving payment cards, IBANs and US SSNs:
  delemark -skip pii < app.log

  # List the tags, such as pii, github or aws:
  delemark -list-tags

  # Redact a file with custom placeholder:
  delemark -placeholder="***" credentials.json

  # Real-time log monitoring:
  tail -f app.log | delemark -email
`)
}

func run(args []string, stdin io.Reader, stdout, stderr io.Writer) int {
	var (
		redactEmail bool
		skip        string
		listRules   bool
		listTags    bool
		placeholder string
		showHelp    bool
	)

	fs := flag.NewFlagSet("delemark", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.BoolVar(&redactEmail, "email", false, "Redact email addresses")
	fs.StringVar(&skip, "skip", "", "Comma-separated rule ids or tags to leave out")
	fs.BoolVar(&listRules, "list-rules", false, "List the rule ids and their tags")
	fs.BoolVar(&listTags, "list-tags", false, "List the tags")
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

	if listRules {
		for _, r := range delemark.Rules() {
			fmt.Fprintln(stdout, strings.TrimSpace(r.ID+" "+strings.Join(r.Tags, ",")))
		}
		return 0
	}
	if listTags {
		for _, tag := range delemark.Tags() {
			fmt.Fprintln(stdout, tag)
		}
		return 0
	}

	var skipNames []string
	for name := range strings.SplitSeq(skip, ",") {
		if name = strings.TrimSpace(name); name != "" {
			skipNames = append(skipNames, name)
		}
	}
	redactor, err := delemark.New(delemark.WithSkip(skipNames...), delemark.WithEmail(redactEmail), delemark.WithMarker(placeholder))
	if err != nil {
		fmt.Fprintln(stderr, err)
		return 2
	}

	files := fs.Args()
	if len(files) == 0 {
		if err := redactor.Stream(stdin, stdout); err != nil {
			fmt.Fprintf(stderr, "delemark: error reading stdin: %v\n", err)
			return 1
		}
		return 0
	}

	exitCode := 0
	for _, filename := range files {
		if filename == "-" {
			if err := redactor.Stream(stdin, stdout); err != nil {
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

		err = redactor.Stream(f, stdout)
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
