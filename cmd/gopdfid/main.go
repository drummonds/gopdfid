// Command gopdfid reports the PDF keywords that indicate active content
// (JavaScript, automatic and launch actions, embedded files) in one or more
// files, in the manner of Didier Stevens' pdfid.
//
// Exit status is 0 when no file has active content, 1 when at least one
// does, and 2 when a file could not be read.
package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"git.bytestone.uk/hum3/gopdfid"
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

type fileReport struct {
	File          string         `json:"file"`
	IsPDF         bool           `json:"is_pdf"`
	Counts        map[string]int `json:"counts"`
	ActiveContent []string       `json:"active_content"`
}

func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("gopdfid", flag.ContinueOnError)
	fs.SetOutput(stderr)
	asJSON := fs.Bool("json", false, "print one JSON object per file")
	fs.Usage = func() {
		fmt.Fprintln(stderr, "usage: gopdfid [-json] file.pdf...")
		fs.PrintDefaults()
	}
	if err := fs.Parse(args); err != nil {
		return 2
	}
	if fs.NArg() == 0 {
		fs.Usage()
		return 2
	}

	code := 0
	for _, path := range fs.Args() {
		r, err := scanFile(path)
		if err != nil {
			fmt.Fprintf(stderr, "gopdfid: %v\n", err)
			code = 2
			continue
		}
		if r.HasActiveContent() && code == 0 {
			code = 1
		}
		fr := fileReport{
			File:          path,
			IsPDF:         r.IsPDF,
			Counts:        r.Counts,
			ActiveContent: r.ActiveContent(),
		}
		if fr.ActiveContent == nil {
			fr.ActiveContent = []string{}
		}
		if *asJSON {
			enc := json.NewEncoder(stdout)
			enc.SetIndent("", "  ")
			enc.Encode(fr)
		} else {
			printText(stdout, fr)
		}
	}
	return code
}

func scanFile(path string) (gopdfid.Report, error) {
	f, err := os.Open(path)
	if err != nil {
		return gopdfid.Report{}, err
	}
	defer f.Close()
	return gopdfid.Scan(f)
}

func printText(w io.Writer, fr fileReport) {
	fmt.Fprintf(w, "%s\n", filepath.Base(fr.File))
	if !fr.IsPDF {
		fmt.Fprintln(w, "  (no %PDF- header)")
	}
	for _, k := range gopdfid.Keywords {
		fmt.Fprintf(w, "  %-14s %d\n", k, fr.Counts[k])
	}
	if len(fr.ActiveContent) == 0 {
		fmt.Fprintln(w, "  active content: none")
		return
	}
	fmt.Fprint(w, "  active content:")
	for _, k := range fr.ActiveContent {
		fmt.Fprint(w, " ", k)
	}
	fmt.Fprintln(w)
}
