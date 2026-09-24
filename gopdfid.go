// Package gopdfid triages PDF files for active content: JavaScript, automatic
// actions, launch actions and embedded files. It counts the PDF names and
// structural tokens that Didier Stevens' pdfid counts, scanning raw bytes so
// that malformed files (the norm for malicious PDFs) are still examined.
//
// Names are decoded before matching, so the hex-escaped /J#53 counts as /JS.
package gopdfid

import (
	"bytes"
	"io"
)

// Keywords is every name and structural token counted, in report order.
var Keywords = []string{
	"obj", "endobj", "stream", "endstream", "xref", "trailer", "startxref",
	"/Page", "/Encrypt", "/ObjStm",
	"/JS", "/JavaScript", "/AA", "/OpenAction", "/AcroForm", "/JBIG2Decode",
	"/RichMedia", "/Launch", "/EmbeddedFile", "/XFA", "/URI",
}

// ActiveKeywords are the names whose presence means the PDF can run code or
// carry a payload without the reader clicking anything: JavaScript, automatic
// actions, launch actions, rich media, XFA forms, embedded files and the
// JBIG2 decoder that has hosted exploits.
var ActiveKeywords = []string{
	"/JS", "/JavaScript", "/AA", "/OpenAction", "/Launch",
	"/RichMedia", "/XFA", "/EmbeddedFile", "/JBIG2Decode",
}

// Report is the result of scanning one file.
type Report struct {
	// IsPDF is true when the file starts with a %PDF- header.
	IsPDF bool
	// Counts holds the number of occurrences of each keyword in Keywords.
	Counts map[string]int
}

// HasActiveContent reports whether any of ActiveKeywords was seen.
func (r Report) HasActiveContent() bool {
	return len(r.ActiveContent()) > 0
}

// ActiveContent lists the active keywords present, in ActiveKeywords order.
func (r Report) ActiveContent() []string {
	var found []string
	for _, k := range ActiveKeywords {
		if r.Counts[k] > 0 {
			found = append(found, k)
		}
	}
	return found
}

// Scan reads the whole file and counts keywords.
func Scan(src io.Reader) (Report, error) {
	data, err := io.ReadAll(src)
	if err != nil {
		return Report{}, err
	}
	return ScanBytes(data), nil
}

// ScanBytes counts keywords in an in-memory file.
func ScanBytes(data []byte) Report {
	r := Report{
		IsPDF:  bytes.HasPrefix(data, []byte("%PDF-")),
		Counts: make(map[string]int, len(Keywords)),
	}
	for _, k := range Keywords {
		r.Counts[k] = 0
	}
	s := scanner{data: data, counts: r.Counts}
	s.run()
	return r
}

var wanted = func() map[string]bool {
	m := make(map[string]bool, len(Keywords))
	for _, k := range Keywords {
		m[k] = true
	}
	return m
}()

type scanner struct {
	data   []byte
	counts map[string]int
}

// run walks the bytes once. A '/' starts a name, which is decoded and matched
// as a whole; any other run of regular characters is a token matched as a
// whole. Delimiters and whitespace end both.
func (s *scanner) run() {
	i := 0
	for i < len(s.data) {
		c := s.data[i]
		switch {
		case c == '/':
			name, next := s.readName(i + 1)
			s.count("/" + name)
			i = next
		case isRegular(c):
			start := i
			for i < len(s.data) && isRegular(s.data[i]) {
				i++
			}
			s.count(string(s.data[start:i]))
		default:
			i++
		}
	}
}

func (s *scanner) count(token string) {
	if wanted[token] {
		s.counts[token]++
	}
}

// readName decodes a name starting at i (just after the '/'), resolving #xx
// hex escapes, and returns it with the index of the first byte after it.
func (s *scanner) readName(i int) (string, int) {
	var name []byte
	for i < len(s.data) && isRegular(s.data[i]) {
		c := s.data[i]
		if c == '#' && i+2 < len(s.data) && isHex(s.data[i+1]) && isHex(s.data[i+2]) {
			name = append(name, hexVal(s.data[i+1])<<4|hexVal(s.data[i+2]))
			i += 3
			continue
		}
		name = append(name, c)
		i++
	}
	return string(name), i
}

// isRegular is true for PDF regular characters: anything that is neither
// whitespace nor a delimiter.
func isRegular(c byte) bool {
	switch c {
	case 0, '\t', '\n', '\f', '\r', ' ',
		'(', ')', '<', '>', '[', ']', '{', '}', '/', '%':
		return false
	}
	return true
}

func isHex(c byte) bool {
	return hexVal(c) != 0xff
}

func hexVal(c byte) byte {
	switch {
	case c >= '0' && c <= '9':
		return c - '0'
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10
	}
	return 0xff
}
