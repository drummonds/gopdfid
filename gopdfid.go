// Package gopdfid triages PDF files for active content: JavaScript, automatic
// actions, launch actions and embedded files. It counts the PDF names and
// structural tokens that Didier Stevens' pdfid counts, scanning raw bytes so
// that malformed files (the norm for malicious PDFs) are still examined.
//
// Names are decoded before matching, so the hex-escaped /J#53 counts as /JS.
// Flate-compressed streams are inflated and scanned as well, so names hidden
// in object streams (PDF 1.5+) are counted separately in StreamCounts.
package gopdfid

import (
	"bytes"
	"compress/zlib"
	"io"
)

// maxInflated caps the bytes taken from any one stream, so a decompression
// bomb cannot exhaust memory.
const maxInflated = 32 << 20

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
	// Counts holds the number of occurrences of each keyword in Keywords in
	// the raw bytes of the file: the numbers pdfid would report.
	Counts map[string]int
	// StreamCounts holds occurrences found inside inflated Flate streams,
	// which is where object streams hide dictionaries from a raw scan.
	StreamCounts map[string]int
}

// HasActiveContent reports whether any of ActiveKeywords was seen.
func (r Report) HasActiveContent() bool {
	return len(r.ActiveContent()) > 0
}

// ActiveContent lists the active keywords present, in ActiveKeywords order.
func (r Report) ActiveContent() []string {
	var found []string
	for _, k := range ActiveKeywords {
		if r.Counts[k]+r.StreamCounts[k] > 0 {
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
		IsPDF:        bytes.HasPrefix(data, []byte("%PDF-")),
		Counts:       zeroCounts(),
		StreamCounts: zeroCounts(),
	}
	raw := scanner{data: data, counts: r.Counts, collectStreams: true}
	raw.run()
	for _, start := range raw.streams {
		inflated := inflate(streamBody(data, start))
		if len(inflated) == 0 {
			continue
		}
		s := scanner{data: inflated, counts: r.StreamCounts}
		s.run()
	}
	return r
}

func zeroCounts() map[string]int {
	m := make(map[string]int, len(Keywords))
	for _, k := range Keywords {
		m[k] = 0
	}
	return m
}

// streamBody returns the bytes from a stream's data start up to its
// endstream keyword, or to end of file when the keyword is missing.
func streamBody(data []byte, start int) []byte {
	end := bytes.Index(data[start:], []byte("endstream"))
	if end < 0 {
		return data[start:]
	}
	return data[start : start+end]
}

// inflate decodes zlib data, returning whatever was recovered before any
// error (a truncated stream still yields its leading bytes) and nil when the
// data is not zlib at all.
func inflate(body []byte) []byte {
	zr, err := zlib.NewReader(bytes.NewReader(body))
	if err != nil {
		return nil
	}
	out, _ := io.ReadAll(io.LimitReader(zr, maxInflated))
	return out
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
	// collectStreams records the data start of every stream keyword seen,
	// for inflation after the pass. Off when scanning inflated data.
	collectStreams bool
	streams        []int
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
			token := string(s.data[start:i])
			s.count(token)
			if token == "stream" && s.collectStreams {
				s.streams = append(s.streams, s.afterEOL(i))
			}
		default:
			i++
		}
	}
}

// afterEOL skips the CRLF or LF that follows the stream keyword.
func (s *scanner) afterEOL(i int) int {
	if i < len(s.data) && s.data[i] == '\r' {
		i++
	}
	if i < len(s.data) && s.data[i] == '\n' {
		i++
	}
	return i
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
