package gopdfid

import (
	"bytes"
	"compress/zlib"
	"strconv"
	"strings"
	"testing"
)

// minimalPDF wraps a catalog dictionary body in enough PDF structure for the
// scanner to see the structural tokens pdfid counts.
func minimalPDF(catalogExtra string) string {
	return "%PDF-1.4\n" +
		"1 0 obj\n<< /Type /Catalog /Pages 2 0 R " + catalogExtra + " >>\nendobj\n" +
		"2 0 obj\n<< /Type /Pages /Kids [3 0 R] /Count 1 >>\nendobj\n" +
		"3 0 obj\n<< /Type /Page /Parent 2 0 R >>\nendobj\n" +
		"xref\n0 4\ntrailer\n<< /Root 1 0 R /Size 4 >>\nstartxref\n0\n%%EOF\n"
}

func scanString(t *testing.T, s string) Report {
	t.Helper()
	r, err := Scan(strings.NewReader(s))
	if err != nil {
		t.Fatalf("Scan: %v", err)
	}
	return r
}

func TestCleanPDFHasNoActiveContent(t *testing.T) {
	r := scanString(t, minimalPDF(""))
	if r.HasActiveContent() {
		t.Errorf("clean PDF reported active content: %v", r.ActiveContent())
	}
	want := map[string]int{"obj": 3, "endobj": 3, "xref": 1, "trailer": 1, "startxref": 1, "/Page": 1}
	for k, n := range want {
		if got := r.Counts[k]; got != n {
			t.Errorf("%s: got %d want %d", k, got, n)
		}
	}
}

func TestOpenActionWithJavaScriptIsActiveContent(t *testing.T) {
	r := scanString(t, minimalPDF("/OpenAction << /S /JavaScript /JS (app.alert(1)) >>"))
	if !r.HasActiveContent() {
		t.Fatal("expected active content")
	}
	for _, k := range []string{"/OpenAction", "/JavaScript", "/JS"} {
		if r.Counts[k] != 1 {
			t.Errorf("%s: got %d want 1", k, r.Counts[k])
		}
	}
	if got := r.ActiveContent(); len(got) != 3 {
		t.Errorf("ActiveContent = %v, want the three keywords", got)
	}
}

func TestHexEscapedNamesAreCounted(t *testing.T) {
	// /J#53 is /JS and /Open#41ction is /OpenAction: a common obfuscation.
	r := scanString(t, minimalPDF("/Open#41ction << /S /JavaScript /J#53 (x) >>"))
	if r.Counts["/JS"] != 1 || r.Counts["/OpenAction"] != 1 {
		t.Errorf("hex-escaped names not counted: %v", r.Counts)
	}
}

func TestKeywordMatchesWholeNameOnly(t *testing.T) {
	r := scanString(t, minimalPDF("/JSX 1 /AAA 2 /Pages 3 /Launcher 4"))
	for _, k := range []string{"/JS", "/AA", "/Launch"} {
		if r.Counts[k] != 0 {
			t.Errorf("%s counted %d times from a longer name", k, r.Counts[k])
		}
	}
	// /Page must count /Page but not /Pages.
	if r.Counts["/Page"] != 1 {
		t.Errorf("/Page: got %d want 1", r.Counts["/Page"])
	}
}

func TestStructuralTokensNeedWordBoundaries(t *testing.T) {
	r := scanString(t, minimalPDF("/Title (object endobject xrefs)"))
	if r.Counts["obj"] != 3 || r.Counts["endobj"] != 3 || r.Counts["xref"] != 1 {
		t.Errorf("structural tokens matched inside words: %v", r.Counts)
	}
}

func TestEachActiveKeywordIsFlagged(t *testing.T) {
	for _, k := range ActiveKeywords {
		r := scanString(t, minimalPDF(k+" 1"))
		if !r.HasActiveContent() {
			t.Errorf("%s alone not flagged as active content", k)
		}
	}
}

func TestNotAPDF(t *testing.T) {
	r := scanString(t, "hello world")
	if r.IsPDF {
		t.Error("plain text reported as PDF")
	}
	r = scanString(t, minimalPDF(""))
	if !r.IsPDF {
		t.Error("PDF header not recognised")
	}
}

// objStmPDF hides a dictionary inside a Flate-compressed object stream, as
// PDF 1.5+ writers do, so the raw bytes never contain its names.
func objStmPDF(t *testing.T, hidden string, eol string) string {
	t.Helper()
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write([]byte("4 0 " + hidden)); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	return "%PDF-1.5\n" +
		"5 0 obj\n<< /Type /ObjStm /N 1 /First 4 /Filter /FlateDecode /Length " +
		strconv.Itoa(z.Len()) + " >>\nstream" + eol + z.String() + eol + "endstream\nendobj\n" +
		"trailer\n<< /Root 4 0 R >>\n%%EOF\n"
}

func TestNamesInsideObjectStreamsAreCounted(t *testing.T) {
	for _, eol := range []string{"\n", "\r\n"} {
		r := scanString(t, objStmPDF(t, "<< /Type /Catalog /OpenAction << /S /JavaScript /JS (x) >> >>", eol))
		if r.Counts["/JS"] != 0 {
			t.Errorf("eol %q: raw count saw inside a compressed stream: %d", eol, r.Counts["/JS"])
		}
		if r.StreamCounts["/JS"] != 1 || r.StreamCounts["/OpenAction"] != 1 {
			t.Errorf("eol %q: stream counts %v", eol, r.StreamCounts)
		}
		if !r.HasActiveContent() {
			t.Errorf("eol %q: active content in object stream not flagged", eol)
		}
		if r.Counts["/ObjStm"] != 1 || r.Counts["stream"] != 1 {
			t.Errorf("eol %q: raw counts %v", eol, r.Counts)
		}
	}
}

func TestUncompressibleStreamIsSkipped(t *testing.T) {
	pdf := "%PDF-1.4\n1 0 obj\n<< /Length 9 >>\nstream\n/JS junk!\nendstream\nendobj\n"
	r := scanString(t, pdf)
	// Not zlib data, so nothing inflates; the raw scan still sees /JS.
	if r.Counts["/JS"] != 1 || r.StreamCounts["/JS"] != 0 {
		t.Errorf("raw %v stream %v", r.Counts, r.StreamCounts)
	}
}

func TestStreamWithoutEndIsTolerated(t *testing.T) {
	r := scanString(t, "%PDF-1.4\n1 0 obj\n<< >>\nstream\n")
	if r.Counts["stream"] != 1 {
		t.Errorf("truncated stream: %v", r.Counts)
	}
}
