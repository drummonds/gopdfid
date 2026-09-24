package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func writePDF(t *testing.T, name, catalogExtra string) string {
	t.Helper()
	p := filepath.Join(t.TempDir(), name)
	body := "%PDF-1.4\n1 0 obj\n<< /Type /Catalog " + catalogExtra + " >>\nendobj\ntrailer\n<< /Root 1 0 R >>\n%%EOF\n"
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return p
}

func TestCleanFileExitsZero(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{writePDF(t, "clean.pdf", "")}, &out, &errOut)
	if code != 0 {
		t.Errorf("exit %d, stderr %q", code, errOut.String())
	}
	if !strings.Contains(out.String(), "/JS") || !strings.Contains(out.String(), "clean.pdf") {
		t.Errorf("report missing file name or keyword table:\n%s", out.String())
	}
}

func TestActiveContentExitsOne(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{writePDF(t, "bad.pdf", "/OpenAction << /S /JavaScript /JS (x) >>")}, &out, &errOut)
	if code != 1 {
		t.Errorf("exit %d want 1", code)
	}
	if !strings.Contains(out.String(), "active content: /JS /JavaScript /OpenAction") {
		t.Errorf("verdict line missing:\n%s", out.String())
	}
}

func TestMissingFileExitsTwo(t *testing.T) {
	var out, errOut bytes.Buffer
	if code := run([]string{"/nonexistent.pdf"}, &out, &errOut); code != 2 {
		t.Errorf("exit %d want 2", code)
	}
	if errOut.Len() == 0 {
		t.Error("no error message on stderr")
	}
}

func TestJSONOutput(t *testing.T) {
	var out, errOut bytes.Buffer
	code := run([]string{"-json", writePDF(t, "bad.pdf", "/AA 1")}, &out, &errOut)
	if code != 1 {
		t.Errorf("exit %d want 1", code)
	}
	s := out.String()
	if !strings.Contains(s, `"/AA": 1`) || !strings.Contains(s, `"active_content": [`) {
		t.Errorf("unexpected JSON:\n%s", s)
	}
}
