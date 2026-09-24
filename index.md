# gopdfid

Triage a PDF for active content before opening it: JavaScript, automatic
actions (`/OpenAction`, `/AA`), launch actions, rich media, XFA forms and
embedded files. A Go take on Didier Stevens'
[pdfid](https://blog.didierstevens.com/programs/pdf-tools/): it counts the
same keywords by scanning the raw bytes, so a malformed file (the norm for
malicious PDFs) is still examined, and it decodes `#xx` hex escapes so the
obfuscated `/J#53` is counted as `/JS`.

Pure Go, standard library only, no cgo. Usable as a CLI or as a library
(the intended use is scanning mail attachments in
[gomail](https://git.bytestone.uk/hum3/gomail)).

This is triage, not a verdict. A hit means the file can run code or carry a
payload and deserves a closer look with pdf-parser or a sandbox; a clean
count does not prove the file safe.

## Install

```
go install git.bytestone.uk/hum3/gopdfid/cmd/gopdfid@latest
```

## Use

```
gopdfid suspect.pdf            # keyword table and an "active content" line
gopdfid -json a.pdf b.pdf      # one JSON object per file
```

Exit status is 0 when no file has active content, 1 when at least one does,
and 2 when a file could not be read, so it drops into shell pipelines.

```
suspect.pdf
  obj            12
  endobj         12
  ...
  /JS            1
  /JavaScript    1
  /OpenAction    1
  ...
  active content: /JS /JavaScript /OpenAction
```

## Library

```go
r, err := gopdfid.Scan(file)
if err == nil && r.HasActiveContent() {
    log.Printf("%s: %v", name, r.ActiveContent())
}
```

`Report.Counts` (raw) and `Report.StreamCounts` (inside inflated streams)
hold every keyword in `gopdfid.Keywords`; `gopdfid.ActiveKeywords` lists the
ones that trigger the verdict.

## Streams

PDF 1.5+ writers pack dictionaries into Flate-compressed object streams, so
a raw scan can miss an `/OpenAction` entirely. Every stream is inflated
(capped at 32 MiB each) and scanned again; those hits are reported
separately as `(N in streams)` in the text output and `stream_counts` in
JSON, and count towards the verdict. `Report.Counts` stays the raw figure
pdfid would give.

## Limits

Only Flate streams are inflated; a stream under another filter (LZW, ASCII85,
or a Flate stream with predictors) is scanned only in its compressed form.
Encrypted files (`/Encrypt` non-zero) keep their strings and streams
opaque, though names in dictionaries remain visible.

## Links

<!-- auto:links -->
| | |
|---|---|
| Documentation | https://gopdfid.docs.bytestone.uk/ |
| Source | https://git.bytestone.uk/hum3/gopdfid |
| Mirror (GitHub) | https://github.com/drummonds/gopdfid |
<!-- /auto:links -->

## Acknowledgements

The keyword list and triage approach are Didier Stevens' pdfid; this is an
independent Go implementation.
