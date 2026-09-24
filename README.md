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

`Report.Counts` holds every keyword in `gopdfid.Keywords`;
`gopdfid.ActiveKeywords` lists the ones that trigger the verdict.

## Limits

Only raw bytes are scanned. Names inside compressed object streams
(`/ObjStm`, PDF 1.5+) are invisible until the stream is inflated; a non-zero
`/ObjStm` count with otherwise clean results is itself worth noting. Stream
inflation is on the roadmap.

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
