# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/).

## [Unreleased]

### Added
- Flate streams are inflated and rescanned; hits reported as `StreamCounts` / `(N in streams)`.
- Raw byte scan counting the pdfid keyword set, with `#xx` name escapes decoded.
- `gopdfid` CLI with text and `-json` output; exit status 1 on active content.
- Library API: `Scan`, `ScanBytes`, `Report.HasActiveContent`, `Report.ActiveContent`.
