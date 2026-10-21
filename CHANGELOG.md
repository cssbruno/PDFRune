# Changelog

## Unreleased

- `importpdf` reads cross-reference streams (including hybrid `XRefStm`
  files), object streams, and PNG-predicted container streams by normalizing
  them into a classic-xref file before parsing.
- `importpdf` decrypts the standard security handler (RC4 40/128, AES-128,
  AES-256 R5/R6). Files restricted only by permissions open with no password;
  others take `ImportOptions.Password` and report `ErrPasswordRequired` or
  `ErrIncorrectPassword`. `pdfcdr.Options.Password` forwards it.
- `pdfcdr` accepts an object referenced both as a resource-name map and as an
  ordinary value when it sanitizes identically in both roles (for example a
  shared indexed color space), inlines a direct-valued indirect `/Filter` or
  `/DecodeParms`, and repairs a stream whose `endstream` lacks the preceding
  end-of-line marker.
- `pdfcdr` keeps `/JBIG2Globals` references in image `/DecodeParms` (scanned
  documents), keeps the page `/Rotate` (inherited values included), and
  reconstructs the crop box clipped to the media box, so pages look as readers
  show them. Page boxes with swapped corners are normalized.
- `importpdf` accepts a stream object whose `endobj` is missing when the next
  token starts another object or cross-reference section (pypdf incremental
  updates), and opens a file that needs no password even when one is supplied.
- `importpdf` reads a file whose `%PDF-` header follows other bytes within the
  first 1024 (a UTF-8 BOM or a web preamble) from that header when it cannot be
  read as given.

- Extracted bounded PDF signing, verification, parsing, inspection, import
  modeling, and CDR from PaperRune into an independent module.
