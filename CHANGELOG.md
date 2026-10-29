# Changelog

## Unreleased

- `inspect.Text` decodes shown strings through their fonts: `/ToUnicode` CMaps
  (1–4 byte codes, bfchar/bfrange, surrogate pairs, ligatures), Type0
  Identity-H/V (codes without a mapping produce no text), and simple-font
  encodings (WinAnsi, MacRoman, Standard, Symbol, `/Differences` through the
  Adobe Glyph List). Text drawn by Form XObjects is included, bounded in depth
  and by the shared decoded-byte budget. Text from Chrome, LibreOffice,
  Ghostscript and pypdf output was unreadable before.
- `inspect.Text` separates words, lines, and pages by layout (baseline
  changes, gaps from glyph widths, standard 14 Helvetica and Courier metrics
  when `/Widths` is absent, TJ adjustments of -200 or less), so adjacent values
  such as "13,5" and "14,0" no longer fuse.
- `inspect` sizes hexadecimal-string buffers by the string, not the rest of
  the stream (a 2 MB stream took 13 s); an inline image followed by an operand
  or using `/L` no longer fails the document, and a broken inline image ends
  only its content stream.
- `inspect.FirstPageSizePoints` applies the page `/UserUnit` (`/Rotate` is
  still not applied).
- `inspect` uses the Adobe Core 14 ASCII advances of Helvetica-Bold (and
  Arial Bold) and the four Times faces for fonts written without `/Widths`.
- `importpdf` measures a stream whose `/Length` is wrong only up to its own
  `endobj`; an `endstream` found past it belongs to a later object, and
  measuring to it copied the rest of the file once per broken stream. Such a
  stream whose data contains `endobj` is now reported as missing
  `endstream`.
- `importpdf` repair leaves out object numbers past `MaxXrefEntries`, which
  made a 133-byte file allocate about 1.9 GB.
- `importpdf` normalization leaves out object numbers past 1,600,000 and
  checks the rewritten xref table against the source limit before writing it;
  a 1 KB classic file naming object 300000000000 exhausted memory.
- `importpdf` page reads copy at most the source size (plus 1 MB) from
  referenced objects, so a chain of objects without `endobj` no longer copies
  the rest of the file once per object.
- `importpdf` sources opened with `OpenReaderAt` copy each object out of its
  read window before caching it, and stop caching once cached bodies reach
  the source size; tiny objects previously kept 64 KB–32 MB windows alive.
- `sign` rejects an RSASSA-PSS salt length longer than the signer key allows
  before calling `crypto/rsa`, whose length check a salt near MaxInt64 wrapped
  into a panic.
- `importpdf` rejects an object stream whose `/N` exceeds what its header can
  hold before allocating for it; reconstruction skips such streams, so 2000
  tiny ones allocated 3 GB.
- `importpdf` decodes a stream named several times in one page's `/Contents`
  array once; a stream that inflates to nothing, which the page content limit
  never charges, was inflated once per entry.
- `inspect` decodes each resource stream once per extraction, failures
  included, so a Form XObject drawn many times or a font selected many times
  is not inflated again (still charged to the budget per use).
- `inspect` ignores CMap destinations longer than 256 bytes and codespace
  ranges past the 256th; both were processed for every glyph shown.
- `sign` bounds the bytes read from indirect objects at four times the file
  size, so objects whose spans nest each other cannot make AcroForm scanning
  quadratic, and bounds the rows of all xref streams of a `/Prev` chain at
  four times `MaxXrefEntries`.
- `pdfcdr` no longer treats a dictionary as a resource-name map when its
  `/Type`, `/S`, `/Subtype` or `/FT` is a name, its `/Type` or `/S` is a
  reference, or its `/EF` or `/RF` is a dictionary. Such a dictionary under a
  resource category key kept every removed key, so an action with its `/JS`
  script, a widget annotation, or a file specification with its embedded
  file crossed the reconstruction (none was reachable from a trigger). An
  indirect `/S` or `/Type` there now refuses the document, as elsewhere.
- `pdfcdr` drops dictionaries of every ISO 32000-2 action type (GoTo, Hide,
  Named, SetOCGState, ImportData, Sound, Trans, GoTo3DView, GoToDp,
  RichMediaExecute and ECMAScript were kept) and removes `/Next`.
- `pdfcdr` writes indirect references as `N G R`; a signed `+7 0 R` was
  resolved to object 7 but copied unchanged, and renumbering then left it
  pointing at whichever output object received number 7.
- `pdfcdr` splices an indirect `/Length`, `/Filter` or `/DecodeParms` as its
  parsed value; a trailing comment in the referenced object (`57 % len`)
  swallowed the keys after it, and trailing tokens added keys. A key repeated
  in one dictionary is no longer inlined once per repetition (1000 copies of
  a 1 MB value were built before the duplicate was refused).
- `pdfcdr` sanitizes an object shared by many pages once per reconstruction
  and checks the context per object; 40 pages sharing one large font took
  forty times as long as one, which no byte limit charged.
- `pdfcdr` `MaxOutputBytes` no longer refuses an output that fits: the early
  check counted a fixed trailer allowance.
- `importpdf` pages share cached object bodies and each object's reference
  list instead of copying and parsing them per page, and a caller waiting
  for a shared `Source` stops when its context ends. New `Source.Root` and
  `Source.PageUserUnit`.
- `sign` verification requires the signer certificate to match the signed
  ESS signing-certificate(-v2) attribute when present (hash, and issuer and
  serial when given). The sid and certificate set are outside the signature,
  so they could be swapped for another trusted certificate over the same
  key, which Verify then reported as the signer. Duplicate ESS attributes
  are refused.
- `sign` trusts a chain only when each CA's extended key usage, if it has
  one, allows document signing (any, documentSigning, emailProtection,
  Microsoft or Adobe document signing); a TLS-only CA could issue a trusted
  signer because the chain was built with `ExtKeyUsageAny`.
- `inspect.FirstPageSizePoints` reads `/UserUnit` from the first page of the
  trailer's catalog; orphan catalogs changed the size, and thousands of decoy
  catalogs each walked a page tree. New `FirstPageSizePointsContext`.
- `inspect` builds a font written inside `/Resources` once per content
  stream instead of on every `Tf`. New `PagesTextContext` returns per-page
  text under one parse and one document decode budget.
- `characterize.Build` extracts a fixture's pages with one parse and one
  decode budget (it reopened the file per page with a fresh budget) and
  stops at `MaxJSONBytes` as text accumulates.
- `pdfverify.InspectTags` reads objects from the cross-reference data and
  `/MarkInfo` and the structure-tree root from the trailer's catalog; text
  inside a stream that looked like a structure tree made an untagged PDF
  pass. `Verify`'s `RequireTagged` uses the same check, checks the PDF page
  count first, reads PNG headers before decoding, decodes expected pages one
  at a time, and the Poppler pin must equal the reported version.
- `sign` writes non-ASCII signature dictionary text (`/Name`, `/Reason`,
  `/Location`, `/ContactInfo`, field `/T`) as UTF-16BE instead of `?`.
- `sign` verification and extraction read cross-reference streams, hybrid
  `XRefStm` files and object streams; a signed PDF 1.5+ file is no longer
  counted as unsigned. Signing still requires classic xref tables. New
  `CountSignatures` returns the parse error that `SignatureCount` reports as 0.
- `sign` verification accepts SignerInfos identified by subjectKeyIdentifier,
  RSASSA-PSS with matching hash and MGF1 hash, and signed attributes not in DER
  order; SHA-1 (including PSS defaults) stays rejected.
- `sign` accepts CR-only line ends and `trailer <<` on one line.
- `sign` output with the default `ETSI.CAdES.detached` SubFilter omits the CMS
  signing-time attribute and adds ESS signing-certificate-v2 (PAdES-B-B);
  `adbe.pkcs7.detached` and `CreateCMS` keep signing-time.
- `pdfcdr` gives a pattern's `/Shading` object, and any other value reached
  through a resource category key that does not have the shape of a
  resource-name map (a stream, or a dictionary holding a number, string or
  boolean), the full sanitizer policy. Such a shading previously kept external
  file keys, `/JS` and `/OpenAction`; a shading shared by the page `/Shading`
  map and a pattern (Ghostscript output) is now accepted.
- `pdfcdr` refuses PostScript form XObjects marked with `/Subtype2 /PS`, drops
  `/OPI` proxies instead of refusing the document, steps over removed entries
  without applying policy to their values, inlines an indirect `/Length`, and
  produces the same bytes on every run for objects referenced in both roles.
- `importpdf` repairs damaged files: a cross-reference section that does not
  lead to its objects is rebuilt from the object headers (object streams
  included), a single wrong xref offset is found by scanning, and a stream whose
  `/Length` misses `endstream` is measured. Unreferenced broken entries no
  longer fail normalization.
- `importpdf` resolves indirect `/Kids`, `/Contents` arrays, page boxes and
  `/Rotate`; uses the crop box as the default for the bleed, trim and art boxes
  and inherits only the media and crop boxes; takes the V4 key length from the
  crypt filter; ignores the `/Prev` of a hybrid file's hidden xref stream; and
  accepts trailing spaces in xref subsection headers.
- `importpdf` no longer loops forever on an unterminated object read through
  `OpenReaderAt`, and no longer copies the raw bytes of a nested value once per
  enclosing level (a 4 MB file allocated almost 500 MB).

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
