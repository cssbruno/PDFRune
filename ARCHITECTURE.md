# Architecture

PDFRune owns operations whose input is an existing PDF. It never owns document
authoring, layout, or initial PDF generation.

`importpdf` is the bounded classic-xref parser. A source that uses
cross-reference streams, object streams, or standard-handler encryption is
first rewritten by a bounded normalization pass into an equivalent classic,
unencrypted PDF, which the same classic parser then reads. A file whose
cross-reference information cannot be used (offsets shifted by converted line
endings, a missing `startxref`) is rebuilt by a bounded repair pass from the
object headers found in the file, as conforming readers do; it only runs on a
file with a `%PDF-` header and keeps the original error when it fails. A stream
whose `/Length` does not reach `endstream` is measured instead, and its body is
rewritten with the measured direct length. `inspect` and `pdfcdr` consume
that parser. `characterize` and `pdfverify` own post-generation evidence.
`sign` owns incremental PDF signatures and CMS verification and is independent
of the parser packages.

Applications may depend on PDFRune and a generator such as PaperRune. PDFRune
and PaperRune must not depend on each other.
