# Architecture

PDFRune owns operations whose input is an existing PDF. It never owns document
authoring, layout, or initial PDF generation.

`importpdf` is the bounded classic-xref parser. `inspect` and `pdfcdr` consume
that parser. `characterize` and `pdfverify` own post-generation evidence.
`sign` owns incremental PDF signatures and CMS verification and is independent
of the parser packages.

Applications may depend on PDFRune and a generator such as PaperRune. PDFRune
and PaperRune must not depend on each other.
