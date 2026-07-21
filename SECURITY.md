# Security Policy

## Supported versions

Security fixes are made on the current `main` branch and released from the
latest version line. Older pre-1.0 releases are not maintained in parallel.

## Reporting a vulnerability

Use the repository's private GitHub security-advisory reporting flow. Please do
not open a public issue for a vulnerability before a coordinated fix is
available. Include a minimal reproducer, affected API, impact, and any relevant
resource or platform assumptions. Do not include real credentials, private
keys, or sensitive documents.

## PDF trust boundaries

Treat imported PDFs as hostile. Use bounded `importpdf` options and `pdfcdr`
before retaining or opening uploaded documents. `pdfcdr` reconstructs the
supported classic-xref subset; it is not a rasterizer and does not protect a
downstream reader from vulnerabilities in image, font, or rendering decoders.

Applications remain responsible for request-body limits, deadlines, process
isolation appropriate to their threat model, and keeping PDF readers and the
Go toolchain patched. Do not expose these parsers directly to unbounded public
requests.

## Signing credentials

Callers must never place private keys, key passwords, or secret-manager
credentials inside the PDF being signed. Server applications should inject a
managed `crypto.Signer`; this supports operating-system key stores, HSMs,
PKCS#11 modules, and cloud KMS adapters without exporting key bytes.

`sign.LoadPEMCredentials` accepts explicit PEM certificate and key paths for
mounted-secret and operator workflows. Files are size-bounded and the public
key is matched against the leaf certificate before signing. Credential paths
must be selected by the trusted process, never by an untrusted request.
