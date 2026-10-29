// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

// This file signs and verifies PDF CMS signatures.
package sign

import (
	"bytes"
	"crypto"
	"crypto/ecdsa"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"errors"
	"fmt"
	"math/big"
	"time"
)

var (
	oidData            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
	oidSignedData      = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidContentType     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidMessageDigest   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidSigningTime     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidSigningCertV2   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 47}
	oidSigningCert     = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 16, 2, 12}
	oidSHA1            = asn1.ObjectIdentifier{1, 3, 14, 3, 2, 26}
	oidSHA256          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 1}
	oidSHA384          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 2}
	oidSHA512          = asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 2, 3}
	oidRSAEncryption   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 1}
	oidSHA256WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 11}
	oidSHA384WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 12}
	oidSHA512WithRSA   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 13}
	oidRSASSAPSS       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1            = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
	oidECDSAWithSHA256 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 2}
	oidECDSAWithSHA384 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 3}
	oidECDSAWithSHA512 = asn1.ObjectIdentifier{1, 2, 840, 10045, 4, 3, 4}
	oidDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 5, 5, 7, 3, 36}
)

const maxCMSPackageBytes = 16 * 1024 * 1024

// ErrTrustStoreRequired is returned by trusted verification APIs when no root
// certificate pool is supplied.
var ErrTrustStoreRequired = errors.New("pdfsigning: trust store is required")

// CMSOptions configures CMS SignedData creation.
type CMSOptions struct {
	// Signer signs the CMS signed attributes.
	Signer crypto.Signer
	// Certificate is the signing certificate and must match Signer.
	Certificate *x509.Certificate
	// CertificateChain contains optional intermediate certificates to include.
	CertificateChain []*x509.Certificate
	// DigestAlgorithm selects the message digest. A zero value uses SHA-256.
	DigestAlgorithm crypto.Hash
	// Detached omits the signed content from the CMS payload when true.
	Detached bool
	// SigningTime sets the CMS signingTime attribute. A zero value uses now.
	SigningTime time.Time
}

// CMSVerifyResult contains the relevant result of a CMS verification.
type CMSVerifyResult struct {
	// Certificates contains the certificates embedded in the CMS payload.
	Certificates []*x509.Certificate
	// Signer is the certificate that produced the verified signature.
	Signer *x509.Certificate
	// Digest is the digest algorithm used by the signer.
	Digest crypto.Hash
	// Detached reports whether the CMS payload is detached from its content.
	Detached bool
	// Content contains the verified content.
	Content []byte
	// SigningTime is the optional signingTime attribute from the CMS payload.
	SigningTime *time.Time
	// ValidSignature reports whether the CMS signature was cryptographically valid.
	ValidSignature bool
	// TrustedSigner reports whether the signer chained to the supplied truststore.
	TrustedSigner bool
}

// CreateCMS creates CMS SignedData using this package's own DER encoder.
func CreateCMS(content []byte, options CMSOptions) ([]byte, error) {
	digest, signingTime, err := prepareCMSOptions(options)
	if err != nil {
		return nil, err
	}
	contentDigest := hashBytes(digest, content)
	signedAttrs, err := signedAttributes(contentDigest, signingTime)
	if err != nil {
		return nil, err
	}
	return createCMSWithDigest(content, signedAttrs, digest, options)
}

func createDetachedCMSWithPreparedDigest(contentDigest []byte, options preparedOptions) ([]byte, error) {
	if len(contentDigest) != options.DigestAlgorithm.Size() {
		return nil, fmt.Errorf("pdfsigning: content digest has %d bytes, want %d", len(contentDigest), options.DigestAlgorithm.Size())
	}
	cmsOptions := CMSOptions{
		Signer:           options.Signer,
		Certificate:      options.Certificate,
		CertificateChain: options.CertificateChain,
		DigestAlgorithm:  options.DigestAlgorithm,
		Detached:         true,
		SigningTime:      options.SigningTime,
	}
	// PAdES baseline (ETSI EN 319 142-1) forbids the CMS signing-time
	// attribute, takes the time from /M instead, and requires the ESS
	// signing-certificate-v2 attribute binding the signer certificate.
	var signedAttrs []byte
	var err error
	if options.SubFilter == SubFilterETSI_CAdESDetached {
		signedAttrs, err = cadesSignedAttributes(contentDigest, options.Certificate)
	} else {
		signedAttrs, err = signedAttributes(contentDigest, options.SigningTime)
	}
	if err != nil {
		return nil, err
	}
	return createCMSWithDigest(nil, signedAttrs, options.DigestAlgorithm, cmsOptions)
}

func prepareCMSOptions(options CMSOptions) (crypto.Hash, time.Time, error) {
	if options.Signer == nil {
		return 0, time.Time{}, ErrMissingSigner
	}
	if options.Certificate == nil {
		return 0, time.Time{}, ErrMissingCertificate
	}
	if !publicKeysEqual(options.Signer.Public(), options.Certificate.PublicKey) {
		return 0, time.Time{}, errors.New("pdfsigning: signer public key does not match certificate")
	}
	digest, err := normalizeDigest(options.DigestAlgorithm)
	if err != nil {
		return 0, time.Time{}, err
	}
	signingTime := options.SigningTime
	if signingTime.IsZero() {
		signingTime = time.Now().UTC()
	}
	return digest, signingTime, nil
}

func createCMSWithDigest(content, signedAttrs []byte, digest crypto.Hash, options CMSOptions) (out []byte, err error) {
	defer func() {
		if recovered := recover(); recovered != nil {
			out = nil
			err = fmt.Errorf("pdfsigning: DER/CMS encoding failed: %v", recovered)
		}
	}()
	signatureDigest := hashBytes(digest, signedAttrs)
	signature, err := options.Signer.Sign(rand.Reader, signatureDigest, digest)
	if err != nil {
		return nil, fmt.Errorf("sign CMS attributes: %w", err)
	}

	digestAlg := digestAlgorithmID(digest)
	signatureAlg, err := signatureAlgorithmID(options.Signer.Public(), digest)
	if err != nil {
		return nil, err
	}
	signedAttrValue, _, err := readDER(signedAttrs)
	if err != nil {
		return nil, err
	}
	signerInfo := derSequence(
		derInteger(1),
		derSequence(
			options.Certificate.RawIssuer,
			derInteger(options.Certificate.SerialNumber),
		),
		digestAlg,
		der(0xa0, signedAttrValue.Content),
		signatureAlg,
		derOctetString(signature),
	)

	certs := make([][]byte, 0, 1+len(options.CertificateChain))
	certs = append(certs, options.Certificate.Raw)
	for _, cert := range options.CertificateChain {
		if cert != nil {
			certs = append(certs, cert.Raw)
		}
	}

	encapContentInfo := derSequence(derOID(oidData))
	if !options.Detached {
		encapContentInfo = derSequence(
			derOID(oidData),
			der(0xa0, derOctetString(content)),
		)
	}
	signedData := derSequence(
		derInteger(1),
		derSet(digestAlg),
		encapContentInfo,
		der(0xa0, derValueContent(derSet(certs...))),
		derSet(signerInfo),
	)
	return derSequence(derOID(oidSignedData), der(0xa0, signedData)), nil
}

func derValueContent(encoded []byte) []byte {
	value, rest, err := readDER(encoded)
	if err != nil || len(rest) != 0 {
		panic("invalid DER value")
	}
	return value.Content
}

// VerifyCMS verifies attached CMS SignedData containing exactly one signer.
func VerifyCMS(signature []byte, truststore *x509.CertPool) (*CMSVerifyResult, error) {
	if truststore == nil {
		return nil, ErrTrustStoreRequired
	}
	return verifyCMS(signature, nil, truststore, false)
}

// VerifyCMSIntegrity verifies one signer's CMS cryptographic integrity without
// establishing signer trust. Multi-signer packages are rejected. Callers must
// not use this as an authorization decision.
func VerifyCMSIntegrity(signature []byte) (*CMSVerifyResult, error) {
	return verifyCMS(signature, nil, nil, false)
}

// VerifyDetachedCMS verifies detached CMS SignedData containing exactly one
// signer against content.
func VerifyDetachedCMS(signature, content []byte, truststore *x509.CertPool) (*CMSVerifyResult, error) {
	if truststore == nil {
		return nil, ErrTrustStoreRequired
	}
	return verifyCMS(signature, content, truststore, true)
}

// VerifyDetachedCMSIntegrity verifies detached CMS cryptographic integrity for
// exactly one signer without establishing signer trust.
func VerifyDetachedCMSIntegrity(signature, content []byte) (*CMSVerifyResult, error) {
	return verifyCMS(signature, content, nil, true)
}

func verifyCMS(signature []byte, detachedContent []byte, truststore *x509.CertPool, requireDetached bool) (*CMSVerifyResult, error) {
	if len(signature) > maxCMSPackageBytes {
		return nil, errors.New("pdfsigning: CMS package exceeds maximum size")
	}
	outer, rest, err := readDER(signature)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("pdfsigning: trailing bytes after CMS package")
	}
	if err := expectTag(outer, 0x30, "CMS ContentInfo"); err != nil {
		return nil, err
	}
	outerChildren, err := readDERChildren(outer.Content)
	if err != nil {
		return nil, err
	}
	if len(outerChildren) != 2 {
		return nil, errors.New("pdfsigning: invalid CMS ContentInfo")
	}
	contentType, err := decodeOID(outerChildren[0])
	if err != nil {
		return nil, err
	}
	if !contentType.Equal(oidSignedData) {
		return nil, errors.New("pdfsigning: CMS content is not SignedData")
	}
	if err := expectTag(outerChildren[1], 0xa0, "CMS SignedData wrapper"); err != nil {
		return nil, err
	}
	signedDataValue, rest, err := readDER(outerChildren[1].Content)
	if err != nil {
		return nil, err
	}
	if len(rest) != 0 {
		return nil, errors.New("pdfsigning: invalid SignedData wrapper")
	}
	return verifySignedData(signedDataValue, detachedContent, truststore, requireDetached)
}

func verifySignedData(signedDataValue derValue, detachedContent []byte, truststore *x509.CertPool, requireDetached bool) (*CMSVerifyResult, error) {
	if err := expectTag(signedDataValue, 0x30, "SignedData"); err != nil {
		return nil, err
	}
	children, err := readDERChildren(signedDataValue.Content)
	if err != nil {
		return nil, err
	}
	if len(children) < 5 {
		return nil, errors.New("pdfsigning: incomplete SignedData")
	}

	encapChildren, err := readDERChildren(children[2].Content)
	if err != nil {
		return nil, err
	}
	if len(encapChildren) == 0 {
		return nil, errors.New("pdfsigning: missing encapsulated content info")
	}
	contentOID, err := decodeOID(encapChildren[0])
	if err != nil {
		return nil, err
	}
	if !contentOID.Equal(oidData) {
		return nil, errors.New("pdfsigning: unsupported CMS content type")
	}

	content := detachedContent
	detached := true
	if len(encapChildren) > 1 {
		if requireDetached {
			return nil, errors.New("pdfsigning: detached CMS verification requires detached content")
		}
		embedded, rest, err := readDER(encapChildren[1].Content)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("pdfsigning: invalid embedded CMS content")
		}
		if err := expectTag(embedded, 0x04, "embedded CMS content"); err != nil {
			return nil, err
		}
		content = embedded.Content
		detached = false
	}
	if content == nil {
		return nil, errors.New("pdfsigning: detached content is required")
	}

	certificates, signerInfos, err := parseCertificatesAndSigners(children[3:])
	if err != nil {
		return nil, err
	}
	if len(certificates) == 0 {
		return nil, errors.New("pdfsigning: CMS package has no certificates")
	}
	if len(signerInfos) == 0 {
		return nil, errors.New("pdfsigning: CMS package has no signer info")
	}
	if len(signerInfos) != 1 {
		return nil, fmt.Errorf("pdfsigning: CMS verification requires exactly one signer info, got %d", len(signerInfos))
	}

	result, err := verifySignerInfo(signerInfos[0], certificates, content, truststore)
	if err != nil {
		return nil, err
	}
	result.Detached = detached
	result.Content = append([]byte(nil), content...)
	return result, nil
}

func parseCertificatesAndSigners(values []derValue) ([]*x509.Certificate, []derValue, error) {
	var certs []*x509.Certificate
	var signers []derValue
	for _, value := range values {
		switch value.Tag {
		case 0xa0:
			rawCerts, err := readDERChildren(value.Content)
			if err != nil {
				return nil, nil, err
			}
			for _, raw := range rawCerts {
				cert, err := x509.ParseCertificate(raw.Full)
				if err != nil {
					return nil, nil, fmt.Errorf("parse CMS certificate: %w", err)
				}
				certs = append(certs, cert)
			}
		case 0x31:
			rawSigners, err := readDERChildren(value.Content)
			if err != nil {
				return nil, nil, err
			}
			signers = append(signers, rawSigners...)
		}
	}
	return certs, signers, nil
}

func verifySignerInfo(signerInfo derValue, certificates []*x509.Certificate, content []byte, truststore *x509.CertPool) (*CMSVerifyResult, error) {
	if err := expectTag(signerInfo, 0x30, "SignerInfo"); err != nil {
		return nil, err
	}
	children, err := readDERChildren(signerInfo.Content)
	if err != nil {
		return nil, err
	}
	if len(children) < 6 {
		return nil, errors.New("pdfsigning: incomplete SignerInfo")
	}
	signer, err := findSignerCertificate(certificates, children[1])
	if err != nil {
		return nil, err
	}
	if signer == nil {
		return nil, errors.New("pdfsigning: signer certificate not found")
	}
	digest, err := decodeDigestAlgorithm(children[2])
	if err != nil {
		return nil, err
	}
	if children[3].Tag != 0xa0 {
		return nil, errors.New("pdfsigning: signed attributes are required")
	}
	signedAttrsDER := der(0x31, children[3].Content)
	messageDigest, signingTime, signingCert, err := decodeSignedAttributesWithSigningCertificate(signedAttrsDER)
	if err != nil {
		return nil, err
	}
	// The sid and certificate set are outside the signature; the ESS
	// signing-certificate attribute is inside it, so it alone binds the signer.
	if err := signingCert.matches(signer); err != nil {
		return nil, err
	}
	expectedDigest := hashBytes(digest, content)
	if !bytes.Equal(messageDigest, expectedDigest) {
		return nil, errors.New("pdfsigning: CMS message digest mismatch")
	}

	pss, err := verifySignatureAlgorithm(children[4], signer.PublicKey, digest)
	if err != nil {
		return nil, err
	}
	signature := children[5]
	if err := expectTag(signature, 0x04, "CMS signature"); err != nil {
		return nil, err
	}
	signedAttrsDigest := hashBytes(digest, signedAttrsDER)
	if err := verifyPublicKeySignature(signer.PublicKey, digest, signedAttrsDigest, signature.Content, pss); err != nil {
		return nil, err
	}

	trusted := false
	if truststore != nil {
		if err := validateDocumentSignerCertificate(signer); err != nil {
			return nil, err
		}
		intermediates := x509.NewCertPool()
		for _, cert := range certificates {
			if !cert.Equal(signer) {
				intermediates.AddCert(cert)
			}
		}
		// ExtKeyUsageAny is needed because crypto/x509 cannot match the
		// documentSigning OID, but it also skips the check that each CA's EKU
		// allows the leaf's use, so that check is made on the chains here.
		chains, err := signer.Verify(x509.VerifyOptions{
			Roots:         truststore,
			Intermediates: intermediates,
			KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		})
		if err != nil {
			return nil, fmt.Errorf("verify signer certificate: %w", err)
		}
		if !anyChainAllowsDocumentSigning(chains) {
			return nil, errors.New("verify signer certificate: an issuing CA's extended key usage does not allow document signing")
		}
		trusted = true
	}

	return &CMSVerifyResult{
		Certificates:   certificates,
		Signer:         signer,
		Digest:         digest,
		SigningTime:    signingTime,
		ValidSignature: true,
		TrustedSigner:  trusted,
	}, nil
}

func signedAttributes(messageDigest []byte, signingTime time.Time) ([]byte, error) {
	timeDER, err := asn1.Marshal(signingTime.UTC())
	if err != nil {
		return nil, err
	}
	return derSet(
		derSequence(derOID(oidContentType), derSet(derOID(oidData))),
		derSequence(derOID(oidMessageDigest), derSet(derOctetString(messageDigest))),
		derSequence(derOID(oidSigningTime), derSet(timeDER)),
	), nil
}

// cadesSignedAttributes builds PAdES-B-B signed attributes: contentType,
// messageDigest and an ESS signing-certificate-v2 (RFC 5035) holding the
// SHA-256 hash and issuer/serial of cert, without signing-time.
func cadesSignedAttributes(messageDigest []byte, cert *x509.Certificate) ([]byte, error) {
	certHash := hashBytes(crypto.SHA256, cert.Raw)
	issuerSerial := derSequence(
		derSequence(der(0xa4, cert.RawIssuer)),
		derInteger(cert.SerialNumber),
	)
	// hashAlgorithm is omitted because SHA-256 is its DER default.
	essCertID := derSequence(derOctetString(certHash), issuerSerial)
	signingCertificate := derSequence(derSequence(essCertID))
	return derSet(
		derSequence(derOID(oidContentType), derSet(derOID(oidData))),
		derSequence(derOID(oidMessageDigest), derSet(derOctetString(messageDigest))),
		derSequence(derOID(oidSigningCertV2), derSet(signingCertificate)),
	), nil
}

func decodeSignedAttributes(attrsDER []byte) ([]byte, *time.Time, error) {
	messageDigest, signingTime, _, err := decodeSignedAttributesWithSigningCertificate(attrsDER)
	return messageDigest, signingTime, err
}

// essSigningCertificate is the first ESSCertID of a signed ESS
// signing-certificate (v1, SHA-1) or signing-certificate-v2 attribute.
type essSigningCertificate struct {
	present      bool
	hash         crypto.Hash
	certHash     []byte
	issuerSerial *derValue
}

func (e essSigningCertificate) matches(cert *x509.Certificate) error {
	if !e.present {
		return nil
	}
	if !bytes.Equal(e.certHash, hashBytes(e.hash, cert.Raw)) {
		return errors.New("pdfsigning: signer certificate does not match the signed ESS signing-certificate attribute")
	}
	if e.issuerSerial == nil {
		return nil
	}
	parts, err := readDERChildren(e.issuerSerial.Content)
	if err != nil || len(parts) != 2 || parts[0].Tag != 0x30 {
		return errors.New("pdfsigning: invalid ESS issuerSerial")
	}
	var serial *big.Int
	if rest, err := asn1.Unmarshal(parts[1].Full, &serial); err != nil || len(rest) != 0 {
		return errors.New("pdfsigning: invalid ESS issuerSerial")
	}
	names, err := readDERChildren(parts[0].Content)
	if err != nil {
		return errors.New("pdfsigning: invalid ESS issuerSerial")
	}
	issuerMatches := false
	for _, name := range names {
		if name.Tag == 0xa4 && bytes.Equal(name.Content, cert.RawIssuer) {
			issuerMatches = true
		}
	}
	if !issuerMatches || serial.Cmp(cert.SerialNumber) != 0 {
		return errors.New("pdfsigning: signer certificate does not match the signed ESS issuerSerial")
	}
	return nil
}

// decodeESSSigningCertificate reads the first ESSCertID(v2) of value. v2's
// hashAlgorithm defaults to SHA-256; v1 always uses SHA-1.
func decodeESSSigningCertificate(value derValue, v2 bool) (essSigningCertificate, error) {
	invalid := errors.New("pdfsigning: invalid ESS signing-certificate attribute")
	if value.Tag != 0x30 {
		return essSigningCertificate{}, invalid
	}
	fields, err := readDERChildren(value.Content)
	if err != nil || len(fields) == 0 || fields[0].Tag != 0x30 {
		return essSigningCertificate{}, invalid
	}
	certIDs, err := readDERChildren(fields[0].Content)
	if err != nil || len(certIDs) == 0 || certIDs[0].Tag != 0x30 {
		return essSigningCertificate{}, invalid
	}
	parts, err := readDERChildren(certIDs[0].Content)
	if err != nil || len(parts) == 0 {
		return essSigningCertificate{}, invalid
	}
	result := essSigningCertificate{present: true, hash: crypto.SHA1}
	if v2 {
		result.hash = crypto.SHA256
		if parts[0].Tag == 0x30 {
			if result.hash, err = decodeDigestAlgorithm(parts[0]); err != nil {
				return essSigningCertificate{}, err
			}
			parts = parts[1:]
		}
	}
	if len(parts) == 0 || parts[0].Tag != 0x04 || len(parts) > 2 {
		return essSigningCertificate{}, invalid
	}
	result.certHash = parts[0].Content
	if len(parts) == 2 {
		if parts[1].Tag != 0x30 {
			return essSigningCertificate{}, invalid
		}
		result.issuerSerial = &parts[1]
	}
	return result, nil
}

func decodeSignedAttributesWithSigningCertificate(attrsDER []byte) ([]byte, *time.Time, essSigningCertificate, error) {
	var signingCert essSigningCertificate
	attrs, rest, err := readDER(attrsDER)
	if err != nil {
		return nil, nil, essSigningCertificate{}, err
	}
	if len(rest) != 0 {
		return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: invalid signed attributes")
	}
	if err := expectTag(attrs, 0x31, "signed attributes"); err != nil {
		return nil, nil, essSigningCertificate{}, err
	}
	children, err := readDERChildren(attrs.Content)
	if err != nil {
		return nil, nil, essSigningCertificate{}, err
	}
	var messageDigest []byte
	contentTypeSeen := false
	messageDigestSeen := false
	var signingTime *time.Time
	// The signature covers these exact bytes, so a non-canonical SET OF order
	// is accepted here; CMS produced by this package is always DER sorted.
	for _, attr := range children {
		attrChildren, err := readDERChildren(attr.Content)
		if err != nil {
			return nil, nil, essSigningCertificate{}, err
		}
		if len(attrChildren) != 2 {
			return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: invalid signed attribute")
		}
		oid, err := decodeOID(attrChildren[0])
		if err != nil {
			return nil, nil, essSigningCertificate{}, err
		}
		values, err := readDERChildren(attrChildren[1].Content)
		if err != nil {
			return nil, nil, essSigningCertificate{}, err
		}
		if len(values) == 0 {
			continue
		}
		switch {
		case oid.Equal(oidContentType):
			if contentTypeSeen {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: duplicate contentType attribute")
			}
			if len(values) != 1 {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: invalid contentType attribute")
			}
			contentType, err := decodeOID(values[0])
			if err != nil {
				return nil, nil, essSigningCertificate{}, err
			}
			if !contentType.Equal(oidData) {
				return nil, nil, essSigningCertificate{}, fmt.Errorf("pdfsigning: unsupported contentType attribute %v", contentType)
			}
			contentTypeSeen = true
		case oid.Equal(oidMessageDigest):
			if messageDigestSeen {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: duplicate messageDigest attribute")
			}
			if len(values) != 1 {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: invalid messageDigest attribute")
			}
			if err := expectTag(values[0], 0x04, "messageDigest attribute"); err != nil {
				return nil, nil, essSigningCertificate{}, err
			}
			messageDigest = append([]byte(nil), values[0].Content...)
			messageDigestSeen = true
		case oid.Equal(oidSigningTime):
			if len(values) != 1 {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: invalid signingTime attribute")
			}
			var t time.Time
			if _, err := asn1.Unmarshal(values[0].Full, &t); err != nil {
				return nil, nil, essSigningCertificate{}, err
			}
			signingTime = &t
		case oid.Equal(oidSigningCertV2) || oid.Equal(oidSigningCert):
			if signingCert.present {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: duplicate ESS signing-certificate attribute")
			}
			if len(values) != 1 {
				return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: invalid ESS signing-certificate attribute")
			}
			if signingCert, err = decodeESSSigningCertificate(values[0], oid.Equal(oidSigningCertV2)); err != nil {
				return nil, nil, essSigningCertificate{}, err
			}
		}
	}
	if !contentTypeSeen {
		return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: missing contentType attribute")
	}
	if !messageDigestSeen || len(messageDigest) == 0 {
		return nil, nil, essSigningCertificate{}, errors.New("pdfsigning: missing messageDigest attribute")
	}
	return messageDigest, signingTime, signingCert, nil
}

func digestAlgorithmID(digest crypto.Hash) []byte {
	return derSequence(derOID(digestOID(digest)))
}

func signatureAlgorithmID(publicKey any, digest crypto.Hash) ([]byte, error) {
	switch publicKey.(type) {
	case *rsa.PublicKey:
		switch digest {
		case crypto.SHA256:
			return derSequence(derOID(oidSHA256WithRSA), derNull()), nil
		case crypto.SHA384:
			return derSequence(derOID(oidSHA384WithRSA), derNull()), nil
		case crypto.SHA512:
			return derSequence(derOID(oidSHA512WithRSA), derNull()), nil
		}
	case *ecdsa.PublicKey:
		switch digest {
		case crypto.SHA256:
			return derSequence(derOID(oidECDSAWithSHA256)), nil
		case crypto.SHA384:
			return derSequence(derOID(oidECDSAWithSHA384)), nil
		case crypto.SHA512:
			return derSequence(derOID(oidECDSAWithSHA512)), nil
		}
	}
	return nil, fmt.Errorf("pdfsigning: unsupported signer public key %T", publicKey)
}

// verifySignatureAlgorithm checks the SignerInfo signatureAlgorithm against
// the signer key and digest. It returns non-nil options for RSASSA-PSS.
func verifySignatureAlgorithm(value derValue, publicKey any, digest crypto.Hash) (*rsa.PSSOptions, error) {
	children, err := readDERChildren(value.Content)
	if err != nil {
		return nil, err
	}
	if len(children) == 0 || len(children) > 2 {
		return nil, errors.New("pdfsigning: invalid signature algorithm")
	}
	oid, err := decodeOID(children[0])
	if err != nil {
		return nil, err
	}
	if _, isRSA := publicKey.(*rsa.PublicKey); isRSA && oid.Equal(oidRSASSAPSS) {
		if len(children) != 2 {
			// Absent parameters mean SHA-1 (RFC 4055), which is rejected.
			return nil, errors.New("pdfsigning: RSASSA-PSS parameters are required")
		}
		return decodePSSParameters(children[1], digest)
	}
	if len(children) > 1 && !isDERNull(children[1]) {
		return nil, errors.New("pdfsigning: unsupported signature algorithm parameters")
	}
	switch publicKey.(type) {
	case *rsa.PublicKey:
		if oid.Equal(oidRSAEncryption) {
			return nil, nil
		}
		switch digest {
		case crypto.SHA256:
			if oid.Equal(oidSHA256WithRSA) {
				return nil, nil
			}
		case crypto.SHA384:
			if oid.Equal(oidSHA384WithRSA) {
				return nil, nil
			}
		case crypto.SHA512:
			if oid.Equal(oidSHA512WithRSA) {
				return nil, nil
			}
		}
	case *ecdsa.PublicKey:
		switch digest {
		case crypto.SHA256:
			if oid.Equal(oidECDSAWithSHA256) {
				return nil, nil
			}
		case crypto.SHA384:
			if oid.Equal(oidECDSAWithSHA384) {
				return nil, nil
			}
		case crypto.SHA512:
			if oid.Equal(oidECDSAWithSHA512) {
				return nil, nil
			}
		}
	}
	return nil, errors.New("pdfsigning: signature algorithm does not match signer key and digest")
}

// decodePSSParameters decodes RSASSA-PSS-params (RFC 4055 3.1). The hash and
// the MGF1 hash must both equal digest; omitted fields take their SHA-1
// defaults and are therefore rejected, except saltLength (default 20).
func decodePSSParameters(value derValue, digest crypto.Hash) (*rsa.PSSOptions, error) {
	if err := expectTag(value, 0x30, "RSASSA-PSS parameters"); err != nil {
		return nil, err
	}
	fields, err := readDERChildren(value.Content)
	if err != nil {
		return nil, err
	}
	var hashSeen, mgfSeen bool
	saltLength := 20
	nextTag := byte(0xa0)
	for _, field := range fields {
		if field.Tag < nextTag || field.Tag > 0xa3 {
			return nil, errors.New("pdfsigning: invalid RSASSA-PSS parameters")
		}
		nextTag = field.Tag + 1
		inner, rest, err := readDER(field.Content)
		if err != nil {
			return nil, err
		}
		if len(rest) != 0 {
			return nil, errors.New("pdfsigning: invalid RSASSA-PSS parameters")
		}
		switch field.Tag {
		case 0xa0:
			hash, err := decodeDigestAlgorithm(inner)
			if err != nil {
				return nil, err
			}
			if hash != digest {
				return nil, errors.New("pdfsigning: RSASSA-PSS hash does not match digest algorithm")
			}
			hashSeen = true
		case 0xa1:
			mgf, err := readDERChildren(inner.Content)
			if err != nil {
				return nil, err
			}
			if inner.Tag != 0x30 || len(mgf) != 2 {
				return nil, errors.New("pdfsigning: invalid RSASSA-PSS mask generation function")
			}
			mgfOID, err := decodeOID(mgf[0])
			if err != nil {
				return nil, err
			}
			if !mgfOID.Equal(oidMGF1) {
				return nil, fmt.Errorf("pdfsigning: unsupported RSASSA-PSS mask generation function %v", mgfOID)
			}
			mgfHash, err := decodeDigestAlgorithm(mgf[1])
			if err != nil {
				return nil, err
			}
			if mgfHash != digest {
				return nil, errors.New("pdfsigning: RSASSA-PSS MGF1 hash does not match digest algorithm")
			}
			mgfSeen = true
		case 0xa2:
			var salt int
			// rsa.PSSOptions treats 0 as "auto-detect"; the signature is still
			// verified under the signer key, only the salt length is not pinned.
			if rest, err := asn1.Unmarshal(inner.Full, &salt); err != nil || len(rest) != 0 || salt < 0 {
				return nil, errors.New("pdfsigning: invalid RSASSA-PSS salt length")
			}
			saltLength = salt
		case 0xa3:
			var trailer int
			if rest, err := asn1.Unmarshal(inner.Full, &trailer); err != nil || len(rest) != 0 || trailer != 1 {
				return nil, errors.New("pdfsigning: unsupported RSASSA-PSS trailer field")
			}
		}
	}
	if !hashSeen || !mgfSeen {
		return nil, errors.New("pdfsigning: RSASSA-PSS with SHA-1 defaults is not supported")
	}
	return &rsa.PSSOptions{SaltLength: saltLength, Hash: digest}, nil
}

func verifyPublicKeySignature(publicKey any, digest crypto.Hash, hashed, signature []byte, pss *rsa.PSSOptions) error {
	switch key := publicKey.(type) {
	case *rsa.PublicKey:
		if pss != nil {
			// The salt length comes from the CMS. crypto/rsa computes
			// emLen-hLen-sLen-2 without checking for overflow, so a salt near
			// MaxInt64 wraps that check and panics on a negative slice bound;
			// no valid signature has a salt longer than the encoding allows.
			if pss.SaltLength > (key.N.BitLen()+6)/8-digest.Size()-2 {
				return errors.New("pdfsigning: RSASSA-PSS salt length exceeds the key size")
			}
			return rsa.VerifyPSS(key, digest, hashed, signature, pss)
		}
		return rsa.VerifyPKCS1v15(key, digest, hashed, signature)
	case *ecdsa.PublicKey:
		if !ecdsa.VerifyASN1(key, hashed, signature) {
			return errors.New("pdfsigning: invalid ECDSA signature")
		}
		return nil
	default:
		return fmt.Errorf("pdfsigning: unsupported signer public key %T", publicKey)
	}
}

func hashBytes(digest crypto.Hash, input []byte) []byte {
	h := digest.New()
	_, _ = h.Write(input)
	return h.Sum(nil)
}

func digestOID(digest crypto.Hash) asn1.ObjectIdentifier {
	switch digest {
	case crypto.SHA1:
		return oidSHA1
	case crypto.SHA256:
		return oidSHA256
	case crypto.SHA384:
		return oidSHA384
	case crypto.SHA512:
		return oidSHA512
	default:
		panic("unsupported digest")
	}
}

func decodeOID(value derValue) (asn1.ObjectIdentifier, error) {
	var oid asn1.ObjectIdentifier
	if _, err := asn1.Unmarshal(value.Full, &oid); err != nil {
		return nil, err
	}
	return oid, nil
}

func decodeDigestAlgorithm(value derValue) (crypto.Hash, error) {
	children, err := readDERChildren(value.Content)
	if err != nil {
		return 0, err
	}
	if len(children) == 0 {
		return 0, errors.New("pdfsigning: invalid algorithm identifier")
	}
	if len(children) > 2 || (len(children) == 2 && !isDERNull(children[1])) {
		return 0, errors.New("pdfsigning: unsupported digest algorithm parameters")
	}
	oid, err := decodeOID(children[0])
	if err != nil {
		return 0, err
	}
	switch {
	case oid.Equal(oidSHA1):
		return 0, fmt.Errorf("pdfsigning: insecure digest OID %v", oid)
	case oid.Equal(oidSHA256):
		return crypto.SHA256, nil
	case oid.Equal(oidSHA384):
		return crypto.SHA384, nil
	case oid.Equal(oidSHA512):
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("pdfsigning: unsupported digest OID %v", oid)
	}
}

func isDERNull(value derValue) bool {
	return value.Tag == 0x05 && len(value.Content) == 0
}

func publicKeysEqual(a, b any) bool {
	left, err := x509.MarshalPKIXPublicKey(a)
	if err != nil {
		return false
	}
	right, err := x509.MarshalPKIXPublicKey(b)
	return err == nil && bytes.Equal(left, right)
}

// Extended key usages of a CA under which a document signer may be issued.
var (
	oidMicrosoftDocumentSigning = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 311, 10, 3, 12}
	oidAdobeAuthenticDocuments  = asn1.ObjectIdentifier{1, 2, 840, 113583, 1, 1, 5}
)

func anyChainAllowsDocumentSigning(chains [][]*x509.Certificate) bool {
	for _, chain := range chains {
		allowed := true
		for _, ca := range chain[1:] {
			if !caAllowsDocumentSigning(ca) {
				allowed = false
				break
			}
		}
		if allowed {
			return true
		}
	}
	return false
}

// caAllowsDocumentSigning reports whether ca's extended key usage, when it
// has one, lets it issue document signers; a CA limited to TLS does not.
func caAllowsDocumentSigning(ca *x509.Certificate) bool {
	if len(ca.ExtKeyUsage) == 0 && len(ca.UnknownExtKeyUsage) == 0 {
		return true
	}
	for _, usage := range ca.ExtKeyUsage {
		if usage == x509.ExtKeyUsageAny || usage == x509.ExtKeyUsageEmailProtection {
			return true
		}
	}
	for _, oid := range ca.UnknownExtKeyUsage {
		if oid.Equal(oidDocumentSigning) || oid.Equal(oidMicrosoftDocumentSigning) || oid.Equal(oidAdobeAuthenticDocuments) {
			return true
		}
	}
	return false
}

func validateDocumentSignerCertificate(cert *x509.Certificate) error {
	if cert.IsCA {
		return errors.New("pdfsigning: signer certificate must not be a CA")
	}
	if cert.KeyUsage != 0 && cert.KeyUsage&(x509.KeyUsageDigitalSignature|x509.KeyUsageContentCommitment) == 0 {
		return errors.New("pdfsigning: signer certificate is not allowed for digital signatures")
	}
	if len(cert.ExtKeyUsage) == 0 && len(cert.UnknownExtKeyUsage) == 0 {
		return nil
	}
	for _, oid := range cert.UnknownExtKeyUsage {
		if oid.Equal(oidDocumentSigning) {
			return nil
		}
	}
	return errors.New("pdfsigning: signer certificate is not allowed for document signing")
}

// findSignerCertificate returns the certificate named by a SignerInfo sid,
// either issuerAndSerialNumber or [0] subjectKeyIdentifier (RFC 5652 5.3),
// or nil when no embedded certificate matches.
func findSignerCertificate(certs []*x509.Certificate, sid derValue) (*x509.Certificate, error) {
	switch sid.Tag {
	case 0x30:
		issuer, serial, err := decodeIssuerAndSerial(sid)
		if err != nil {
			return nil, err
		}
		for _, cert := range certs {
			if bytes.Equal(cert.RawIssuer, issuer) && cert.SerialNumber.Cmp(serial) == 0 {
				return cert, nil
			}
		}
	case 0x80:
		if len(sid.Content) == 0 {
			return nil, errors.New("pdfsigning: empty signer subjectKeyIdentifier")
		}
		for _, cert := range certs {
			if bytes.Equal(cert.SubjectKeyId, sid.Content) {
				return cert, nil
			}
		}
	default:
		return nil, fmt.Errorf("pdfsigning: unsupported signer identifier tag 0x%02x", sid.Tag)
	}
	return nil, nil
}

func decodeIssuerAndSerial(value derValue) ([]byte, *big.Int, error) {
	children, err := readDERChildren(value.Content)
	if err != nil {
		return nil, nil, err
	}
	if len(children) != 2 {
		return nil, nil, errors.New("pdfsigning: invalid issuer and serial")
	}
	var serial *big.Int
	if _, err := asn1.Unmarshal(children[1].Full, &serial); err != nil {
		return nil, nil, err
	}
	return children[0].Full, serial, nil
}
