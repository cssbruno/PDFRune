// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package importpdf

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5" // #nosec G501 -- PDF standard security handler (ISO 32000) mandates MD5 for R2-R4 key derivation.
	"crypto/rc4" // #nosec G503 -- PDF standard security handler (ISO 32000) mandates RC4 for V1/V2 decryption.
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"unicode/utf8"
)

// ErrPasswordRequired reports an encrypted PDF that cannot be opened with the
// empty user password. Callers may retry with ImportOptions.Password.
var ErrPasswordRequired = errors.New("PDF requires a password to open")

// ErrIncorrectPassword reports that ImportOptions.Password matches neither the
// user nor the owner password of an encrypted PDF.
var ErrIncorrectPassword = errors.New("PDF password is incorrect")

// ErrUnsupportedEncryption reports an encryption handler or crypt filter the
// importer cannot decrypt.
var ErrUnsupportedEncryption = errors.New("PDF encryption method is not supported")

// pdfPasswordPadding is the 32-byte padding string from ISO 32000-1, 7.6.3.3.
var pdfPasswordPadding = []byte{
	0x28, 0xbf, 0x4e, 0x5e, 0x4e, 0x75, 0x8a, 0x41, 0x64, 0x00, 0x4e, 0x56, 0xff, 0xfa, 0x01, 0x08,
	0x2e, 0x2e, 0x00, 0xb6, 0xd0, 0x68, 0x3e, 0x80, 0x2f, 0x0c, 0xa9, 0xfe, 0x64, 0x53, 0x69, 0x7a,
}

type pdfCryptMethod int

const (
	pdfCryptIdentity pdfCryptMethod = iota
	pdfCryptRC4
	pdfCryptAESV2
	pdfCryptAESV3
)

// pdfSecurityHandler decrypts strings and streams of a PDF protected by the
// standard security handler once a user or owner password authenticated.
type pdfSecurityHandler struct {
	key             []byte
	stream          pdfCryptMethod
	str             pdfCryptMethod
	encryptMetadata bool
}

func newPDFSecurityHandler(encrypt pdfDict, firstID []byte, password string) (*pdfSecurityHandler, error) {
	if filter := encrypt["Filter"]; filter.kind != pdfValueName || filter.name != "Standard" {
		return nil, fmt.Errorf("%w: only the Standard security handler is supported", ErrUnsupportedEncryption)
	}
	if _, ok := encrypt["SubFilter"]; ok {
		return nil, fmt.Errorf("%w: public-key security handlers are not supported", ErrUnsupportedEncryption)
	}
	v, err := optionalPDFInt(encrypt, "V", 0)
	if err != nil {
		return nil, err
	}
	r, err := optionalPDFInt(encrypt, "R", 0)
	if err != nil {
		return nil, err
	}
	encryptMetadata := true
	if value, ok := encrypt["EncryptMetadata"]; ok && value.kind == pdfValueRaw && string(value.raw) == "false" {
		encryptMetadata = false
	}
	owner, err := pdfDictStringBytes(encrypt, "O")
	if err != nil {
		return nil, err
	}
	user, err := pdfDictStringBytes(encrypt, "U")
	if err != nil {
		return nil, err
	}
	handler := &pdfSecurityHandler{encryptMetadata: encryptMetadata}
	switch {
	case (v == 1 || v == 2) && (r == 2 || r == 3):
		handler.stream, handler.str = pdfCryptRC4, pdfCryptRC4
	case v == 4 && r == 4:
		if handler.stream, err = v4CryptMethod(encrypt, "StmF"); err != nil {
			return nil, err
		}
		if handler.str, err = v4CryptMethod(encrypt, "StrF"); err != nil {
			return nil, err
		}
	case v == 5 && (r == 5 || r == 6):
		handler.stream, handler.str = pdfCryptAESV3, pdfCryptAESV3
	default:
		return nil, fmt.Errorf("%w: V %d R %d", ErrUnsupportedEncryption, v, r)
	}

	if v == 5 {
		handler.key, err = authenticateAES256(r, []byte(password), owner, user, encrypt)
	} else {
		handler.key, err = authenticateRC4MD5(encrypt, v, r, encryptMetadata, password, owner, user, firstID)
	}
	if err != nil {
		return nil, err
	}
	return handler, nil
}

func v4CryptMethod(encrypt pdfDict, filterKey string) (pdfCryptMethod, error) {
	name := "Identity"
	if value, ok := encrypt[filterKey]; ok {
		if value.kind != pdfValueName {
			return 0, fmt.Errorf("%w: %s is not a name", ErrUnsupportedEncryption, filterKey)
		}
		name = value.name
	}
	if name == "Identity" {
		return pdfCryptIdentity, nil
	}
	filters := encrypt["CF"]
	if filters.kind != pdfValueDict {
		return 0, fmt.Errorf("%w: crypt filter dictionary is missing", ErrUnsupportedEncryption)
	}
	filter := filters.dict[name]
	if filter.kind != pdfValueDict {
		return 0, fmt.Errorf("%w: crypt filter %s is missing", ErrUnsupportedEncryption, name)
	}
	method := filter.dict["CFM"]
	if method.kind != pdfValueName {
		return pdfCryptIdentity, nil
	}
	switch method.name {
	case "None":
		return pdfCryptIdentity, nil
	case "V2":
		return pdfCryptRC4, nil
	case "AESV2":
		return pdfCryptAESV2, nil
	default:
		return 0, fmt.Errorf("%w: crypt filter method %s", ErrUnsupportedEncryption, method.name)
	}
}

// defaultKeyBits is the key length used when the encryption dictionary has no
// top-level /Length. That entry belongs to V 2 and 3; under V 4 the length
// comes from the stream crypt filter, where AESV2 is always 128 bits and
// writers record /Length in bytes as often as in bits.
func defaultKeyBits(encrypt pdfDict, v int) int {
	if v != 4 {
		return 40
	}
	name := encrypt["StmF"]
	filters := encrypt["CF"]
	if name.kind != pdfValueName || filters.kind != pdfValueDict {
		return 128
	}
	filter := filters.dict[name.name]
	if filter.kind != pdfValueDict {
		return 128
	}
	if method := filter.dict["CFM"]; method.kind == pdfValueName && method.name == "AESV2" {
		return 128
	}
	length, err := optionalPDFInt(filter.dict, "Length", 128)
	if err != nil {
		return 128
	}
	if length > 0 && length <= 16 {
		return length * 8
	}
	return length
}

// authenticateRC4MD5 implements ISO 32000-1 algorithms 2, 4, 5 and 7: the
// password is tried first as the user password and then as the owner password.
func authenticateRC4MD5(encrypt pdfDict, v, r int, encryptMetadata bool, password string, owner, user, firstID []byte) ([]byte, error) {
	if len(owner) < 32 || len(user) < 32 {
		return nil, fmt.Errorf("%w: O and U must hold 32 bytes", ErrUnsupportedEncryption)
	}
	keyLength := 5
	if r >= 3 {
		bits, err := optionalPDFInt(encrypt, "Length", defaultKeyBits(encrypt, v))
		if err != nil {
			return nil, err
		}
		if bits < 40 || bits > 128 || bits%8 != 0 {
			return nil, fmt.Errorf("%w: key length %d", ErrUnsupportedEncryption, bits)
		}
		keyLength = bits / 8
	}
	permissions, err := optionalPDFInt(encrypt, "P", 0)
	if err != nil {
		return nil, err
	}
	userPassword := pdfDocPassword(password)
	if key, ok := rc4UserKey(userPassword, owner, user, firstID, uint32(int32(permissions)), r, keyLength, encryptMetadata); ok { // #nosec G115 -- /P is a signed 32-bit field.
		return key, nil
	}
	recovered := ownerToUserPassword(userPassword, owner, r, keyLength)
	if key, ok := rc4UserKey(recovered, owner, user, firstID, uint32(int32(permissions)), r, keyLength, encryptMetadata); ok { // #nosec G115 -- /P is a signed 32-bit field.
		return key, nil
	}
	// A file that opens without a password is not refused because the caller
	// also supplied one, as a conforming reader would open it.
	if password != "" {
		if key, ok := rc4UserKey(nil, owner, user, firstID, uint32(int32(permissions)), r, keyLength, encryptMetadata); ok { // #nosec G115 -- /P is a signed 32-bit field.
			return key, nil
		}
	}
	if password == "" {
		return nil, ErrPasswordRequired
	}
	return nil, ErrIncorrectPassword
}

func rc4UserKey(password, owner, user, firstID []byte, permissions uint32, r, keyLength int, encryptMetadata bool) ([]byte, bool) {
	digest := md5.New() // #nosec G401 -- mandated by the PDF standard security handler.
	digest.Write(padPDFPassword(password))
	digest.Write(owner[:32])
	var p [4]byte
	binary.LittleEndian.PutUint32(p[:], permissions)
	digest.Write(p[:])
	digest.Write(firstID)
	if r >= 4 && !encryptMetadata {
		digest.Write([]byte{0xff, 0xff, 0xff, 0xff})
	}
	key := digest.Sum(nil)
	if r >= 3 {
		for i := 0; i < 50; i++ {
			sum := md5.Sum(key[:keyLength]) // #nosec G401 -- mandated by the PDF standard security handler.
			key = sum[:]
		}
	}
	key = key[:keyLength]

	if r == 2 {
		check := rc4XOR(key, pdfPasswordPadding)
		return key, bytes.Equal(check, user[:32])
	}
	digest = md5.New() // #nosec G401 -- mandated by the PDF standard security handler.
	digest.Write(pdfPasswordPadding)
	digest.Write(firstID)
	check := rc4XOR(key, digest.Sum(nil))
	for i := 1; i <= 19; i++ {
		check = rc4XOR(xorPDFKey(key, byte(i)), check)
	}
	return key, bytes.Equal(check[:16], user[:16])
}

func ownerToUserPassword(password, owner []byte, r, keyLength int) []byte {
	sum := md5.Sum(padPDFPassword(password)) // #nosec G401 -- mandated by the PDF standard security handler.
	key := sum[:]
	if r >= 3 {
		for i := 0; i < 50; i++ {
			sum = md5.Sum(key) // #nosec G401 -- mandated by the PDF standard security handler.
			key = sum[:]
		}
	}
	key = key[:keyLength]
	if r == 2 {
		return rc4XOR(key, owner[:32])
	}
	recovered := append([]byte(nil), owner[:32]...)
	for i := 19; i >= 0; i-- {
		recovered = rc4XOR(xorPDFKey(key, byte(i)), recovered)
	}
	return recovered
}

// authenticateAES256 implements ISO 32000-2 algorithms 2.A and 2.B (R6) and
// the Adobe extension level 3 variant (R5).
func authenticateAES256(r int, password, owner, user []byte, encrypt pdfDict) ([]byte, error) {
	if len(owner) < 48 || len(user) < 48 {
		return nil, fmt.Errorf("%w: O and U must hold 48 bytes", ErrUnsupportedEncryption)
	}
	if len(password) > 127 {
		password = password[:127]
	}
	ownerKey, err := pdfDictStringBytes(encrypt, "OE")
	if err != nil {
		return nil, err
	}
	userKey, err := pdfDictStringBytes(encrypt, "UE")
	if err != nil {
		return nil, err
	}
	if len(ownerKey) < 32 || len(userKey) < 32 {
		return nil, fmt.Errorf("%w: OE and UE must hold 32 bytes", ErrUnsupportedEncryption)
	}
	if bytes.Equal(aes256PasswordHash(r, password, user[32:40], nil), user[:32]) {
		return aes256UnwrapKey(aes256PasswordHash(r, password, user[40:48], nil), userKey[:32])
	}
	if bytes.Equal(aes256PasswordHash(r, password, owner[32:40], user[:48]), owner[:32]) {
		return aes256UnwrapKey(aes256PasswordHash(r, password, owner[40:48], user[:48]), ownerKey[:32])
	}
	// As for RC4: a file that opens without a password still opens.
	if len(password) > 0 && bytes.Equal(aes256PasswordHash(r, nil, user[32:40], nil), user[:32]) {
		return aes256UnwrapKey(aes256PasswordHash(r, nil, user[40:48], nil), userKey[:32])
	}
	if len(password) == 0 {
		return nil, ErrPasswordRequired
	}
	return nil, ErrIncorrectPassword
}

func aes256PasswordHash(r int, password, salt, userData []byte) []byte {
	digest := sha256.New()
	digest.Write(password)
	digest.Write(salt)
	digest.Write(userData)
	key := digest.Sum(nil)
	if r == 5 {
		return key
	}
	for round := 0; ; round++ {
		block := make([]byte, 0, 64*(len(password)+64+len(userData)))
		for i := 0; i < 64; i++ {
			block = append(block, password...)
			block = append(block, key...)
			block = append(block, userData...)
		}
		cipherBlock, _ := aes.NewCipher(key[:16])
		encrypted := make([]byte, len(block))
		cipher.NewCBCEncrypter(cipherBlock, key[16:32]).CryptBlocks(encrypted, block)
		remainder := 0
		for _, b := range encrypted[:16] {
			remainder += int(b)
		}
		var next hash.Hash
		switch remainder % 3 {
		case 0:
			next = sha256.New()
		case 1:
			next = sha512.New384()
		default:
			next = sha512.New()
		}
		next.Write(encrypted)
		key = next.Sum(nil)
		if round >= 63 && int(encrypted[len(encrypted)-1]) <= round+1-32 {
			break
		}
	}
	return key[:32]
}

func aes256UnwrapKey(wrappingKey, wrapped []byte) ([]byte, error) {
	block, err := aes.NewCipher(wrappingKey)
	if err != nil {
		return nil, err
	}
	key := make([]byte, 32)
	cipher.NewCBCDecrypter(block, make([]byte, aes.BlockSize)).CryptBlocks(key, wrapped[:32])
	return key, nil
}

func (h *pdfSecurityHandler) decryptString(ref ObjRef, data []byte) ([]byte, error) {
	return h.decrypt(h.str, ref, data)
}

func (h *pdfSecurityHandler) decryptStream(ref ObjRef, data []byte) ([]byte, error) {
	return h.decrypt(h.stream, ref, data)
}

func (h *pdfSecurityHandler) decrypt(method pdfCryptMethod, ref ObjRef, data []byte) ([]byte, error) {
	switch method {
	case pdfCryptIdentity:
		return data, nil
	case pdfCryptRC4:
		return rc4XOR(h.objectKey(ref, false), data), nil
	case pdfCryptAESV2:
		return aesCBCDecrypt(h.objectKey(ref, true), data)
	case pdfCryptAESV3:
		return aesCBCDecrypt(h.key, data)
	default:
		return nil, ErrUnsupportedEncryption
	}
}

// objectKey implements ISO 32000-1 algorithm 1 for RC4 and AESV2.
func (h *pdfSecurityHandler) objectKey(ref ObjRef, salted bool) []byte {
	digest := md5.New() // #nosec G401 -- mandated by the PDF standard security handler.
	digest.Write(h.key)
	digest.Write([]byte{byte(ref.num), byte(ref.num >> 8), byte(ref.num >> 16), byte(ref.gen), byte(ref.gen >> 8)})
	if salted {
		digest.Write([]byte("sAlT"))
	}
	size := len(h.key) + 5
	if size > 16 {
		size = 16
	}
	return digest.Sum(nil)[:size]
}

// aesCBCDecrypt decrypts IV-prefixed AES-CBC data and removes PKCS#5 padding.
// Producers that emit a truncated final block or malformed padding are read
// leniently, as conforming readers do; the bytes are re-validated downstream.
func aesCBCDecrypt(key, data []byte) ([]byte, error) {
	if len(data) < aes.BlockSize {
		return []byte{}, nil
	}
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	iv := data[:aes.BlockSize]
	body := data[aes.BlockSize:]
	body = body[:len(body)-len(body)%aes.BlockSize]
	plain := make([]byte, len(body))
	cipher.NewCBCDecrypter(block, iv).CryptBlocks(plain, body)
	if n := len(plain); n > 0 {
		pad := int(plain[n-1])
		if pad >= 1 && pad <= aes.BlockSize && pad <= n && bytes.Equal(plain[n-pad:], bytes.Repeat([]byte{byte(pad)}, pad)) {
			plain = plain[:n-pad]
		}
	}
	return plain, nil
}

func rc4XOR(key, data []byte) []byte {
	stream, err := rc4.NewCipher(key) // #nosec G405 -- mandated by the PDF standard security handler.
	if err != nil {
		return append([]byte(nil), data...)
	}
	out := make([]byte, len(data))
	stream.XORKeyStream(out, data)
	return out
}

func xorPDFKey(key []byte, value byte) []byte {
	out := make([]byte, len(key))
	for i, b := range key {
		out[i] = b ^ value
	}
	return out
}

func padPDFPassword(password []byte) []byte {
	padded := make([]byte, 32)
	n := copy(padded, password)
	copy(padded[n:], pdfPasswordPadding)
	return padded
}

// pdfDocPassword encodes an R2-R4 password as Latin-1, the subset of
// PDFDocEncoding a typed password can reach; other runes become '?'.
func pdfDocPassword(password string) []byte {
	if !utf8.ValidString(password) {
		return []byte(password)
	}
	out := make([]byte, 0, len(password))
	for _, r := range password {
		if r > 0xff {
			r = '?'
		}
		out = append(out, byte(r))
	}
	if len(out) > 32 {
		out = out[:32]
	}
	return out
}

func optionalPDFInt(dict pdfDict, key string, fallback int) (int, error) {
	value, ok := dict[key]
	if !ok || value.kind == pdfValueNull {
		return fallback, nil
	}
	if value.kind != pdfValueNumber || value.number != float64(int64(value.number)) {
		return 0, fmt.Errorf("PDF %s is not an integer", key)
	}
	return int(value.number), nil
}

func pdfDictStringBytes(dict pdfDict, key string) ([]byte, error) {
	value, ok := dict[key]
	if !ok {
		return nil, fmt.Errorf("%w: %s is missing", ErrUnsupportedEncryption, key)
	}
	out, ok := pdfStringBytes(value)
	if !ok {
		return nil, fmt.Errorf("%w: %s is not a string", ErrUnsupportedEncryption, key)
	}
	return out, nil
}

// pdfStringBytes decodes a literal or hexadecimal string value.
func pdfStringBytes(value pdfValue) ([]byte, bool) {
	if value.kind != pdfValueRaw || len(value.raw) == 0 {
		return nil, false
	}
	switch value.raw[0] {
	case '(':
		return decodePDFLiteralString(value.raw), true
	case '<':
		return decodePDFHexString(value.raw), true
	default:
		return nil, false
	}
}

func decodePDFLiteralString(raw []byte) []byte {
	if len(raw) < 2 {
		return []byte{}
	}
	body := raw[1 : len(raw)-1]
	out := make([]byte, 0, len(body))
	for i := 0; i < len(body); i++ {
		ch := body[i]
		switch {
		case ch == '\r':
			out = append(out, '\n')
			if i+1 < len(body) && body[i+1] == '\n' {
				i++
			}
		case ch != '\\':
			out = append(out, ch)
		case i+1 >= len(body):
		default:
			i++
			next := body[i]
			switch next {
			case 'n':
				out = append(out, '\n')
			case 'r':
				out = append(out, '\r')
			case 't':
				out = append(out, '\t')
			case 'b':
				out = append(out, '\b')
			case 'f':
				out = append(out, '\f')
			case '\r':
				if i+1 < len(body) && body[i+1] == '\n' {
					i++
				}
			case '\n':
			default:
				if next >= '0' && next <= '7' {
					value := int(next - '0')
					for digits := 1; digits < 3 && i+1 < len(body) && body[i+1] >= '0' && body[i+1] <= '7'; digits++ {
						i++
						value = value*8 + int(body[i]-'0')
					}
					out = append(out, byte(value)) // #nosec G115 -- octal escapes above 0377 wrap as in conforming readers.
				} else {
					out = append(out, next)
				}
			}
		}
	}
	return out
}

func decodePDFHexString(raw []byte) []byte {
	out := make([]byte, 0, len(raw)/2)
	var high byte
	half := false
	for _, ch := range raw[1:] {
		if ch == '>' {
			break
		}
		value, ok := pdfHexValue(ch)
		if !ok {
			continue
		}
		if !half {
			high = value
			half = true
			continue
		}
		out = append(out, high<<4|value)
		half = false
	}
	if half {
		out = append(out, high<<4)
	}
	return out
}
