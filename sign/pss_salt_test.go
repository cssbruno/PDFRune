// SPDX-License-Identifier: LicenseRef-PaperRune-Health-Sector-Restricted-1.0
// Copyright (c) 2026 cssBruno

package sign

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"math/big"
	"testing"
)

// The PSS salt length is read from the CMS. A salt of 2^63-34 once wrapped the
// length check inside crypto/rsa and panicked on a negative slice bound for any
// signature whose encoded message ended in 0xbc with its top bit clear.
func TestVerifyPSSRejectsSaltLongerThanTheKey(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	encoded := make([]byte, key.Size())
	encoded[len(encoded)-1] = 0xbc
	encoded[1] = 0x01
	signature := new(big.Int).Exp(new(big.Int).SetBytes(encoded), key.D, key.N).FillBytes(make([]byte, key.Size()))
	hashed := sha256.Sum256([]byte("document"))

	defer func() {
		if recovered := recover(); recovered != nil {
			t.Fatalf("verification panicked: %v", recovered)
		}
	}()
	for _, salt := range []int{1<<63 - 34, key.Size()} {
		if err := verifyPublicKeySignature(&key.PublicKey, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{SaltLength: salt, Hash: crypto.SHA256}); err == nil {
			t.Fatalf("salt length %d verified", salt)
		}
	}
}

func TestVerifyPSSAcceptsTheLongestSalt(t *testing.T) {
	key, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatal(err)
	}
	hashed := sha256.Sum256([]byte("document"))
	signature, err := rsa.SignPSS(rand.Reader, key, crypto.SHA256, hashed[:], &rsa.PSSOptions{SaltLength: rsa.PSSSaltLengthAuto})
	if err != nil {
		t.Fatal(err)
	}
	longest := key.Size() - sha256.Size - 2
	if err := verifyPublicKeySignature(&key.PublicKey, crypto.SHA256, hashed[:], signature, &rsa.PSSOptions{SaltLength: longest, Hash: crypto.SHA256}); err != nil {
		t.Fatalf("maximum-salt signature rejected: %v", err)
	}
}
