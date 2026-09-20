package nxformat

import (
	"bytes"
	"encoding/hex"
	"testing"
)

// xtsLEVector is EncryptNCAHeader(key=00..1f, unit 1, plain[i]=(i*13+7)&0xff)
// computed with an independent implementation of Nintendo's XTS: the tweak
// evolves as a little-endian GF(2^128) integer (carry toward byte 15, the
// 0x87 reduction landing in byte 0). The convention was determined against
// retail gamecard and CDN NCA headers: with it, the decrypted ProgramId at
// +0x10, RightsId, and FsEntry table all read correctly; with the standard
// IEEE big-endian byte order every block past the first of each data unit
// decrypts to garbage (which is why distribution flipping — a block-0-only
// rewrite — never noticed).
const xtsLEVector = "4c0f2ec9805e23ab5a9af5eed6e33ff4ce8388bf27f240c175ced22b4237ba2e" +
	"f4ffc7aa1ca343372fe7aaf9b70e22a69e108576aed8f42735600d3d57a357b4" +
	"2e7375edd37b569926008f2159547cf44b66cff37c549098d9f1c303c3d6929a" +
	"e2cf41315af512030580dffc3f775a074355ca6d89686760d6c25ef4bfe9b708" +
	"a4e6324bcb5d026b3cfcff0bf616af050f374ca0c66626d10a1d95460c462f5d" +
	"722aa65d1fbdf8d47b4c3def21408b1d4038ebb1a921415700ca948137132d92" +
	"ef25868489365d88d7cb97aa09690d245ea47f75d78f703ef9c0a0c790f770f9" +
	"87551f37671a735f1097854ca8880a03f3898f15195d2eafd9ec071f55d9d394" +
	"8813ca38aa42c22bafce06815b160b44c8be5bd13c828ee88bedaedb57e54214" +
	"9c0e5a5d8c627a8ebac137153de99312e98a1a751497bdd75fbd68ef244341be" +
	"dd72189bfc93829f707a1da2c1baa306a3554e6e5e7c63b6e05c7027c0aa77ee" +
	"524d673c34377feb2a8f1cdb7ffce0e81a6913b1667e6ec2ce39e6f644c1b4aa" +
	"ae765e25fcdb9a13349b3bec7c362c78c9edf2074ffbeb1ce05e0c8eba3e936c" +
	"7c96d03ab9d7a52f95003a654cdcd04287551acf76dfd7f3f37d20d8937117b1" +
	"77acf4af71b895361858814ddb0b0429f6d6cdfb8a5dcf7d403ba569f97961e6" +
	"c6a7da535dbdbecf69dc767cbb7ba142c28e64fbacc7f32752da5d9ab0a17deb"

// TestXTSNintendoTweakEvolution fails if the tweak-evolution byte order
// regresses to (or is "fixed" to) the standard IEEE big-endian convention.
func TestXTSNintendoTweakEvolution(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i)
	}
	plain := make([]byte, 0x200)
	for i := range plain {
		plain[i] = byte(i*13 + 7)
	}
	wantCT, err := hex.DecodeString(xtsLEVector)
	if err != nil {
		t.Fatal(err)
	}

	hdr := make([]byte, 0x400)
	if err := EncryptNCAHeader(hdr, plain, key); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(hdr[NCAHeaderEncOffset:NCAHeaderEncOffset+NCAHeaderEncSize], wantCT) {
		t.Fatalf("ciphertext differs from the pinned little-endian XTS vector — tweak evolution convention regressed")
	}
	got, err := DecryptNCAHeader(hdr, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, plain) {
		t.Fatalf("round trip mismatch")
	}
}
