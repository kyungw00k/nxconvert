package nxformat

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
)

// Retail fixtures from the converting user's library. Both are skipped when
// absent so the suite stays runnable anywhere.
const (
	deadCellsNSP      = "/Users/humphrey.park/Downloads/switch/Dead Cells/Dead Cells [BASE][0100646009FB][v0].nsp"
	reencryptKeysPath = "/tmp/prod.keys"
)

// lcgFill fills b with deterministic pseudo-random bytes so failures are
// reproducible and XOR keystreams never cancel accidentally.
func lcgFill(b []byte, seed uint32) {
	for i := range b {
		seed = seed*1664525 + 1013904223
		b[i] = byte(seed >> 24)
	}
}

// manualKeystream produces the NCA section CTR keystream for n bytes at
// absolute offset abs, computed from first principles (raw ECB of each
// incremented counter block) so it is independent of cipher.NewCTR, which
// the implementation under test uses.
func manualKeystream(key []byte, abs int64, n int) []byte {
	blk, err := aes.NewCipher(key)
	if err != nil {
		panic(err)
	}
	out := make([]byte, n)
	counter := uint64(abs) >> 4
	for i := 0; i < n; i += aes.BlockSize {
		iv := make([]byte, aes.BlockSize)
		binary.BigEndian.PutUint64(iv[8:], counter)
		block := make([]byte, aes.BlockSize)
		blk.Encrypt(block, iv)
		copy(out[i:min(i+aes.BlockSize, n)], block)
		counter++
	}
	return out
}

func xorInto(dst []byte, ks []byte) {
	for i := range dst {
		dst[i] ^= ks[i]
	}
}

func TestKeyAreaRoundTrip(t *testing.T) {
	kaak := make([]byte, 16)
	lcgFill(kaak, 1)
	keys := make([][]byte, KeyAreaKeyCount)
	for i := range keys {
		keys[i] = make([]byte, aes.BlockSize)
		lcgFill(keys[i], uint32(0x10+i))
	}

	enc, err := EncryptKeyArea(keys, kaak)
	if err != nil {
		t.Fatalf("EncryptKeyArea: %v", err)
	}
	if len(enc) != NCAKeyAreaSize {
		t.Fatalf("encrypted key area is %d bytes, want %d", len(enc), NCAKeyAreaSize)
	}
	// Each slot must be an independent ECB block: flipping plaintext slot 3
	// may not touch the ciphertext of slots 0-2.
	mod := make([][]byte, KeyAreaKeyCount)
	for i := range mod {
		mod[i] = keys[i]
	}
	mod[3] = make([]byte, aes.BlockSize)
	lcgFill(mod[3], 99)
	encMod, err := EncryptKeyArea(mod, kaak)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(encMod[:3*aes.BlockSize], enc[:3*aes.BlockSize]) {
		t.Fatalf("slot 3 change leaked into slots 0-2 — key area is not per-block ECB")
	}
	if bytes.Equal(encMod[3*aes.BlockSize:], enc[3*aes.BlockSize:]) {
		t.Fatalf("slot 3 ciphertext did not change with its plaintext")
	}

	got, err := DecryptKeyArea(enc, kaak)
	if err != nil {
		t.Fatalf("DecryptKeyArea: %v", err)
	}
	if len(got) != KeyAreaKeyCount {
		t.Fatalf("got %d keys, want %d", len(got), KeyAreaKeyCount)
	}
	for i := range keys {
		if !bytes.Equal(got[i], keys[i]) {
			t.Errorf("key %d: got %x, want %x", i, got[i], keys[i])
		}
	}

	for _, tc := range []struct {
		name string
		run  func() error
	}{
		{"short blob", func() error { _, err := DecryptKeyArea(enc[:0x30], kaak); return err }},
		{"long blob", func() error {
			blob := append(append([]byte(nil), enc...), enc[:16]...)
			_, err := DecryptKeyArea(blob, kaak)
			return err
		}},
		{"short kaak", func() error { _, err := DecryptKeyArea(enc, kaak[:15]); return err }},
		{"few keys", func() error { _, err := EncryptKeyArea(keys[:3], kaak); return err }},
		{"short slot", func() error {
			bad := make([][]byte, KeyAreaKeyCount)
			for i := range bad {
				bad[i] = keys[i]
			}
			bad[2] = bad[2][:15]
			_, err := EncryptKeyArea(bad, kaak)
			return err
		}},
	} {
		if err := tc.run(); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

func TestDeriveSectionKey(t *testing.T) {
	kaak := make([]byte, 16)
	lcgFill(kaak, 7)
	plain := make([]byte, NCAKeyAreaSize)
	lcgFill(plain, 8)
	enc, err := EncryptKeyArea([][]byte{plain[:16], plain[16:32], plain[32:48], plain[48:]}, kaak)
	if err != nil {
		t.Fatal(err)
	}

	got, err := DeriveSectionKey(enc, kaak)
	if err != nil {
		t.Fatalf("DeriveSectionKey: %v", err)
	}
	want, _ := DecryptKeyArea(enc, kaak)
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("key %d: DeriveSectionKey gave %x, DecryptKeyArea gave %x", i, got[i], want[i])
		}
	}
	if _, err := DeriveSectionKey(enc[:16], kaak); err == nil {
		t.Errorf("16-byte titlekey block: expected an error, want the full 64-byte key area")
	}
}

// cappedReader fails any Read asking for more than max bytes, proving the
// re-encryptor works in bounded chunks instead of slurping whole sections.
type cappedReader struct {
	*bytes.Reader
	max int
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if len(p) > c.max {
		return 0, fmt.Errorf("read of %d bytes exceeds %d-byte chunk cap", len(p), c.max)
	}
	return c.Reader.Read(p)
}

func TestReencryptNCA(t *testing.T) {
	oldKey := make([]byte, aes.BlockSize)
	lcgFill(oldKey, 0xAA)
	newKey := make([]byte, aes.BlockSize)
	lcgFill(newKey, 0xBB)

	// Header, gap, a multi-chunk section with a non-block-aligned tail, a
	// gap, a tiny odd-sized section, and a trailing gap.
	secAOff, secASize := int64(0xC00), int64(64<<10+0x123)
	secBOff, secBSize := int64(0x42000), int64(0x37)
	total := secBOff + secBSize + 0x100
	in := make([]byte, total)
	lcgFill(in, 0xC0FFEE)

	offsets := []int64{secAOff, secBOff}
	sizes := []int64{secASize, secBSize}

	var out bytes.Buffer
	capped := &cappedReader{Reader: bytes.NewReader(in), max: 1 << 20}
	if err := ReencryptNCA(capped, &out, oldKey, newKey, offsets, sizes); err != nil {
		t.Fatalf("ReencryptNCA: %v", err)
	}
	got := out.Bytes()
	if int64(len(got)) != total {
		t.Fatalf("output is %d bytes, want %d", len(got), total)
	}

	// Bytes outside sections pass through untouched.
	if !bytes.Equal(got[:secAOff], in[:secAOff]) {
		t.Errorf("leading gap was modified")
	}
	if !bytes.Equal(got[secAOff+secASize:secBOff], in[secAOff+secASize:secBOff]) {
		t.Errorf("inter-section gap was modified")
	}
	if !bytes.Equal(got[secBOff+secBSize:], in[secBOff+secBSize:]) {
		t.Errorf("trailing gap was modified")
	}

	// Sections match a keystream computed from first principles: XOR with
	// the old key's stream, then the new key's, both counter-based on the
	// absolute offsets.
	for _, sec := range []struct{ off, size int64 }{{secAOff, secASize}, {secBOff, secBSize}} {
		wantSec := append([]byte(nil), in[sec.off:sec.off+sec.size]...)
		xorInto(wantSec, manualKeystream(oldKey, sec.off, int(sec.size)))
		xorInto(wantSec, manualKeystream(newKey, sec.off, int(sec.size)))
		if !bytes.Equal(got[sec.off:sec.off+sec.size], wantSec) {
			t.Errorf("section at %#x does not match the manual two-keystream CTR re-encryption", sec.off)
		}
	}

	// The counter convention itself: the first keystream block of section A
	// must be ECB of [0 || be64(secAOff>>4)] under newKey, pre-XORed with
	// the same under oldKey.
	first := append([]byte(nil), in[secAOff:secAOff+16]...)
	xorInto(first, manualKeystream(oldKey, secAOff, 16))
	xorInto(first, manualKeystream(newKey, secAOff, 16))
	if !bytes.Equal(got[secAOff:secAOff+16], first) {
		t.Errorf("first block of section A mismatched")
	}

	// Re-encrypting the output back with the keys swapped restores the input.
	var back bytes.Buffer
	if err := ReencryptNCA(bytes.NewReader(got), &back, newKey, oldKey, offsets, sizes); err != nil {
		t.Fatalf("inverse ReencryptNCA: %v", err)
	}
	if !bytes.Equal(back.Bytes(), in) {
		t.Errorf("old->new->old round trip did not restore the input")
	}

	// Identical keys make the operation an identity copy.
	var same bytes.Buffer
	if err := ReencryptNCA(bytes.NewReader(in), &same, oldKey, oldKey, offsets, sizes); err != nil {
		t.Fatalf("identity ReencryptNCA: %v", err)
	}
	if !bytes.Equal(same.Bytes(), in) {
		t.Errorf("identical keys changed the stream")
	}

	// Argument validation.
	bad := []struct {
		name string
		run  func() error
	}{
		{"mismatched lengths", func() error {
			return ReencryptNCA(bytes.NewReader(in), io.Discard, oldKey, newKey, offsets, sizes[:1])
		}},
		{"out of order", func() error {
			return ReencryptNCA(bytes.NewReader(in), io.Discard, oldKey, newKey, []int64{secBOff, secAOff}, []int64{1, 1})
		}},
		{"overlap", func() error {
			return ReencryptNCA(bytes.NewReader(in), io.Discard, oldKey, newKey, []int64{secAOff, secAOff + 1}, []int64{0x10, 0x10})
		}},
		{"short old key", func() error {
			return ReencryptNCA(bytes.NewReader(in), io.Discard, oldKey[:15], newKey, offsets, sizes)
		}},
		{"long new key", func() error {
			return ReencryptNCA(bytes.NewReader(in), io.Discard, oldKey, append(append([]byte(nil), newKey...), 0), offsets, sizes)
		}},
		{"negative size", func() error {
			return ReencryptNCA(bytes.NewReader(in), io.Discard, oldKey, newKey, []int64{0x10}, []int64{-1})
		}},
		{"truncated section", func() error {
			return ReencryptNCA(bytes.NewReader(in[:secAOff+0x100]), io.Discard, oldKey, newKey, offsets, sizes)
		}},
	}
	for _, tc := range bad {
		if err := tc.run(); err == nil {
			t.Errorf("%s: expected an error", tc.name)
		}
	}
}

// --- retail fixtures (Dead Cells BASE NSP) ---

type fixtureNCA struct {
	name     string
	size     int64
	plain    []byte // decrypted header region [0x200,0x400)
	dataBase int64  // absolute offset of the NCA inside the NSP
}

// deadCellsNCAs returns every .nca entry of the fixture NSP with its
// decrypted header, or skips the test when the NSP or prod.keys is absent.
func deadCellsNCAs(t *testing.T) (map[string][]byte, *os.File, []fixtureNCA) {
	t.Helper()
	kf, err := os.Open(reencryptKeysPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("prod.keys fixture not present: %s", reencryptKeysPath)
		}
		t.Fatalf("opening prod.keys: %v", err)
	}
	defer kf.Close()
	keys, err := ParseProdKeys(kf)
	if err != nil {
		t.Fatalf("ParseProdKeys: %v", err)
	}

	f, err := os.Open(deadCellsNSP)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			t.Skipf("NSP fixture not present: %s", deadCellsNSP)
		}
		t.Fatalf("opening NSP: %v", err)
	}
	t.Cleanup(func() { f.Close() })

	entries, hdrSize, err := ParsePFS0(f)
	if err != nil {
		t.Fatalf("ParsePFS0: %v", err)
	}
	var out []fixtureNCA
	for _, e := range entries {
		if filepath.Ext(e.Name) != ".nca" {
			continue
		}
		hdr := make([]byte, 0x400)
		if _, err := io.ReadFull(io.LimitReader(ReadPFS0File(f, e), 0x400), hdr); err != nil {
			t.Fatalf("%s: reading header: %v", e.Name, err)
		}
		plain, err := DecryptNCAHeader(hdr, keys["header_key"])
		if err != nil {
			t.Fatalf("%s: DecryptNCAHeader: %v", e.Name, err)
		}
		if string(plain[:4]) != "NCA3" {
			t.Fatalf("%s: decrypted header magic %q, want NCA3", e.Name, plain[:4])
		}
		out = append(out, fixtureNCA{name: e.Name, size: e.Size, plain: plain, dataBase: hdrSize + int64(e.Offset)})
	}
	if len(out) == 0 {
		t.Fatal("fixture NSP carries no .nca entries")
	}
	return keys, f, out
}

// keyAreaKey picks the generation-matched key area key for a decrypted NCA
// header, applying hactool's rule: generation = max(crypto_type,
// crypto_type2) - 1, family from the kaek_ind byte.
func keyAreaKey(keys map[string][]byte, plain []byte) []byte {
	rev := plain[0x06]
	if plain[0x20] > rev {
		rev = plain[0x20]
	}
	if rev > 0 {
		rev--
	}
	family := []string{"application", "ocean", "system"}[plain[0x07]]
	return keys[fmt.Sprintf("key_area_key_%s_%02x", family, rev)]
}

func hasRightsID(plain []byte) bool {
	for _, b := range plain[0x30:0x40] {
		if b != 0 {
			return true
		}
	}
	return false
}

func bytesAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

func TestDeadCellsKeyArea(t *testing.T) {
	keys, _, ncas := deadCellsNCAs(t)

	var checked int
	for _, n := range ncas {
		kaak := keyAreaKey(keys, n.plain)
		if kaak == nil {
			t.Fatalf("%s: no key area key for the header's generation", n.name)
		}
		enc := n.plain[NCAKeyAreaOffset : NCAKeyAreaOffset+NCAKeyAreaSize]

		got, err := DecryptKeyArea(enc, kaak)
		if err != nil {
			t.Fatalf("%s: DecryptKeyArea: %v", n.name, err)
		}
		if len(got) != KeyAreaKeyCount {
			t.Fatalf("%s: got %d keys, want %d", n.name, len(got), KeyAreaKeyCount)
		}
		for i, k := range got {
			if len(k) != aes.BlockSize {
				t.Errorf("%s: key %d is %d bytes, want 16", n.name, i, len(k))
			}
		}

		// Re-encrypting the decrypted slots must reproduce the retail
		// ciphertext byte for byte.
		re, err := EncryptKeyArea(got, kaak)
		if err != nil {
			t.Fatalf("%s: EncryptKeyArea: %v", n.name, err)
		}
		if !bytes.Equal(re, enc) {
			t.Errorf("%s: key area round trip mismatch", n.name)
		}

		// Non-rights-id retail NCAs keep the canonical {0, 0, key, 0}
		// layout: only the AES-CTR section key slot is populated.
		if !hasRightsID(n.plain) {
			for _, i := range []int{0, 1, 3} {
				if !bytesAllZero(got[i]) {
					t.Errorf("%s: key area slot %d = %x, want zeros (retail layout)", n.name, i, got[i])
				}
			}
			if bytesAllZero(got[NCASectionKeySlot]) {
				t.Errorf("%s: key area slot %d is all zero, want the section key", n.name, NCASectionKeySlot)
			}
		}

		derived, err := DeriveSectionKey(enc, kaak)
		if err != nil {
			t.Fatalf("%s: DeriveSectionKey: %v", n.name, err)
		}
		for i := range got {
			if !bytes.Equal(derived[i], got[i]) {
				t.Errorf("%s: DeriveSectionKey key %d differs from DecryptKeyArea", n.name, i)
			}
		}
		checked++
	}
	if checked == 0 {
		t.Fatal("no NCAs checked")
	}
}

// decryptFSHeader decrypts one 0x200-byte fs header of an NCA. Stock retail
// NCAs store them as XTS units numbered 0 under header_key; this fixture
// (a gamecard-to-NSP repack) numbers them continuously from the main
// header, so both candidates are tried and the one decrypting to a sane
// fs header wins.
func decryptFSHeader(t *testing.T, headerKey []byte, raw []byte, idx int) []byte {
	t.Helper()
	for _, tweak := range []uint64{uint64(2 + idx), 0} {
		fs, err := xtsAES(headerKey, tweak, raw, true)
		if err != nil {
			t.Fatalf("decrypting fs header %d: %v", idx, err)
		}
		if fs[0] == 0x02 && fs[1] == 0x00 && fs[2] <= 1 && fs[3] <= 3 && fs[4] >= 1 && fs[4] <= 4 {
			return fs
		}
	}
	t.Fatalf("fs header %d does not decrypt to a sane layout under either XTS unit numbering", idx)
	return nil
}

// pfs0Anchor finds the first PFS0-typed section of an NCA and returns the
// absolute NCA offset where its "PFS0" partition magic sits.
func pfs0Anchor(t *testing.T, f *os.File, n fixtureNCA, headerKey []byte) int64 {
	t.Helper()
	for i := 0; i < 4; i++ {
		start := binary.LittleEndian.Uint32(n.plain[0x40+16*i:])
		end := binary.LittleEndian.Uint32(n.plain[0x44+16*i:])
		if start == 0 || end <= start {
			continue
		}
		raw := make([]byte, 0x200)
		if _, err := io.ReadFull(io.NewSectionReader(f, n.dataBase+0x400+0x200*int64(i), 0x200), raw); err != nil {
			t.Fatalf("%s: reading fs header %d: %v", n.name, i, err)
		}
		fs := decryptFSHeader(t, headerKey, raw, i)
		if fs[2] != 1 { // partition_type PFS0
			continue
		}
		pfs0Off := int64(binary.LittleEndian.Uint64(fs[8+0x38:]))
		if pfs0Off == 0 {
			t.Fatalf("%s: fs header %d has a zero pfs0 offset", n.name, i)
		}
		return int64(start)*0x200 + pfs0Off
	}
	return 0
}

func TestDeadCellsSectionCTR(t *testing.T) {
	keys, f, ncas := deadCellsNCAs(t)
	headerKey := keys["header_key"]

	// The cnmt NCA: one small PFS0 section whose key is fully derivable
	// from the header (no rights ID involved).
	var cnmt *fixtureNCA
	for i := range ncas {
		if filepath.Ext(ncas[i].name) == ".nca" && bytes.HasSuffix([]byte(ncas[i].name), []byte(".cnmt.nca")) {
			cnmt = &ncas[i]
		}
	}
	if cnmt == nil {
		t.Fatal("fixture NSP carries no .cnmt.nca")
	}

	kaak := keyAreaKey(keys, cnmt.plain)
	ka, err := DecryptKeyArea(cnmt.plain[NCAKeyAreaOffset:NCAKeyAreaOffset+NCAKeyAreaSize], kaak)
	if err != nil {
		t.Fatal(err)
	}
	sectionKey := ka[NCASectionKeySlot]

	anchor := pfs0Anchor(t, f, *cnmt, headerKey)
	if anchor == 0 {
		t.Fatal("cnmt NCA has no PFS0 section to anchor against")
	}

	read := func(off, n int64) []byte {
		b := make([]byte, n)
		if _, err := io.ReadFull(io.NewSectionReader(f, cnmt.dataBase+off, n), b); err != nil {
			t.Fatal(err)
		}
		return b
	}

	// Retail proof of the counter convention: decrypting the anchor bytes
	// with the key-area section key under sectionCounter must spell PFS0.
	head := read(anchor, 16)
	xorInto(head, manualKeystream(sectionKey, anchor, 16))
	if string(head[:4]) != "PFS0" {
		t.Fatalf("cnmt PFS0 anchor decrypts to %q — section key or counter convention regressed", head[:4])
	}

	// Functional re-encryption on real bytes: swap the section key for a
	// fresh one and confirm the anchor still decrypts under the new key,
	// the untouched bytes stay put, and the inverse restores the original.
	start := int64(binary.LittleEndian.Uint32(cnmt.plain[0x40:]))
	end := int64(binary.LittleEndian.Uint32(cnmt.plain[0x44:]))
	secOff, secSize := start*0x200, (int64(end)-start)*0x200

	newKey := make([]byte, aes.BlockSize)
	lcgFill(newKey, 0xDEAD)
	newKeys := make([][]byte, KeyAreaKeyCount)
	for i := range newKeys {
		newKeys[i] = make([]byte, aes.BlockSize)
		lcgFill(newKeys[i], uint32(0xE0+i))
	}
	newKeys[NCASectionKeySlot] = newKey
	newBlob, err := EncryptKeyArea(newKeys, kaak)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(newBlob, cnmt.plain[NCAKeyAreaOffset:NCAKeyAreaOffset+NCAKeyAreaSize]) {
		t.Fatal("fresh key area encrypted to the retail blob — fixture is not exercising a key change")
	}
	roundTripped, err := DecryptKeyArea(newBlob, kaak)
	if err != nil {
		t.Fatal(err)
	}
	for i := range newKeys {
		if !bytes.Equal(roundTripped[i], newKeys[i]) {
			t.Fatalf("fresh key area slot %d did not round trip", i)
		}
	}

	nca := read(0, cnmt.size)
	var out bytes.Buffer
	if err := ReencryptNCA(bytes.NewReader(nca), &out, sectionKey, newKey, []int64{secOff}, []int64{secSize}); err != nil {
		t.Fatalf("ReencryptNCA on retail bytes: %v", err)
	}
	got := out.Bytes()
	if int64(len(got)) != cnmt.size {
		t.Fatalf("re-encrypted NCA is %d bytes, want %d", len(got), cnmt.size)
	}
	if !bytes.Equal(got[:secOff], nca[:secOff]) {
		t.Error("header region changed during section re-encryption")
	}
	if !bytes.Equal(got[secOff+secSize:], nca[secOff+secSize:]) {
		t.Error("bytes after the section changed during section re-encryption")
	}
	if bytes.Equal(got[secOff:secOff+16], nca[secOff:secOff+16]) {
		t.Error("section ciphertext unchanged despite a key change")
	}

	rehead := append([]byte(nil), got[anchor:anchor+16]...)
	xorInto(rehead, manualKeystream(newKey, anchor, 16))
	if string(rehead[:4]) != "PFS0" {
		t.Fatalf("re-encrypted section decrypts to %q under the new key — re-encryption is wrong", rehead[:4])
	}

	var back bytes.Buffer
	if err := ReencryptNCA(bytes.NewReader(got), &back, newKey, sectionKey, []int64{secOff}, []int64{secSize}); err != nil {
		t.Fatalf("inverse ReencryptNCA: %v", err)
	}
	if !bytes.Equal(back.Bytes(), nca) {
		t.Error("old->new->old on retail bytes did not restore the original NCA")
	}
}
