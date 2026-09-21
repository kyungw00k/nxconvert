package nxformat

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"sort"
)

// Key-area layout, verified byte-for-byte against retail Dead Cells
// BASE/UPD NCAs (2026-09) and hactool's nca_header_t: the decrypted header
// region [0x200,0x400) holds the section entry table (4 x {u32 media
// start, u32 media end}) at +0x40, the 4 x 0x20 section-header SHA-256
// hashes at +0x80, and the 0x40-byte key area at +0x100 (NCA offset
// 0x300). The key area is four AES-128 keys, each independently
// ECB-encrypted under the generation-matched key_area_key_{
// application|ocean|system} picked by the header's kaek_ind byte (+0x07)
// with generation max(crypto_type, crypto_type2) - 1. Slot semantics:
// 0+1 form the AES-XTS key pair for gamecard XTS sections, 2 is the
// AES-CTR section key (retail non-rights-id NCAs decrypt to {0, 0, key,
// 0}), and 3 is unused.
const (
	// NCAKeyAreaOffset is where the (encrypted) key area sits in the
	// decrypted NCA header.
	NCAKeyAreaOffset = 0x100
	// NCAKeyAreaSize is the full encrypted key area: 4 keys x 16 bytes.
	NCAKeyAreaSize = 4 * aes.BlockSize
	// KeyAreaKeyCount is the number of per-title keys in a key area.
	KeyAreaKeyCount = 4
	// NCASectionKeySlot is the key area slot holding the AES-CTR section
	// key of a non-rights-id NCA.
	NCASectionKeySlot = 2
)

// reencryptChunk bounds the working buffer of the streaming section
// rewrite. Sections are re-encrypted 64 KiB at a time so multi-gigabyte
// NCAs never sit in memory.
const reencryptChunk = 64 << 10

// DecryptKeyArea decrypts the 0x40-byte key area copied from a decrypted
// NCA header (offset NCAKeyAreaOffset) with kaak, the generation-matched
// key area key from prod.keys. Each 16-byte key is AES-ECB decrypted on
// its own — the key area is four independent ECB blocks, not one chained
// blob. keys[NCASectionKeySlot] is the AES-CTR section key.
func DecryptKeyArea(encryptedKeyArea []byte, kaak []byte) ([][]byte, error) {
	if len(encryptedKeyArea) != NCAKeyAreaSize {
		return nil, fmt.Errorf("encrypted key area is %d bytes, want %d", len(encryptedKeyArea), NCAKeyAreaSize)
	}
	if len(kaak) != aes.BlockSize {
		return nil, fmt.Errorf("key area key is %d bytes, want %d (AES-128)", len(kaak), aes.BlockSize)
	}
	block, err := aes.NewCipher(kaak)
	if err != nil {
		return nil, fmt.Errorf("key area key: %w", err)
	}
	keys := make([][]byte, KeyAreaKeyCount)
	for i := range keys {
		keys[i] = make([]byte, aes.BlockSize)
		block.Decrypt(keys[i], encryptedKeyArea[i*aes.BlockSize:(i+1)*aes.BlockSize])
	}
	return keys, nil
}

// EncryptKeyArea is the inverse of DecryptKeyArea: it packs four plaintext
// 16-byte section keys into the 0x40-byte blob the header slot at
// NCAKeyAreaOffset holds, ECB-encrypting each key under kaak.
func EncryptKeyArea(keyArea [][]byte, kaak []byte) ([]byte, error) {
	if len(keyArea) != KeyAreaKeyCount {
		return nil, fmt.Errorf("key area has %d keys, want %d", len(keyArea), KeyAreaKeyCount)
	}
	if len(kaak) != aes.BlockSize {
		return nil, fmt.Errorf("key area key is %d bytes, want %d (AES-128)", len(kaak), aes.BlockSize)
	}
	block, err := aes.NewCipher(kaak)
	if err != nil {
		return nil, fmt.Errorf("key area key: %w", err)
	}
	out := make([]byte, NCAKeyAreaSize)
	for i, key := range keyArea {
		if len(key) != aes.BlockSize {
			return nil, fmt.Errorf("key area key %d is %d bytes, want %d", i, len(key), aes.BlockSize)
		}
		block.Encrypt(out[i*aes.BlockSize:(i+1)*aes.BlockSize], key)
	}
	return out, nil
}

// DeriveSectionKey derives the per-title section keys from titlekey
// material: the 64-byte KAEK-encrypted key area block the title carries in
// its NCA header (DecryptNCAHeader(...)[NCAKeyAreaOffset:]), AES-ECB
// decrypted under kaak. keys[NCASectionKeySlot] is the AES-CTR section
// key. Re-encrypting for a different titlekey does not need this in
// reverse — any 4 consistent keys work, so callers pick fresh ones (e.g.
// random) and feed them to EncryptKeyArea.
func DeriveSectionKey(titleKey []byte, kaak []byte) ([][]byte, error) {
	if len(titleKey) != NCAKeyAreaSize {
		return nil, fmt.Errorf("title key block is %d bytes, want %d (the encrypted key area)", len(titleKey), NCAKeyAreaSize)
	}
	return DecryptKeyArea(titleKey, kaak)
}

// ReencryptNCA streams the NCA in r to w with its sections re-keyed: every
// byte outside the listed sections (header, gaps, tail) is copied verbatim,
// while each section is AES-CTR decrypted under oldKey and re-encrypted
// under newKey using the same counter. oldKey and newKey are plaintext
// 16-byte section keys (DecryptKeyArea yields the old one as
// keys[NCASectionKeySlot]; fresh keys replace it).
//
// The per-section counter mirrors hactool's nca_update_ctr: the absolute
// byte offset in 0x10-byte blocks, big-endian, filling the low half of the
// IV (verified byte-exact against retail sections — the PFS0 partition of
// the Dead Cells cnmt NCAs decrypts under exactly this convention). The
// high half stays zero, matching every non-BKTR retail section; BKTR
// subsection counters are not modelled. Sections must be listed in
// ascending, non-overlapping order.
func ReencryptNCA(r io.ReadSeeker, w io.Writer, oldKey, newKey []byte, sectionOffsets, sectionSizes []int64) error {
	if len(sectionOffsets) != len(sectionSizes) {
		return fmt.Errorf("%d section offsets but %d sizes", len(sectionOffsets), len(sectionSizes))
	}
	for _, key := range [][]byte{oldKey, newKey} {
		if len(key) != aes.BlockSize {
			return fmt.Errorf("section key is %d bytes, want %d (AES-128)", len(key), aes.BlockSize)
		}
	}
	var pos int64
	for i := range sectionOffsets {
		off, size := sectionOffsets[i], sectionSizes[i]
		if off < 0 || size < 0 {
			return fmt.Errorf("section %d: negative offset/size (%d, %d)", i, off, size)
		}
		if off < pos {
			return fmt.Errorf("section %d at %d overlaps the previous section ending at %d", i, off, pos)
		}
		if err := copySpan(w, r, off-pos); err != nil {
			return err
		}
		if err := reencryptSpan(r, w, oldKey, newKey, sectionCounter(off), size); err != nil {
			return fmt.Errorf("section %d (%d bytes at %d): %w", i, size, off, err)
		}
		pos = off + size
	}
	_, err := io.Copy(w, r)
	return err
}

// copySpan streams exactly n untouched bytes from r to w; a short r fails.
func copySpan(w io.Writer, r io.Reader, n int64) error {
	_, err := io.CopyN(w, r, n)
	return err
}

// reencryptSpan transforms size bytes of one section: it XORs the chunk
// stream with the old key's CTR keystream, then the new key's (CTR is
// symmetric, so decrypt-then-reencrypt is two keystream XORs under the
// same counter). Both streamers keep their block position across chunks.
func reencryptSpan(r io.Reader, w io.Writer, oldKey, newKey, iv []byte, size int64) error {
	oldBlock, err := aes.NewCipher(oldKey)
	if err != nil {
		return fmt.Errorf("old section key: %w", err)
	}
	newBlock, err := aes.NewCipher(newKey)
	if err != nil {
		return fmt.Errorf("new section key: %w", err)
	}
	oldCtr := cipher.NewCTR(oldBlock, iv)
	newCtr := cipher.NewCTR(newBlock, iv)
	buf := make([]byte, reencryptChunk)
	for size > 0 {
		chunk := buf
		if size < int64(len(chunk)) {
			chunk = chunk[:size]
		}
		if _, err := io.ReadFull(r, chunk); err != nil {
			return fmt.Errorf("reading %d bytes: %w", len(chunk), err)
		}
		oldCtr.XORKeyStream(chunk, chunk)
		newCtr.XORKeyStream(chunk, chunk)
		if _, err := w.Write(chunk); err != nil {
			return fmt.Errorf("writing %d bytes: %w", len(chunk), err)
		}
		size -= int64(len(chunk))
	}
	return nil
}

// sectionCounter builds the 16-byte AES-CTR IV for the NCA section at the
// given absolute byte offset: the offset in 0x10-byte units, big-endian,
// filling the low half of the block.
func sectionCounter(offset int64) []byte {
	iv := make([]byte, aes.BlockSize)
	binary.BigEndian.PutUint64(iv[8:], uint64(offset)>>4)
	return iv
}

// NCAMediaUnit is the media-unit granularity of NCA section table entries.
const NCAMediaUnit = 0x200

// NCASection describes one encrypted section span inside an NCA.
type NCASection struct {
	Offset int64 // absolute byte offset within the NCA
	Size   int64 // byte size
}

// ParseNCASections reads the section entry table from a decrypted NCA
// header (the 0x200-byte plaintext returned by DecryptNCAHeader) and
// returns the non-empty sections in ascending offset order. Entry i at
// header +0x40+i*8 holds u32 media start/end (NOT start/size): for the
// last section of every retail NCA examined, end*0x200 equals the exact
// file size. Unused slots carry sentinels such as {1,0} or {0,0}; valid
// sections require end > start and start >= 2 (a section cannot begin
// before the 0x400-byte NCA header ends).
func ParseNCASections(plainHeader []byte) []NCASection {
	var out []NCASection
	for i := range 4 {
		base := 0x40 + i*8
		start := binary.LittleEndian.Uint32(plainHeader[base:])
		end := binary.LittleEndian.Uint32(plainHeader[base+4:])
		if end <= start || start < 2 {
			continue
		}
		out = append(out, NCASection{
			Offset: int64(start) * NCAMediaUnit,
			Size:   int64(end-start) * NCAMediaUnit,
		})
	}
	sort.Slice(out, func(a, b int) bool { return out[a].Offset < out[b].Offset })
	return out
}

// KAAKName returns the prod.keys key name for the key-area key matching
// kaakIndex (NCA header +0x07: 0=application, 1=ocean, 2=system) and the
// master-key generation (crypto type). Generation indexing follows the
// same convention as DecryptKeyArea callers: master_key_XX where
// XX = max(crypto_type, crypto_type2) - 1, floored at 0.
func KAAKName(kaakIndex byte, cryptoType, cryptoType2 byte) string {
	kind := map[byte]string{0: "application", 1: "ocean", 2: "system"}[kaakIndex]
	if kind == "" {
		kind = "application"
	}
	gen := cryptoType
	if cryptoType2 > gen {
		gen = cryptoType2
	}
	if gen > 0 {
		gen--
	}
	return fmt.Sprintf("key_area_key_%s_%02d", kind, gen)
}
