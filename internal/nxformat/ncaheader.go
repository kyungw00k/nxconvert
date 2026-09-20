package nxformat

import (
	"crypto/aes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"strings"
)

// ParseProdKeys reads a "key = hexvalue" prod.keys file (the format emitted
// by Lockpick / Lockpick_RCM and consumed by hactool, Ryujinx, yuzu, ...).
// Only well-formed hex lines are returned; comments and blanks are skipped.
func ParseProdKeys(r io.Reader) (map[string][]byte, error) {
	keys := make(map[string][]byte)
	data, err := io.ReadAll(io.LimitReader(r, 4<<20))
	if err != nil {
		return nil, err
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") || !strings.Contains(line, "=") {
			continue
		}
		name, val, _ := strings.Cut(line, "=")
		val = strings.TrimSpace(val)
		b, err := hexDecode(val)
		if err != nil || len(b) == 0 {
			continue
		}
		keys[strings.TrimSpace(name)] = b
	}
	return keys, nil
}

func hexDecode(s string) ([]byte, error) {
	if len(s)%2 != 0 {
		return nil, errors.New("odd length")
	}
	out := make([]byte, len(s)/2)
	for i := 0; i < len(out); i++ {
		hi, ok1 := hexVal(s[2*i])
		lo, ok2 := hexVal(s[2*i+1])
		if !ok1 || !ok2 {
			return nil, errors.New("bad hex")
		}
		out[i] = hi<<4 | lo
	}
	return out, nil
}

func hexVal(c byte) (byte, bool) {
	switch {
	case c >= '0' && c <= '9':
		return c - '0', true
	case c >= 'a' && c <= 'f':
		return c - 'a' + 10, true
	case c >= 'A' && c <= 'F':
		return c - 'A' + 10, true
	}
	return 0, false
}

// NCA header crypto constants (verified against real gamecard and CDN NCAs,
// 2026-09: region [0x200, 0x400) is AES-128-XTS with the global header_key
// and tweak value 1; the decrypted blob starts with the NCA magic).
const (
	NCAHeaderEncOffset = 0x200
	NCAHeaderEncSize   = 0x200
	XTSTweakValue      = 1
	// NCADistributionOffset is the offset of the distribution byte inside the
	// decrypted NCA header: 0x01 = gamecard, 0x00 = CDN/download.
	NCADistributionOffset = 0x04
	DistributionGamecard  = 0x01
	DistributionDownload  = 0x00
)

// xtsAES processes one XTS data unit the way Nintendo NCAs do. key must be
// 32 bytes (data key ‖ tweak key); tweak is the data-unit number, encoded
// big-endian for the initial tweak block. The GF(2^128) multiplier is
// x^128 + x^7 + x^2 + x + 1 (0x87) with the tweak treated as a little-
// endian 128-bit integer: the carry propagates toward byte 15 and the
// reduction constant lands in byte 0 (verified against retail gamecard and
// CDN NCA headers — with it, the decrypted ProgramId at +0x10, RightsId,
// and FsEntry table all read correctly; with the standard IEEE byte order
// every block past the first of each unit decrypts to garbage).
func xtsAES(key []byte, tweak uint64, data []byte, decrypt bool) ([]byte, error) {
	if len(key) != 32 {
		return nil, fmt.Errorf("xts: key must be 32 bytes, got %d", len(key))
	}
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("xts: data must be 16-byte aligned, got %d", len(data))
	}
	k2, err := aes.NewCipher(key[16:])
	if err != nil {
		return nil, err
	}
	var tweakBuf [16]byte
	binary.BigEndian.PutUint64(tweakBuf[8:], tweak)
	k2.Encrypt(tweakBuf[:], tweakBuf[:])

	k1, err := aes.NewCipher(key[:16])
	if err != nil {
		return nil, err
	}
	out := make([]byte, len(data))
	var t [16]byte
	copy(t[:], tweakBuf[:])
	for i := 0; i < len(data); i += 16 {
		var x, y [16]byte
		for j := 0; j < 16; j++ {
			x[j] = data[i+j] ^ t[j]
		}
		if decrypt {
			k1.Decrypt(y[:], x[:])
		} else {
			k1.Encrypt(y[:], x[:])
		}
		for j := 0; j < 16; j++ {
			out[i+j] = y[j] ^ t[j]
		}
		// t = t * x in GF(2^128), little-endian integer convention.
		carry := t[15] >> 7
		var next [16]byte
		next[0] = t[0] << 1
		for j := 1; j < 16; j++ {
			next[j] = t[j]<<1 | t[j-1]>>7
		}
		if carry == 1 {
			next[0] ^= 0x87
		}
		t = next
	}
	return out, nil
}

// DecryptNCAHeader decrypts the encrypted NCA header region of the first
// 0x400 bytes in hdr using header_key, returning the 0x200-byte plaintext.
func DecryptNCAHeader(hdr []byte, headerKey []byte) ([]byte, error) {
	if len(hdr) < NCAHeaderEncOffset+NCAHeaderEncSize {
		return nil, fmt.Errorf("nca header: need at least 0x400 bytes, got %#x", len(hdr))
	}
	return xtsAES(headerKey, XTSTweakValue, hdr[NCAHeaderEncOffset:NCAHeaderEncOffset+NCAHeaderEncSize], true)
}

// EncryptNCAHeader re-encrypts a decrypted header region back into place.
func EncryptNCAHeader(hdr, plain, headerKey []byte) error {
	enc, err := xtsAES(headerKey, XTSTweakValue, plain, false)
	if err != nil {
		return err
	}
	copy(hdr[NCAHeaderEncOffset:], enc)
	return nil
}

// FlipDistribution rewrites the distribution byte of the NCA whose first
// 0x400 bytes are in hdr, setting it to want (0x01 gamecard / 0x00 CDN).
// It returns the mutated header and true if a change was made. The NCA
// magic is verified after decryption — a wrong key fails loudly here.
func FlipDistribution(hdr []byte, headerKey []byte, want byte) ([]byte, bool, error) {
	plain, err := DecryptNCAHeader(hdr, headerKey)
	if err != nil {
		return nil, false, err
	}
	magic := string(plain[:4])
	if magic != "NCA3" && magic != "NCA2" {
		return nil, false, fmt.Errorf("nca header: decrypted magic %q — wrong header_key?", magic)
	}
	if plain[NCADistributionOffset] == want {
		return hdr, false, nil
	}
	plain[NCADistributionOffset] = want
	if err := EncryptNCAHeader(hdr, plain, headerKey); err != nil {
		return nil, false, err
	}
	return hdr, true, nil
}

// DistributionFlippingReader wraps an NCA stream, transparently rewriting
// the distribution byte of the first 0x400 bytes (the rest passes through
// unchanged). Content hashes and nca_ids are unaffected — they cover the
// NCA body only, excluding this header.
type DistributionFlippingReader struct {
	r          io.Reader
	header     [0x400]byte
	patched    []byte // nil until the patched header is fully served
	served     int    // bytes served from patched
	headerDone bool
	want       byte
	key        []byte
	err        error
}

// NewDistributionFlipper returns a reader serving r with its NCA
// distribution byte set to want. headerKey is the global prod.keys
// header_key.
func NewDistributionFlipper(r io.Reader, headerKey []byte, want byte) io.Reader {
	return &DistributionFlippingReader{r: r, want: want, key: headerKey}
}

func (d *DistributionFlippingReader) Read(p []byte) (int, error) {
	if d.err != nil {
		return 0, d.err
	}
	if !d.headerDone {
		if _, err := io.ReadFull(d.r, d.header[:]); err != nil {
			d.err = err
			return 0, err
		}
		hdr, _, err := FlipDistribution(d.header[:], d.key, d.want)
		if err != nil {
			d.err = err
			return 0, err
		}
		copy(d.header[:], hdr)
		d.patched = d.header[:]
		d.headerDone = true
	}
	if d.served < len(d.patched) {
		n := copy(p, d.patched[d.served:])
		d.served += n
		return n, nil
	}
	return d.r.Read(p)
}

// PatchDistribution returns a seekable reader serving r with the NCA
// distribution byte (of the first 0x400 header bytes) set to want; the
// remainder of r passes through untouched. Non-NCA entries (a .tik or .cert
// sharing the container) must not be routed here — the magic check fails.
func PatchDistribution(r io.ReadSeeker, headerKey []byte, want byte) (io.ReadSeeker, byte, error) {
	var head [0x400]byte
	if _, err := io.ReadFull(r, head[:]); err != nil {
		return nil, 0, err
	}
	plain, err := DecryptNCAHeader(head[:], headerKey)
	if err != nil {
		return nil, 0, err
	}
	was := plain[NCADistributionOffset]
	hdr, _, err := FlipDistribution(head[:], headerKey, want)
	if err != nil {
		return nil, 0, err
	}
	return &patchedReader{frontData: hdr[:0x400], tail: r, tailBase: 0x400}, was, nil
}

// patchedReader serves the patched 0x400-byte header then the tail of the
// original reader from tailBase, implementing Seek across the seam.
type patchedReader struct {
	frontData []byte
	tail      io.ReadSeeker
	tailBase  int64
	off       int64
}

func (p *patchedReader) Read(buf []byte) (int, error) {
	if p.off < 0 {
		return 0, fmt.Errorf("patchedReader: negative offset")
	}
	if p.off < int64(len(p.frontData)) {
		n := copy(buf, p.frontData[p.off:])
		p.off += int64(n)
		return n, nil
	}
	if _, err := p.tail.Seek(p.tailBase+p.off-int64(len(p.frontData)), io.SeekStart); err != nil {
		return 0, err
	}
	n, err := p.tail.Read(buf)
	p.off += int64(n)
	return n, err
}

func (p *patchedReader) Seek(off int64, whence int) (int64, error) {
	var abs int64
	switch whence {
	case io.SeekStart:
		abs = off
	case io.SeekCurrent:
		abs = p.off + off
	case io.SeekEnd:
		return 0, fmt.Errorf("patchedReader: SeekEnd unsupported")
	default:
		return 0, fmt.Errorf("patchedReader: bad whence %d", whence)
	}
	if abs < 0 {
		return 0, fmt.Errorf("patchedReader: negative seek")
	}
	p.off = abs
	return abs, nil
}
