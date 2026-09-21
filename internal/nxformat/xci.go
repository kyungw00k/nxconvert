package nxformat

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
)

// XCI (gamecard image) layout, verified byte-exact against a retail dump:
//
//	0x0000  RSA-2048 signature (garbage on dumps; copied from template)
//	0x0100  gamecard header, 'HEAD' magic at 0x100. Fields relevant to
//	        conversion: u32 @0x104 = 0x7B (secure partition start page,
//	        0xF600/0x200), u32 @0x108 = 0xFFFFFFFF, u64 @0x118 = index of
//	        the last valid page, (totalSize-1)/0x200, u32 @0x130 = 0xF000
//	        (root offset), u32 @0x138 = 0x200. The remaining bytes are
//	        per-card identity/encrypted data and are copied verbatim from
//	        the template.
//	0xF000  root HFS0 with entries "update", "normal", "secure"; its
//	        string table is zero-padded to a 0x200-byte header
//	0xF200  update partition: a bare 0x200-byte empty HFS0 header
//	0xF400  normal partition: identical to update
//	0xF600  secure partition: HFS0 holding the NCA files
//
// Root entry hashes cover each partition's first hashedRegionSize bytes:
// 0x200 for update/normal (their full size) and the secure partition's
// full header size for secure (0x400 in the verified retail dump).
const (
	gamecardHeaderSize = 0xF000
	gamecardRootOffset = 0xF000

	rootPartitionSize  = 0x200 // fixed: 0x10 + 3*0x40 entries + string table padded to 0x200
	emptyPartitionSize = 0x200 // update/normal are bare empty HFS0 headers
	updatePartitionOff = 0     // relative to root data area
	normalPartitionOff = emptyPartitionSize
	securePartitionOff = 2 * emptyPartitionSize

	xciPageSize     = 0x200
	xciLastPageOff  = 0x118 // u64: index of the last valid page
	xciRootHashOff  = 0x140 // SHA-256 of the root HFS0 header's first 0x200 bytes
	secureNameOff   = 0x0E  // "update\0normal\0" precedes "secure" in the root string table
	secureEntryBase = 0x10 + 2*hfs0EntrySize
)

// ParseXCI walks the root HFS0 at the fixed gamecard offset 0xF000 and
// returns the secure partition's file entries. secureBase is the absolute
// offset of the secure partition's data area, so each entry's bytes live at
// secureBase + entry.Offset.
func ParseXCI(r io.ReaderAt) ([]FileEntry, int64, error) {
	root, rootHeaderSize, err := ParseHFS0(r, gamecardRootOffset)
	if err != nil {
		return nil, 0, fmt.Errorf("nxformat: XCI root partition: %w", err)
	}
	var secure *FileEntry
	for i := range root {
		if root[i].Name == "secure" {
			secure = &root[i]
			break
		}
	}
	if secure == nil {
		return nil, 0, fmt.Errorf("nxformat: XCI root partition has no %q entry", "secure")
	}
	partBase := gamecardRootOffset + rootHeaderSize + secure.Offset
	entries, headerSize, err := ParseHFS0(r, partBase)
	if err != nil {
		return nil, 0, fmt.Errorf("nxformat: XCI secure partition: %w", err)
	}
	return entries, partBase + headerSize, nil
}

// WriteXCI streams a complete XCI image to w: the template gamecard header,
// the root HFS0 with empty update/normal partitions, and files as the
// secure partition (written exactly as WriteHFS0 would).
//
// The only template field patched is the u64 at 0x118, the index of the
// last valid page, recomputed as (totalSize-1)/0x200 for the new image
// (verified byte-exact against a retail dump). Everything else in the
// 0xF000-byte header is copied verbatim, so callers are expected to pass a
// known-good template (or zeros); a zero header parses fine.
func WriteXCI(w io.Writer, gamecardHeader [gamecardHeaderSize]byte, files []NamedReader) error {
	secure, err := prepareHFS0(files)
	if err != nil {
		return err
	}
	defer secure.close()

	total := gamecardHeaderSize + rootPartitionSize + 2*emptyPartitionSize + secure.totalSize
	binary.LittleEndian.PutUint64(gamecardHeader[xciLastPageOff:], uint64((total-1)/xciPageSize))

	root := make([]byte, rootPartitionSize)
	copy(root[0:4], hfs0Magic)
	put32(root[4:], 3)
	put32(root[8:], rootPartitionSize-hfs0HeaderSize-3*hfs0EntrySize) // padded string table
	copy(root[hfs0HeaderSize+3*hfs0EntrySize:], "update\x00normal\x00secure\x00")

	empty := emptyPartitionHeader()
	emptyHash := sha256.Sum256(empty[:])
	putHFS0Entry(root[hfs0HeaderSize+0*hfs0EntrySize:], updatePartitionOff, emptyPartitionSize, 0, emptyPartitionSize, emptyHash)
	putHFS0Entry(root[hfs0HeaderSize+1*hfs0EntrySize:], normalPartitionOff, emptyPartitionSize, uint32(len("update")+1), emptyPartitionSize, emptyHash)
	// The secure entry's hash covers the partition's own header, exactly
	// like the retail dump (hashed region = secure header size there).
	secureHash := sha256.Sum256(secure.header)
	putHFS0Entry(root[secureEntryBase:], securePartitionOff, secure.totalSize, secureNameOff, int64(len(secure.header)), secureHash)
	if _, err := w.Write(gamecardHeader[:]); err != nil {
		return fmt.Errorf("nxformat: writing gamecard header: %w", err)
	}
	if _, err := w.Write(root); err != nil {
		return fmt.Errorf("nxformat: writing root partition header: %w", err)
	}
	for range 2 {
		if _, err := w.Write(empty[:]); err != nil {
			return fmt.Errorf("nxformat: writing update/normal partition: %w", err)
		}
	}
	if _, err := w.Write(secure.header); err != nil {
		return fmt.Errorf("nxformat: writing secure partition header: %w", err)
	}
	return secure.copyData(w)
}

// emptyPartitionHeader returns the 0x200-byte empty HFS0 header that
// retail gamecards use for the update and normal partitions: an HFS0 with
// zero files whose string-table size pads it out to 0x200 bytes.
func emptyPartitionHeader() [emptyPartitionSize]byte {
	var b [emptyPartitionSize]byte
	copy(b[0:4], hfs0Magic)
	put32(b[8:], emptyPartitionSize-hfs0HeaderSize)
	return b
}

// putHFS0Entry writes one 0x40-byte HFS0 entry with the layout verified
// against retail dumps (hashedRegionSize u32, zero u64, SHA-256).
func putHFS0Entry(b []byte, off, size int64, nameOff uint32, hashedRegion int64, hash [sha256.Size]byte) {
	put64(b, off)
	put64(b[8:], size)
	put32(b[16:], int64(nameOff))
	put32(b[20:], hashedRegion)
	copy(b[hfs0HashOff:], hash[:])
}

// TransplantXCI writes an XCI byte-identical to the template gamecard
// image except for the secure partition, whose files are replaced. The
// template must be a real card dump: root HFS0 at 0xF000 with
// update/logo/normal/secure entries and the secure partition sitting at
// RomAreaStart. Everything before the secure partition — gamecard header,
// firmware update area, logo, normal — is copied verbatim, so the output
// preserves the card identity a flashcart or console validates. The
// root's secure entry gets the new size and header hash; the header's
// last-valid-page field is recomputed only when the total grows. tmplSize
// is the template's byte size (used to reproduce the 0xFF tail padding
// dumps carry past valid data).
func TransplantXCI(w io.Writer, template io.ReaderAt, tmplSize int64, files []NamedReader) error {
	root, rootHeaderSize, err := ParseHFS0(template, gamecardRootOffset)
	if err != nil {
		return fmt.Errorf("nxformat: template root: %w", err)
	}
	secureIdx := -1
	for i := range root {
		if root[i].Name == "secure" {
			secureIdx = i
			break
		}
	}
	if secureIdx < 0 {
		return fmt.Errorf("nxformat: template root has no secure entry")
	}
	secureBase := gamecardRootOffset + rootHeaderSize + root[secureIdx].Offset

	secure, err := prepareHFS0(files)
	if err != nil {
		return err
	}
	defer secure.close()

	// Patched gamecard header: verbatim except the last-valid-page field.
	hdr := make([]byte, gamecardHeaderSize)
	if _, err := template.ReadAt(hdr, 0); err != nil {
		return fmt.Errorf("nxformat: reading template header: %w", err)
	}
	total := secureBase + secure.totalSize
	if total > tmplSize || secure.totalSize != root[secureIdx].Size {
		binary.LittleEndian.PutUint64(hdr[xciLastPageOff:], uint64((total-1)/xciPageSize))
	}

	// Patched root: verbatim except the secure entry's size and hash.
	rootBuf := make([]byte, rootHeaderSize)
	if _, err := template.ReadAt(rootBuf, gamecardRootOffset); err != nil {
		return fmt.Errorf("nxformat: reading template root: %w", err)
	}
	eOff := hfs0HeaderSize + int64(secureIdx)*hfs0EntrySize
	put64(rootBuf[eOff+8:], secure.totalSize)
	hashed := min(int64(len(secure.header)), hfs0HashPrefix)
	put32(rootBuf[eOff+20:], hashed)
	secHash := sha256.Sum256(secure.header[:hashed])
	copy(rootBuf[eOff+hfs0HashOff:], secHash[:])

	// The gamecard header carries SHA-256 of the root HFS0 header's
	// first 0x200 bytes at +0x140 (verified against a retail dump and
	// NSC_BUILDER's writer). Patching the root invalidates it — recompute.
	rootHdrHash := sha256.Sum256(rootBuf[:min(rootHeaderSize, hfs0HashPrefix)])
	copy(hdr[xciRootHashOff:], rootHdrHash[:])

	if _, err := w.Write(hdr); err != nil {
		return fmt.Errorf("nxformat: writing gamecard header: %w", err)
	}
	if _, err := w.Write(rootBuf); err != nil {
		return fmt.Errorf("nxformat: writing root: %w", err)
	}

	// Verbatim template span from the end of the root to the secure
	// partition: firmware update data, logo, normal, and the alignment gap.
	span := secureBase - (gamecardRootOffset + rootHeaderSize)
	if span > 0 {
		if err := copyExact(w, io.NewSectionReader(template, gamecardRootOffset+rootHeaderSize, span), span, "template span"); err != nil {
			return fmt.Errorf("nxformat: copying template span: %w", err)
		}
	}

	if _, err := w.Write(secure.header); err != nil {
		return fmt.Errorf("nxformat: writing secure header: %w", err)
	}
	if err := secure.copyData(w); err != nil {
		return fmt.Errorf("nxformat: writing secure data: %w", err)
	}

	// Reproduce the dump's 0xFF tail so the image matches the card size.
	if tmplSize > total {
		pad := tmplSize - total
		buf := make([]byte, 1<<20)
		for i := range buf {
			buf[i] = 0xFF
		}
		for pad > 0 {
			n := min(int64(len(buf)), pad)
			if _, err := w.Write(buf[:n]); err != nil {
				return fmt.Errorf("nxformat: padding tail: %w", err)
			}
			pad -= n
		}
	}
	return nil
}
