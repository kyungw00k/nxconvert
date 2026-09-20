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
