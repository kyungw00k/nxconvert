package nxformat

import (
	"crypto/rand"
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
	// Card capacity code must cover the new content (thresholds mirror
	// NSC_BUILDER's getGCsize: >=4GiB -> 0xE0 8GB card, >=2 -> 0xF0,
	// >=1 -> 0xF8, else 0xFA). The donor's code fits only donor content.
	hdr[0x10D] = GamecardSizeCode(total)

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

// GamecardSizeCode maps a total image size to the RomSize header byte
// (gamecard header +0x0D), choosing the smallest standard capacity that
// covers the content. Thresholds mirror NSC_BUILDER's getGCsize.
func GamecardSizeCode(total int64) byte {
	const GB = 1 << 30
	switch {
	case total >= 32*GB:
		return 0xE3 // 64GB
	case total >= 16*GB:
		return 0xE2 // 32GB
	case total >= 8*GB:
		return 0xE1 // 16GB
	case total >= 4*GB:
		return 0xE0 // 8GB
	case total >= 2*GB:
		return 0xF0 // 4GB
	case total >= 1*GB:
		return 0xF8 // 2GB
	default:
		return 0xFA // 1GB
	}
}

// NSC_BUILDER-compatible XCI writer — the layout the MIG flashcart is
// empirically verified to accept (constants mirrored from NSC_BUILDER's
// writer via the nscb_rust reference port):
//
//	0x0000  0x100 random RSA-signature filler
//	0x0100  HEAD + fields: secure page @0x104, card size @0x10D,
//	        constant PackageId @0x110 (BE 0x8750F4C0A9C5A966),
//	        valid-data-end @0x118, constant IV @0x120,
//	        root offset/size/hash @0x130/0x138/0x140
//	0x0160  constant InitialDataHash (the MIG does not check it against
//	        the external Initial Data bin)
//	0x0180  secureMode=1, titleKeyFlag=2, keyFlag=0, normal end @0x18C
//	0x0190  0x70 constant game-info block (two variants by 4GiB size)
//	0x0200  0x6E00 zero padding
//	0x7000  0x8000 0xFF filler (certificate area unused)
//	0xF000  root HFS0: update(0x200 empty) normal(0x200 empty) secure
//	0xF600  secure partition (media aligned)
//
// NCA entries keep their original filenames; each secure entry hash is
// the SHA-256 of the (patched) NCA's first 0x200 bytes.
func WriteXCINSC(w io.Writer, files []NamedReader) error {
	secure, err := prepareHFS0(files)
	if err != nil {
		return err
	}
	defer secure.close()

	empty := emptyPartitionHeader()
	emptyHash := sha256.Sum256(empty[:])

	root := make([]byte, rootPartitionSize)
	copy(root[0:4], hfs0Magic)
	put32(root[4:], 3)
	put32(root[8:], rootPartitionSize-hfs0HeaderSize-3*hfs0EntrySize)
	copy(root[hfs0HeaderSize+3*hfs0EntrySize:], "update\x00normal\x00secure\x00")
	putHFS0Entry(root[hfs0HeaderSize:], updatePartitionOff, emptyPartitionSize, 0, emptyPartitionSize, emptyHash)
	putHFS0Entry(root[hfs0HeaderSize+hfs0EntrySize:], normalPartitionOff, emptyPartitionSize, uint32(len("update")+1), emptyPartitionSize, emptyHash)
	// Secure entry: hashed region is the FULL secure header (uncapped),
	// matching NSC_BUILDER's gen_rhfs0_head.
	secureHash := sha256.Sum256(secure.header)
	putHFS0Entry(root[secureEntryBase:], securePartitionOff, secure.totalSize, secureNameOff, int64(len(secure.header)), secureHash)

	secureOffset := gamecardRootOffset + int64(rootPartitionSize) + 2*emptyPartitionSize
	if secureOffset%NCAMediaUnit != 0 {
		return fmt.Errorf("nxformat: secure offset %#x not media aligned", secureOffset)
	}
	total := secureOffset + secure.totalSize

	hdr := make([]byte, 0x190)
	// Random signature filler — the MIG does not verify it.
	if _, err := rand.Read(hdr[0:0x100]); err != nil {
		return fmt.Errorf("nxformat: signature filler: %w", err)
	}
	copy(hdr[0x100:0x104], "HEAD")
	put32(hdr[0x104:], int64(secureOffset/NCAMediaUnit))
	put32(hdr[0x108:], 0xFFFFFFFF) // backup area
	hdr[0x10C] = 0x00              // kek index
	hdr[0x10D] = GamecardSizeCode(total)
	hdr[0x10E] = 0x00                                           // header version
	hdr[0x10F] = 0x00                                           // flags
	binary.BigEndian.PutUint64(hdr[0x110:], 0x8750F4C0A9C5A966) // constant PackageId
	put64(hdr[0x118:], (total+NCAMediaUnit-1)/NCAMediaUnit-1)   // valid data end
	binary.BigEndian.PutUint32(hdr[0x120:], 0x5B408B14)         // constant IV
	binary.BigEndian.PutUint32(hdr[0x124:], 0x5E277E81)
	binary.BigEndian.PutUint32(hdr[0x128:], 0xE5BF677C)
	binary.BigEndian.PutUint32(hdr[0x12C:], 0x94888D7B)
	put64(hdr[0x130:], gamecardRootOffset)
	put64(hdr[0x138:], int64(rootPartitionSize))
	copy(hdr[0x140:], func() []byte { h := sha256.Sum256(root); return h[:] }())
	copy(hdr[0x160:], []byte{
		0x1A, 0xB7, 0xC7, 0xB2, 0x63, 0xE7, 0x4E, 0x44, 0xCD, 0x3C, 0x68, 0xE4, 0x0F, 0x7E,
		0xF4, 0xA4, 0xD6, 0x57, 0x15, 0x51, 0xD0, 0x43, 0xFC, 0xA8, 0xEC, 0xF5, 0xC4, 0x89,
		0xF2, 0xC6, 0x6E, 0x7E,
	}) // constant InitialDataHash
	put32(hdr[0x180:], 1) // secureMode
	put32(hdr[0x184:], 2) // titleKeyFlag
	put32(hdr[0x188:], 0) // keyFlag
	put32(hdr[0x18C:], secureOffset/NCAMediaUnit)

	gameInfo := nscGameInfoSmall
	if total >= 4<<30 {
		gameInfo = nscGameInfoLarge
	}

	certFF := make([]byte, 0x8000)
	for i := range certFF {
		certFF[i] = 0xFF
	}
	blocks := [][]byte{hdr, gameInfo[:], make([]byte, 0x6E00), certFF, root, empty[:], empty[:], secure.header}
	for _, part := range blocks {
		if _, err := w.Write(part); err != nil {
			return fmt.Errorf("nxformat: writing xci block: %w", err)
		}
	}
	if err := secure.copyData(w); err != nil {
		return fmt.Errorf("nxformat: writing secure data: %w", err)
	}
	return nil
}

// NSC_BUILDER's fixed game-info blocks (0x70 bytes at file offset 0x190),
// selected by whether the image reaches 4 GiB.
var nscGameInfoLarge = [0x70]byte{
	0x92, 0x98, 0xF3, 0x50, 0x88, 0xF0, 0x9F, 0x7D, 0xA8, 0x9A, 0x60, 0xD4, 0xCB, 0xA6, 0xF9, 0x6F,
	0xA4, 0x5B, 0xB6, 0xAC, 0xAB, 0xC7, 0x51, 0xF9, 0x5D, 0x39, 0x87, 0x42, 0x6B, 0x38, 0xC3, 0xF2,
	0x10, 0xDA, 0x0B, 0x70, 0x0E, 0x5E, 0xCE, 0x29, 0xA1, 0x3C, 0xBE, 0x1D, 0xA6, 0xD0, 0x52, 0xCB,
	0xF2, 0x08, 0x7C, 0xE9, 0xAF, 0x59, 0x05, 0x38, 0x57, 0x0D, 0x78, 0xB9, 0xCD, 0xD2, 0x7F, 0xBE,
	0xB4, 0xA0, 0xAC, 0x2A, 0xDF, 0xF9, 0xBA, 0x77, 0x75, 0x4D, 0xD6, 0x67, 0x5A, 0xC7, 0x62, 0x23,
	0x50, 0x6B, 0x3B, 0xDA, 0xBC, 0xB2, 0xE2, 0x12, 0xFA, 0x46, 0x51, 0x11, 0xAB, 0x7D, 0x51, 0xAF,
	0xC8, 0xB5, 0xB2, 0xB2, 0x1C, 0x4B, 0x3F, 0x40, 0x65, 0x45, 0x98, 0x62, 0x02, 0x82, 0xAD, 0xD6,
}

var nscGameInfoSmall = [0x70]byte{
	0x91, 0x09, 0xFF, 0x82, 0x97, 0x1E, 0xE9, 0x93, 0x50, 0x11, 0xCA, 0x06, 0x3F, 0x3C, 0x4D, 0x87,
	0xA1, 0x3D, 0x28, 0xA9, 0x92, 0x8D, 0x74, 0xF1, 0x49, 0x91, 0x9E, 0xB7, 0x82, 0xE1, 0xF0, 0xCF,
	0xE4, 0xA5, 0xA3, 0xBD, 0xF9, 0x78, 0x29, 0x5C, 0xD5, 0x26, 0x39, 0xA4, 0x99, 0x1B, 0xDB, 0x1F,
	0xED, 0x84, 0x17, 0x79, 0xA3, 0xF8, 0x5D, 0x23, 0xAA, 0x42, 0x42, 0x13, 0x56, 0x16, 0xF5, 0x18,
	0x7C, 0x03, 0xCF, 0x0D, 0x97, 0xE5, 0xD2, 0x18, 0xFD, 0xB2, 0x45, 0x38, 0x1F, 0xD1, 0xCF, 0x8D,
	0xFB, 0x79, 0x6F, 0xBE, 0xDA, 0x4B, 0xF7, 0xF7, 0xD6, 0xB1, 0x28, 0xCE, 0x89, 0xBC, 0x9E, 0xAA,
	0x85, 0x52, 0xD4, 0x2F, 0x59, 0x7C, 0x5D, 0xB8, 0x66, 0xC6, 0x7B, 0xB0, 0xDD, 0x8E, 0xEA, 0x11,
}
