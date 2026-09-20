package nxformat

import (
	"encoding/binary"
	"fmt"
	"io"

	"github.com/klauspost/compress/zstd"
)

// NCZ layout, verified byte-exact against a retail NSZ (SIGNALIS):
//
//	0x0000  the first 0x4000 bytes of the original NCA, stored uncompressed
//	0x4000  'NCZSECTN'
//	0x4008  u64 sectionCount
//	0x4010  section table, 0x40 bytes per entry:
//	          u64 offset          (position in the decompressed NCA)
//	          u64 size            (decompressed section size)
//	          u64 cryptoType      (3 = AES-CTR; informational)
//	          u64 relativeOffset  (0)
//	          16-byte IV          (titlekey-derived; informational)
//	          16 bytes reserved (0)
//	then    a single continuous zstd stream holding the decompressed NCA
//	        body (0x4000 .. end). Sections tile that range contiguously.
//
// Decompression needs none of the crypto fields: the NCZ body is already
// decrypted, so only offset/size (to size the output) matter.
const (
	nczHeaderSize        = 0x4000 // NCA header kept uncompressed at the front
	nczSectionMagic      = "NCZSECTN"
	nczSectionHeaderSize = 0x10    // magic + u64 section count
	nczSectionEntrySize  = 0x40    // bytes per section-table entry
	maxNCZSections       = 1 << 16 // sanity cap; retail files use ~200
)

// NCZSection describes one entry of an .ncz section table.
type NCZSection struct {
	Offset         uint64 // position in the decompressed NCA
	Size           uint64 // decompressed section size
	CryptoType     uint64 // 3 = AES-CTR; informational
	RelativeOffset uint64
	IV             [16]byte // titlekey-derived; informational
}

// ParseNCZHeader reads the NCZ section header at 0x4000 in an .ncz file,
// returning the section table and the offset where the compressed zstd
// body starts.
func ParseNCZHeader(r io.ReaderAt) ([]NCZSection, int64, error) {
	var hdr [nczSectionHeaderSize]byte
	if _, err := r.ReadAt(hdr[:], nczHeaderSize); err != nil {
		return nil, 0, fmt.Errorf("nxformat: reading NCZ section header at %#x: %w", nczHeaderSize, err)
	}
	if string(hdr[0:8]) != nczSectionMagic {
		return nil, 0, fmt.Errorf("nxformat: NCZ section magic not found at %#x (is this an .ncz file?)", nczHeaderSize)
	}
	count := binary.LittleEndian.Uint64(hdr[8:16])
	if count > maxNCZSections {
		return nil, 0, fmt.Errorf("nxformat: NCZ section count %d exceeds cap %d", count, maxNCZSections)
	}

	table := make([]byte, int64(count)*nczSectionEntrySize)
	if _, err := r.ReadAt(table, nczHeaderSize+nczSectionHeaderSize); err != nil {
		return nil, 0, fmt.Errorf("nxformat: reading NCZ section table: %w", err)
	}

	sections := make([]NCZSection, count)
	for i := range sections {
		e := table[i*nczSectionEntrySize:]
		s := &sections[i]
		s.Offset = binary.LittleEndian.Uint64(e[0:8])
		s.Size = binary.LittleEndian.Uint64(e[8:16])
		s.CryptoType = binary.LittleEndian.Uint64(e[16:24])
		s.RelativeOffset = binary.LittleEndian.Uint64(e[24:32])
		copy(s.IV[:], e[32:48])
	}

	compressedStart := int64(nczHeaderSize + nczSectionHeaderSize + int(count)*nczSectionEntrySize)
	return sections, compressedStart, nil
}

// DecompressedNCASize returns the total decompressed NCA size implied by the
// section table: the end of the last section. Sections tile the NCA
// contiguously from 0x4000 (verified against retail files), so that is the
// full NCA size.
func DecompressedNCASize(sections []NCZSection) int64 {
	if len(sections) == 0 {
		return 0
	}
	last := sections[len(sections)-1]
	return int64(last.Offset + last.Size)
}

// DecompressNCZ streams the .ncz in r out to w as its original .nca: the
// leading 0x4000-byte NCA header is copied as-is and the zstd stream after
// the section table is decompressed as the NCA body.
func DecompressNCZ(r io.ReaderAt, w io.Writer) error {
	_, compressedStart, err := ParseNCZHeader(r)
	if err != nil {
		return err
	}

	if _, err := io.CopyN(w, io.NewSectionReader(r, 0, nczHeaderSize), nczHeaderSize); err != nil {
		return fmt.Errorf("nxformat: copying NCA header: %w", err)
	}

	zr, err := zstd.NewReader(io.NewSectionReader(r, compressedStart, 1<<62-1))
	if err != nil {
		return fmt.Errorf("nxformat: zstd: %w", err)
	}
	defer zr.Close()
	if _, err := io.Copy(w, zr); err != nil {
		return fmt.Errorf("nxformat: decompressing NCA body: %w", err)
	}
	return nil
}
