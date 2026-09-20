package nxformat

import (
	"crypto/sha256"
	"encoding/binary"
	"fmt"
	"io"
	"os"
)

// HFS0 layout, verified byte-exact against a retail gamecard dump (both the
// root partition and the inner secure partition):
//
//	0x00  'HFS0'
//	0x04  u32 fileCount
//	0x08  u32 stringTableSize
//	0x0C  u32 reserved (0)
//	0x10  file entries, 0x40 bytes each:
//	        u64 dataOffset (relative to the data area)
//	        u64 dataSize
//	        u32 nameOffset (into the string table)
//	        u32 hashedRegionSize
//	        u64 0
//	        [0x20] SHA-256 of the file's first hashedRegionSize bytes
//	then the string table, then the data area at
//	0x10 + fileCount*0x40 + stringTableSize.
//
// Retail partitions zero-pad the string table so the data area starts
// 0x200-aligned; WriteHFS0 reproduces that padding.
const (
	hfs0Magic      = "HFS0"
	hfs0HeaderSize = 0x10
	hfs0EntrySize  = 0x40
	hfs0HashOff    = 0x20 // SHA-256 offset within an entry
	// hfs0DataAlign is the data-area alignment retail partitions use.
	hfs0DataAlign = 0x200
	// hfs0HashPrefix is the hashed region size retail gamecards use for
	// content entries: only each NCA's first 0x200 bytes (its crypto
	// header) are hashed. This is also what keeps hashedRegionSize inside
	// its u32 field, which the full size of a multi-gigabyte NCA is not.
	// For files of at most 0x200 bytes the hash therefore covers the
	// entire file.
	hfs0HashPrefix = 0x200
)

// ParseHFS0 parses the HFS0 header whose superblock starts at absolute
// offset base in r. The returned headerSize is the distance from base to
// the partition's data area, i.e. the base that entry offsets are relative
// to.
func ParseHFS0(r io.ReaderAt, base int64) ([]FileEntry, int64, error) {
	var hdr [hfs0HeaderSize]byte
	if _, err := r.ReadAt(hdr[:], base); err != nil {
		return nil, 0, fmt.Errorf("nxformat: reading HFS0 header at %#x: %w", base, err)
	}
	if string(hdr[0:4]) != hfs0Magic {
		return nil, 0, fmt.Errorf("nxformat: bad HFS0 magic %q at %#x", hdr[0:4], base)
	}
	count := binary.LittleEndian.Uint32(hdr[4:8])
	strSize := binary.LittleEndian.Uint32(hdr[8:12])
	if err := checkHeaderShape(int64(count), int64(strSize), hfs0EntrySize); err != nil {
		return nil, 0, err
	}

	table := make([]byte, int64(count)*hfs0EntrySize+int64(strSize))
	if _, err := r.ReadAt(table, base+hfs0HeaderSize); err != nil {
		return nil, 0, fmt.Errorf("nxformat: reading HFS0 table at %#x: %w", base, err)
	}

	strBase := int64(count) * hfs0EntrySize
	entries := make([]FileEntry, 0, count)
	for i := range int64(count) {
		e := i * hfs0EntrySize
		off := int64(binary.LittleEndian.Uint64(table[e:]))
		size := int64(binary.LittleEndian.Uint64(table[e+8:]))
		if off < 0 || size < 0 {
			return nil, 0, fmt.Errorf("nxformat: HFS0 entry %d: implausible offset/size", i)
		}
		name, err := nameAt(table[strBase:], binary.LittleEndian.Uint32(table[e+16:]))
		if err != nil {
			return nil, 0, fmt.Errorf("nxformat: HFS0 entry %d: %w", i, err)
		}
		entries = append(entries, FileEntry{Name: name, Size: size, Offset: off})
	}
	return entries, hfs0HeaderSize + int64(count)*hfs0EntrySize + int64(strSize), nil
}

// hfs0Partition is a fully prepared partition: its complete header bytes
// (including the zero-padded string table) and one replay function per
// file that streams exactly that file's bytes.
type hfs0Partition struct {
	header    []byte
	totalSize int64 // len(header) + sum of file sizes
	replay    []func(io.Writer) error
	cleanups  []func()
}

func (p *hfs0Partition) close() {
	for i := len(p.cleanups) - 1; i >= 0; i-- {
		p.cleanups[i]()
	}
}

func (p *hfs0Partition) copyData(w io.Writer) error {
	for _, replay := range p.replay {
		if err := replay(w); err != nil {
			return err
		}
	}
	return nil
}

// WriteHFS0 streams an HFS0 partition to w. Each entry carries the SHA-256
// of its file's first hashedRegionSize bytes; hashedRegionSize is
// min(size, 0x200), matching retail gamecards (see hfs0HashPrefix). Files
// are stored in the given order, packed contiguously from the data area.
//
// Because the hashes precede the file data in the image, every source is
// read twice: once for its hashed prefix and once for the copy itself.
// Seekable sources (io.ReadSeeker, or io.ReaderAt, which includes
// *io.SectionReader and *os.File) are simply rewound between passes; any
// other reader is spooled to a temporary file.
func WriteHFS0(w io.Writer, files []NamedReader) error {
	p, err := prepareHFS0(files)
	if err != nil {
		return err
	}
	defer p.close()
	if _, err := w.Write(p.header); err != nil {
		return fmt.Errorf("nxformat: writing HFS0 header: %w", err)
	}
	return p.copyData(w)
}

// prepareHFS0 builds the partition header (hashing each source's prefix)
// and the per-file replay copiers, without writing anything.
func prepareHFS0(files []NamedReader) (*hfs0Partition, error) {
	strSize, err := validateNames(files)
	if err != nil {
		return nil, err
	}
	n := int64(len(files))
	headerSize := alignUp(hfs0HeaderSize+n*hfs0EntrySize+strSize, hfs0DataAlign)
	part := &hfs0Partition{header: make([]byte, headerSize)}
	ok := false
	defer func() {
		if !ok {
			part.close()
		}
	}()

	copy(part.header[0:4], hfs0Magic)
	put32(part.header[4:], n)
	put32(part.header[8:], headerSize-hfs0HeaderSize-n*hfs0EntrySize) // padded string table

	strBase := hfs0HeaderSize + n*hfs0EntrySize
	var nameOff, dataOff int64
	for i, f := range files {
		hashed := min(f.Size, hfs0HashPrefix)
		hash, replay, cleanup, err := prepareSource(f, hashed)
		if err != nil {
			return nil, err
		}
		if cleanup != nil {
			part.cleanups = append(part.cleanups, cleanup)
		}
		part.replay = append(part.replay, replay)
		e := hfs0HeaderSize + int64(i)*hfs0EntrySize
		put64(part.header[e:], dataOff)
		put64(part.header[e+8:], f.Size)
		put32(part.header[e+16:], nameOff)
		put32(part.header[e+20:], hashed)
		copy(part.header[e+hfs0HashOff:], hash[:])
		copy(part.header[strBase+nameOff:], f.Name)
		nameOff += int64(len(f.Name)) + 1
		dataOff += f.Size
	}
	part.totalSize = headerSize + dataOff
	ok = true
	return part, nil
}

// prepareSource hashes the first hashedLen bytes of f and returns a replay
// function that streams exactly f.Size bytes from the (rewound) source,
// plus an optional cleanup for the temp-file fallback.
func prepareSource(f NamedReader, hashedLen int64) (hash [sha256.Size]byte, replay func(io.Writer) error, cleanup func(), err error) {
	src, ok := f.R.(io.ReadSeeker)
	if !ok {
		if ra, ok := f.R.(io.ReaderAt); ok {
			src = io.NewSectionReader(ra, 0, f.Size)
		}
	}
	if src != nil {
		h := sha256.New()
		if hashedLen > 0 {
			if n, err := io.CopyN(h, src, hashedLen); err != nil {
				if err == io.EOF {
					return hash, nil, nil, fmt.Errorf("nxformat: file %q: hashing: source yielded %d bytes, %d declared", f.Name, n, f.Size)
				}
				return hash, nil, nil, fmt.Errorf("nxformat: file %q: hashing: %w", f.Name, err)
			}
		}
		copy(hash[:], h.Sum(nil))
		return hash, func(w io.Writer) error {
			if _, err := src.Seek(0, io.SeekStart); err != nil {
				return fmt.Errorf("nxformat: file %q: rewind: %w", f.Name, err)
			}
			return copyExact(w, src, f.Size, f.Name)
		}, nil, nil
	}

	// Non-seekable source: spool exactly Size bytes to a temp file.
	tmp, err := os.CreateTemp("", "nxformat-hfs0-*.tmp")
	if err != nil {
		return hash, nil, nil, fmt.Errorf("nxformat: file %q: spool: %w", f.Name, err)
	}
	cleanup = func() { tmp.Close(); os.Remove(tmp.Name()) }
	if err := copyExact(tmp, f.R, f.Size, f.Name); err != nil {
		cleanup()
		return hash, nil, nil, err
	}
	h := sha256.New()
	if hashedLen > 0 {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			cleanup()
			return hash, nil, nil, fmt.Errorf("nxformat: file %q: spool rewind: %w", f.Name, err)
		}
		if _, err := io.CopyN(h, tmp, hashedLen); err != nil {
			cleanup()
			return hash, nil, nil, fmt.Errorf("nxformat: file %q: hashing spool: %w", f.Name, err)
		}
	}
	copy(hash[:], h.Sum(nil))
	return hash, func(w io.Writer) error {
		if _, err := tmp.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("nxformat: file %q: spool rewind: %w", f.Name, err)
		}
		return copyExact(w, tmp, f.Size, f.Name)
	}, cleanup, nil
}
