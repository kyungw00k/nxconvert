// Package nxformat reads and writes the Nintendo Switch container formats
// used by nxconvert: PFS0 (the NSP package format) and the gamecard (XCI)
// HFS0 partition format.
//
// All parsers operate on io.ReaderAt so the headers of multi-gigabyte
// images can be inspected without loading them, and all writers stream file
// bodies with io.Copy, never buffering whole files in memory.
package nxformat

import (
	"encoding/binary"
	"fmt"
	"io"
	"strings"
)

// FileEntry describes one file inside a PFS0 or HFS0 container. Offset is
// relative to the container's data area (the byte immediately after the
// header and string table); the absolute position of the file's bytes is
// dataAreaBase + Offset, where dataAreaBase is the container base plus the
// header size returned by the parser.
type FileEntry struct {
	Name   string
	Size   int64
	Offset int64 // relative to the data area
}

// NamedReader is one file to store in a container. Size is the exact number
// of bytes the writers will read from R; R must be positioned at the start
// of the file's content and yield at least Size bytes.
type NamedReader struct {
	Name string
	R    io.Reader
	Size int64
}

// PFS0 layout, verified byte-exact against a retail NSP dump:
//
//	0x00  'PFS0'
//	0x04  u32 fileCount
//	0x08  u32 stringTableSize
//	0x0C  u32 reserved (0)
//	0x10  file entries, 0x18 bytes each:
//	        u64 dataOffset (relative to the data area)
//	        u64 dataSize
//	        u32 nameOffset (into the string table)
//	        u32 reserved (0)
//	then the string table (names NUL-terminated), then the data area at
//	0x10 + fileCount*0x18 + stringTableSize. Retail NSPs do NOT align the
//	data area (observed at an unaligned 0x184) and pack files contiguously.
const (
	pfs0Magic      = "PFS0"
	pfs0HeaderSize = 0x10
	pfs0EntrySize  = 0x18
)

// Sanity caps so corrupted headers cannot trigger huge allocations.
const (
	maxFiles           = 1 << 16
	maxStringTableSize = 1 << 24
	maxNameLen         = 1 << 12
)

// ParsePFS0 parses the PFS0 header at the start of r. The returned
// headerSize is the distance from the start of r to the data area, i.e.
// the base that entry offsets are relative to.
func ParsePFS0(r io.ReaderAt) ([]FileEntry, int64, error) {
	var hdr [pfs0HeaderSize]byte
	if _, err := r.ReadAt(hdr[:], 0); err != nil {
		return nil, 0, fmt.Errorf("nxformat: reading PFS0 header: %w", err)
	}
	if string(hdr[0:4]) != pfs0Magic {
		return nil, 0, fmt.Errorf("nxformat: bad PFS0 magic %q", hdr[0:4])
	}
	count := binary.LittleEndian.Uint32(hdr[4:8])
	strSize := binary.LittleEndian.Uint32(hdr[8:12])
	if err := checkHeaderShape(int64(count), int64(strSize), pfs0EntrySize); err != nil {
		return nil, 0, err
	}

	table := make([]byte, int64(count)*pfs0EntrySize+int64(strSize))
	if _, err := r.ReadAt(table, pfs0HeaderSize); err != nil {
		return nil, 0, fmt.Errorf("nxformat: reading PFS0 table: %w", err)
	}

	entries := make([]FileEntry, 0, count)
	for i := range int64(count) {
		e := i * pfs0EntrySize
		off := int64(binary.LittleEndian.Uint64(table[e:]))
		size := int64(binary.LittleEndian.Uint64(table[e+8:]))
		if off < 0 || size < 0 {
			return nil, 0, fmt.Errorf("nxformat: PFS0 entry %d: implausible offset/size", i)
		}
		name, err := nameAt(table[int64(count)*pfs0EntrySize:], binary.LittleEndian.Uint32(table[e+16:]))
		if err != nil {
			return nil, 0, fmt.Errorf("nxformat: PFS0 entry %d: %w", i, err)
		}
		entries = append(entries, FileEntry{Name: name, Size: size, Offset: off})
	}
	return entries, pfs0HeaderSize + int64(count)*pfs0EntrySize + int64(strSize), nil
}

// ReadPFS0File returns a reader over one parsed entry's data. It re-parses
// the PFS0 header to locate the data area, so the reader is valid for the
// entry's exact byte range; a header error surfaces on the first Read.
func ReadPFS0File(r io.ReaderAt, e FileEntry) io.Reader {
	_, headerSize, err := ParsePFS0(r)
	if err != nil {
		return errReader{fmt.Errorf("nxformat: ReadPFS0File: %w", err)}
	}
	return io.NewSectionReader(r, headerSize+e.Offset, e.Size)
}

// WritePFS0 streams a PFS0 container to w. Files are stored in the given
// order and packed contiguously from the data area, like retail NSPs; the
// last u32 of each entry is written as the reserved zero field observed in
// retail files.
func WritePFS0(w io.Writer, files []NamedReader) error {
	strSize, err := validateNames(files)
	if err != nil {
		return err
	}
	n := int64(len(files))
	tableSize := pfs0HeaderSize + n*pfs0EntrySize + strSize
	buf := make([]byte, tableSize)
	copy(buf[0:4], pfs0Magic)
	put32(buf[4:], n)
	put32(buf[8:], strSize)

	strBase := pfs0HeaderSize + n*pfs0EntrySize
	var nameOff, dataOff int64
	for i, f := range files {
		e := pfs0HeaderSize + int64(i)*pfs0EntrySize
		put64(buf[e:], dataOff)
		put64(buf[e+8:], f.Size)
		put32(buf[e+16:], nameOff)
		copy(buf[strBase+nameOff:], f.Name)
		nameOff += int64(len(f.Name)) + 1
		dataOff += f.Size
	}
	if _, err := w.Write(buf); err != nil {
		return fmt.Errorf("nxformat: writing PFS0 header: %w", err)
	}
	for _, f := range files {
		if err := copyExact(w, f.R, f.Size, f.Name); err != nil {
			return err
		}
	}
	return nil
}

// --- shared helpers ---

// checkHeaderShape guards the count/string-table fields of a parsed header.
func checkHeaderShape(count, strSize, entrySize int64) error {
	if count > maxFiles {
		return fmt.Errorf("nxformat: implausible file count %d", count)
	}
	if strSize > maxStringTableSize {
		return fmt.Errorf("nxformat: implausible string table size %d", strSize)
	}
	if count*entrySize+strSize > int64(maxFiles*entrySize)+maxStringTableSize {
		return fmt.Errorf("nxformat: implausible header size")
	}
	return nil
}

// nameAt reads the NUL-terminated name at off in a string table.
func nameAt(table []byte, off uint32) (string, error) {
	if int64(off) >= int64(len(table)) {
		return "", fmt.Errorf("name offset %#x out of range", off)
	}
	end := int(off)
	for end < len(table) && table[end] != 0 {
		end++
	}
	if end == len(table) {
		return "", fmt.Errorf("unterminated name at offset %#x", off)
	}
	return string(table[off:end]), nil
}

// validateNames checks a file list and returns its string-table size.
func validateNames(files []NamedReader) (int64, error) {
	var strSize int64
	for i, f := range files {
		if f.Name == "" {
			return 0, fmt.Errorf("nxformat: file %d: empty name", i)
		}
		if strings.IndexByte(f.Name, 0) >= 0 {
			return 0, fmt.Errorf("nxformat: file %q: name contains NUL", f.Name)
		}
		if len(f.Name) > maxNameLen {
			return 0, fmt.Errorf("nxformat: file %q: name too long (%d bytes)", f.Name, len(f.Name))
		}
		if f.Size < 0 {
			return 0, fmt.Errorf("nxformat: file %q: negative size %d", f.Name, f.Size)
		}
		strSize += int64(len(f.Name)) + 1
	}
	if strSize > maxStringTableSize {
		return 0, fmt.Errorf("nxformat: string table too large (%d bytes)", strSize)
	}
	return strSize, nil
}

// copyExact copies exactly n bytes from src to w, reporting a short source
// as an error naming the file.
func copyExact(w io.Writer, src io.Reader, n int64, name string) error {
	m, err := io.CopyN(w, src, n)
	if err == io.EOF {
		return fmt.Errorf("nxformat: file %q: source yielded %d bytes, %d declared", name, m, n)
	}
	if err != nil {
		return fmt.Errorf("nxformat: file %q: %w", name, err)
	}
	return nil
}

func put32(b []byte, v int64) { binary.LittleEndian.PutUint32(b, uint32(v)) }
func put64(b []byte, v int64) { binary.LittleEndian.PutUint64(b, uint64(v)) }

func alignUp(v, a int64) int64 {
	if r := v % a; r != 0 {
		return v + a - r
	}
	return v
}

// errReader yields err on every Read, for APIs that cannot return errors.
type errReader struct{ err error }

func (e errReader) Read([]byte) (int, error) { return 0, e.err }
