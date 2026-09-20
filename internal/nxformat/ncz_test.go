package nxformat

import (
	"bytes"
	"io"
	"strings"
	"testing"

	"github.com/klauspost/compress/zstd"
)

// signalisNCZ opens the .ncz payload inside the retail NSZ sample and
// returns a reader over just that file's bytes.
func signalisNCZ(t *testing.T) io.ReaderAt {
	t.Helper()
	f := openSample(t, "signalis.nsz.head")

	entries, headerSize, err := ParsePFS0(f)
	if err != nil {
		t.Fatalf("ParsePFS0: %v", err)
	}
	for _, e := range entries {
		if strings.HasSuffix(e.Name, ".ncz") {
			return io.NewSectionReader(f, headerSize+e.Offset, e.Size)
		}
	}
	t.Fatal("no .ncz file in sample NSZ")
	return nil
}

// --- fixture parsing (retail sample, read-only) ---

func TestNCZParseHeaderSampleSignalis(t *testing.T) {
	ncz := signalisNCZ(t)

	sections, compressedStart, err := ParseNCZHeader(ncz)
	if err != nil {
		t.Fatalf("ParseNCZHeader: %v", err)
	}
	if len(sections) != 179 {
		t.Fatalf("got %d sections, want 179", len(sections))
	}

	first := sections[0]
	if first.Offset != 0x4000 {
		t.Errorf("first section offset = %#x, want 0x4000", first.Offset)
	}
	if first.Size != 70150336 {
		t.Errorf("first section size = %d, want 70150336", first.Size)
	}
	if first.CryptoType != 3 {
		t.Errorf("first section cryptoType = %d, want 3", first.CryptoType)
	}

	// Sections tile the NCA contiguously from 0x4000 to the NCA end.
	var want int64 = 0x4000
	for i, s := range sections {
		if int64(s.Offset) != want {
			t.Fatalf("section %d offset = %#x, want %#x (sections are contiguous)", i, s.Offset, want)
		}
		want += int64(s.Size)
	}
	if got := DecompressedNCASize(sections); got != want {
		t.Errorf("DecompressedNCASize = %d, want %d (end of last section)", got, want)
	}
	if want != 518565888 {
		t.Errorf("decompressed NCA size = %d, want 518565888", want)
	}

	// The zstd stream starts immediately after the section table.
	if compressedStart != 0x4000+nczSectionHeaderSize+179*nczSectionEntrySize {
		t.Errorf("compressedStart = %#x, want %#x", compressedStart, 0x4000+nczSectionHeaderSize+179*nczSectionEntrySize)
	}
	var magic [4]byte
	if _, err := ncz.ReadAt(magic[:], compressedStart); err != nil {
		t.Fatalf("reading zstd magic: %v", err)
	}
	if !bytes.Equal(magic[:], []byte{0x28, 0xB5, 0x2F, 0xFD}) {
		t.Errorf("bytes at %#x = % x, want zstd frame magic 28 b5 2f fd", compressedStart, magic)
	}
}

// --- synthetic round-trip ---

// buildNCZ assembles a single-section .ncz: a recognizable 0x4000-byte NCA
// header, the section table, and the payload zstd-compressed.
func buildNCZ(t *testing.T, header, payload []byte) []byte {
	t.Helper()

	enc, err := zstd.NewWriter(nil)
	if err != nil {
		t.Fatalf("zstd.NewWriter: %v", err)
	}
	defer enc.Close()
	compressed := enc.EncodeAll(payload, nil)

	var sect [nczSectionEntrySize]byte
	put64(sect[0:8], nczHeaderSize)
	put64(sect[8:16], int64(len(payload)))
	put64(sect[16:24], 3)
	put64(sect[24:32], 0)
	copy(sect[32:48], "0123456789abcdef") // IV
	// trailing 16 bytes stay zero (reserved)

	buf := bytes.NewBuffer(nil)
	buf.Write(header)
	buf.WriteString(nczSectionMagic)
	var cnt [8]byte
	put64(cnt[:], 1)
	buf.Write(cnt[:])
	buf.Write(sect[:])
	buf.Write(compressed)
	return buf.Bytes()
}

func TestNCZDecompressRoundTripSynthetic(t *testing.T) {
	header := make([]byte, nczHeaderSize)
	for i := range header {
		header[i] = byte(i) // recognizable pattern
	}
	payload := make([]byte, 1024) // deterministic pseudo-random body
	var s uint32 = 0x12345
	for i := range payload {
		s = s*1664525 + 1013904223
		payload[i] = byte(s >> 24)
	}

	ncz := bytes.NewReader(buildNCZ(t, header, payload))

	sections, compressedStart, err := ParseNCZHeader(ncz)
	if err != nil {
		t.Fatalf("ParseNCZHeader: %v", err)
	}
	if len(sections) != 1 {
		t.Fatalf("got %d sections, want 1", len(sections))
	}
	if sections[0].Offset != nczHeaderSize || sections[0].Size != uint64(len(payload)) || sections[0].CryptoType != 3 {
		t.Errorf("parsed section = %+v, want offset 0x4000 size %d crypto 3", sections[0], len(payload))
	}
	if sections[0].IV != [16]byte([]byte("0123456789abcdef")) {
		t.Errorf("parsed IV = %x, want 30313233343536373839616263646566", sections[0].IV)
	}
	if compressedStart != 0x4000+nczSectionHeaderSize+nczSectionEntrySize {
		t.Errorf("compressedStart = %#x, want %#x", compressedStart, 0x4000+nczSectionHeaderSize+nczSectionEntrySize)
	}
	if got := DecompressedNCASize(sections); got != int64(nczHeaderSize+len(payload)) {
		t.Errorf("DecompressedNCASize = %d, want %d", got, nczHeaderSize+len(payload))
	}

	var out bytes.Buffer
	if err := DecompressNCZ(ncz, &out); err != nil {
		t.Fatalf("DecompressNCZ: %v", err)
	}
	got := out.Bytes()
	if len(got) != nczHeaderSize+len(payload) {
		t.Fatalf("decompressed %d bytes, want %d", len(got), nczHeaderSize+len(payload))
	}
	if !bytes.Equal(got[:nczHeaderSize], header) {
		t.Error("NCA header not copied verbatim")
	}
	if !bytes.Equal(got[nczHeaderSize:], payload) {
		t.Error("NCA body does not round-trip to the original payload")
	}
}

// --- error paths ---

func TestNCZParseHeaderRejectsNonNCZ(t *testing.T) {
	// A full-size buffer with no NCZSECTN at 0x4000 (e.g. a plain .nca).
	if _, _, err := ParseNCZHeader(bytes.NewReader(make([]byte, 0x5000))); err == nil {
		t.Fatal("ParseNCZHeader accepted input without NCZSECTN magic")
	}
	// Input shorter than the section header position.
	if _, _, err := ParseNCZHeader(bytes.NewReader(make([]byte, 0x100))); err == nil {
		t.Fatal("ParseNCZHeader accepted input shorter than 0x4010 bytes")
	}
}

func TestNCZDecompressTruncatedErrors(t *testing.T) {
	ncz := signalisNCZ(t)

	// The sample is a 2MB head of a ~408MB .ncz: the zstd stream is cut
	// off mid-frame, so decompression must surface an error.
	var out bytes.Buffer
	if err := DecompressNCZ(ncz, &out); err == nil {
		t.Fatalf("DecompressNCZ succeeded on truncated .ncz (%d bytes out)", out.Len())
	}
}
