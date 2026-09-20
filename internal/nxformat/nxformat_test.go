package nxformat

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/iotest"
)

const sampleDir = "/tmp/nxconvert-samples"

func openSample(t *testing.T, name string) *os.File {
	t.Helper()
	f, err := os.Open(filepath.Join(sampleDir, name))
	if errors.Is(err, fs.ErrNotExist) {
		t.Skipf("sample fixture not present: %s", name)
	}
	if err != nil {
		t.Fatalf("opening sample %s: %v", name, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// --- fixture parsing (retail samples, read-only) ---

func TestParsePFS0SampleCuphead(t *testing.T) {
	f := openSample(t, "cuphead.nsp.head")

	entries, headerSize, err := ParsePFS0(f)
	if err != nil {
		t.Fatalf("ParsePFS0: %v", err)
	}
	if len(entries) != 6 {
		t.Fatalf("got %d files, want 6", len(entries))
	}
	if headerSize != 0x10+6*pfs0EntrySize+0xE4 {
		t.Fatalf("headerSize = %#x, want 0x184 (unaligned, like retail)", headerSize)
	}

	wantSizes := []int64{704, 1792, 3584, 162304, 1060864, 3480485888}
	wantSuffix := []string{".tik", ".cert", ".cnmt.nca", ".nca", ".nca", ".nca"}
	var dataOff int64
	for i, e := range entries {
		if e.Size != wantSizes[i] {
			t.Errorf("entry %d (%s): size = %d, want %d", i, e.Name, e.Size, wantSizes[i])
		}
		if e.Offset != dataOff {
			t.Errorf("entry %d (%s): offset = %#x, want %#x (retail packs files contiguously)", i, e.Name, e.Offset, dataOff)
		}
		dataOff += e.Size
		if suffix := wantSuffix[i]; len(e.Name) < len(suffix) || e.Name[len(e.Name)-len(suffix):] != suffix {
			t.Errorf("entry %d: name %q lacks suffix %s", i, e.Name, suffix)
		}
	}
	if want := "0100a5c00d1620000000000000000007.tik"; entries[0].Name != want {
		t.Errorf("first name = %q, want %q", entries[0].Name, want)
	}

	// Both small files lie fully inside the 4 MiB head.
	for _, i := range []int{0, 1} {
		got, err := io.ReadAll(ReadPFS0File(f, entries[i]))
		if err != nil {
			t.Fatalf("ReadPFS0File(%d): %v", i, err)
		}
		if int64(len(got)) != entries[i].Size {
			t.Errorf("file %d: read %d bytes, want %d", i, len(got), entries[i].Size)
		}
	}
}

func TestParseXCISampleCrysis(t *testing.T) {
	f := openSample(t, "crysis.xci.head")

	root, rootHeaderSize, err := ParseHFS0(f, 0xF000)
	if err != nil {
		t.Fatalf("ParseHFS0(root): %v", err)
	}
	if len(root) != 3 || root[0].Name != "update" || root[1].Name != "normal" || root[2].Name != "secure" {
		t.Fatalf("root entries = %+v, want update/normal/secure", root)
	}
	for i, want := range []int64{0x200, 0x200, 0x2C0DBEA00} {
		if root[i].Size != want {
			t.Errorf("root %s: size = %#x, want %#x", root[i].Name, root[i].Size, want)
		}
	}
	if rootHeaderSize != 0x200 {
		t.Errorf("root headerSize = %#x, want 0x200", rootHeaderSize)
	}

	entries, secureBase, err := ParseXCI(f)
	if err != nil {
		t.Fatalf("ParseXCI: %v", err)
	}
	if len(entries) < 6 {
		t.Fatalf("secure has %d entries, want >= 6", len(entries))
	}
	if secureBase != 0xF600+0x400 {
		t.Fatalf("secureBase = %#x, want 0xFA00", secureBase)
	}
	// First program NCA: ~10997 MB.
	if entries[0].Size <= 10e9 {
		t.Errorf("first secure entry %s: size %d, want > 10e9", entries[0].Name, entries[0].Size)
	}
	if entries[0].Size != 10997202944 {
		t.Errorf("first secure entry size = %d, want 10997202944", entries[0].Size)
	}

	cnmt := 0
	var dataOff int64
	for _, e := range entries {
		switch {
		case len(e.Name) > 9 && e.Name[len(e.Name)-9:] == ".cnmt.nca":
			cnmt++
		case len(e.Name) < 4 || e.Name[len(e.Name)-4:] != ".nca":
			t.Errorf("secure entry %q is not an NCA name", e.Name)
		}
		if e.Offset != dataOff {
			t.Errorf("secure entry %s: offset = %#x, want %#x (contiguous)", e.Name, e.Offset, dataOff)
		}
		dataOff += e.Size
	}
	if cnmt == 0 {
		t.Error("no .cnmt.nca entry in secure partition")
	}
	// Header + file data must exactly fill the secure partition.
	if dataOff+0x400 != 0x2C0DBEA00 {
		t.Errorf("secure contents = %#x, want 0x2C0DBEA00", dataOff+0x400)
	}
}

// --- writer round-trips (synthetic content) ---

func testFiles() (files []NamedReader, contents [][]byte) {
	for i, size := range []int{3, 513, 70000} {
		b := make([]byte, size)
		for j := range b {
			b[j] = byte(i*127 + j*7)
		}
		contents = append(contents, b)
		files = append(files, NamedReader{
			Name: []string{
				"0100a5c00d1620000000000000000007.tik",
				"5d38cf85c9761a6db94204dbe163a7b3.cnmt.nca",
				"c1de1d5b4d0c4ab8ffe6610e1977cb3a.nca",
			}[i],
			R:    bytes.NewReader(b),
			Size: int64(size),
		})
	}
	return files, contents
}

func TestWritePFS0RoundTrip(t *testing.T) {
	files, contents := testFiles()

	var buf bytes.Buffer
	if err := WritePFS0(&buf, files); err != nil {
		t.Fatalf("WritePFS0: %v", err)
	}
	out := buf.Bytes()

	entries, headerSize, err := ParsePFS0(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("ParsePFS0: %v", err)
	}
	if len(entries) != len(files) {
		t.Fatalf("got %d entries, want %d", len(entries), len(files))
	}
	var dataOff int64
	for i, e := range entries {
		if e.Name != files[i].Name || e.Size != files[i].Size || e.Offset != dataOff {
			t.Errorf("entry %d = %+v, want name %q size %d offset %#x", i, e, files[i].Name, files[i].Size, dataOff)
		}
		dataOff += e.Size

		got, err := io.ReadAll(ReadPFS0File(bytes.NewReader(out), e))
		if err != nil {
			t.Fatalf("ReadPFS0File(%d): %v", i, err)
		}
		if !bytes.Equal(got, contents[i]) {
			t.Errorf("file %d: bytes differ after round-trip", i)
		}
	}
	if int64(len(out)) != headerSize+dataOff {
		t.Errorf("output length %d = header %d + data %d?", len(out), headerSize, dataOff)
	}
}

func TestWriteHFS0RoundTrip(t *testing.T) {
	files, contents := testFiles()

	var buf bytes.Buffer
	if err := WriteHFS0(&buf, files); err != nil {
		t.Fatalf("WriteHFS0: %v", err)
	}
	out := buf.Bytes()

	entries, headerSize, err := ParseHFS0(bytes.NewReader(out), 0)
	if err != nil {
		t.Fatalf("ParseHFS0: %v", err)
	}
	if headerSize%hfs0DataAlign != 0 {
		t.Errorf("data area %#x is not 0x200-aligned like retail", headerSize)
	}
	if len(entries) != len(files) {
		t.Fatalf("got %d entries, want %d", len(entries), len(files))
	}
	var dataOff int64
	for i, e := range entries {
		if e.Name != files[i].Name || e.Size != files[i].Size || e.Offset != dataOff {
			t.Errorf("entry %d = %+v, want name %q size %d offset %#x", i, e, files[i].Name, files[i].Size, dataOff)
		}
		dataOff += e.Size

		got, err := io.ReadAll(io.NewSectionReader(bytes.NewReader(out), headerSize+e.Offset, e.Size))
		if err != nil {
			t.Fatalf("reading entry %d: %v", i, err)
		}
		if !bytes.Equal(got, contents[i]) {
			t.Errorf("file %d: bytes differ after round-trip", i)
		}

		// Entry layout: hashedRegionSize at +0x14, zero u64 at +0x18,
		// SHA-256 of the file's first hashedRegionSize bytes at +0x20.
		entry := out[hfs0HeaderSize+i*hfs0EntrySize:]
		hashed := min(files[i].Size, hfs0HashPrefix)
		if got := binary.LittleEndian.Uint32(entry[0x14:]); int64(got) != hashed {
			t.Errorf("entry %d: hashedRegionSize = %d, want %d", i, got, hashed)
		}
		if v := binary.LittleEndian.Uint64(entry[0x18:]); v != 0 {
			t.Errorf("entry %d: u64@+0x18 = %#x, want 0 like retail", i, v)
		}
		sum := sha256.Sum256(contents[i][:hashed])
		if !bytes.Equal(entry[hfs0HashOff:hfs0HashOff+sha256.Size], sum[:]) {
			t.Errorf("entry %d: stored hash %x, want sha256 of content %x", i, entry[hfs0HashOff:hfs0HashOff+sha256.Size], sum)
		}
	}
	if int64(len(out)) != headerSize+dataOff {
		t.Errorf("output length %d = header %d + data %d?", len(out), headerSize, dataOff)
	}
}

func TestWriteXCIRoundTrip(t *testing.T) {
	files, contents := testFiles()

	var tmpl [gamecardHeaderSize]byte
	copy(tmpl[0x100:0x104], "HEAD")
	tmpl[0x1234] = 0xAB // marker: template bytes pass through verbatim

	var buf bytes.Buffer
	if err := WriteXCI(&buf, tmpl, files); err != nil {
		t.Fatalf("WriteXCI: %v", err)
	}
	out := buf.Bytes()
	r := bytes.NewReader(out)

	if out[0x1234] != 0xAB {
		t.Error("template marker byte was not preserved")
	}
	// Patched field: index of the last valid page.
	if got, want := binary.LittleEndian.Uint64(out[xciLastPageOff:]), uint64((len(out)-1)/xciPageSize); got != want {
		t.Errorf("last-page field @0x118 = %#x, want %#x", got, want)
	}

	// Root partition layout.
	root, rootHeaderSize, err := ParseHFS0(r, gamecardRootOffset)
	if err != nil {
		t.Fatalf("ParseHFS0(root): %v", err)
	}
	if rootHeaderSize != rootPartitionSize {
		t.Errorf("root headerSize = %#x, want %#x", rootHeaderSize, rootPartitionSize)
	}
	for i, want := range []int64{emptyPartitionSize, emptyPartitionSize, int64(len(out)) - 0xF600} {
		if root[i].Size != want {
			t.Errorf("root %s: size = %#x, want %#x", root[i].Name, root[i].Size, want)
		}
	}
	if str := out[0xF000+hfs0HeaderSize+3*hfs0EntrySize:][:22]; string(str) != "update\x00normal\x00secure\x00" {
	}

	// update/normal partitions: bare empty HFS0 headers, byte-identical to
	// the retail sample's (whose SHA-256 we verified against the fixture).
	empty := emptyPartitionHeader()
	blob := make([]byte, emptyPartitionSize)
	if _, err := r.ReadAt(blob, 0xF200); err != nil {
		t.Fatalf("reading update partition: %v", err)
	}
	if !bytes.Equal(blob, empty[:]) {
		t.Error("update partition is not a bare empty HFS0 header")
	}
	const retailEmptyHash = "7a2bfa78b3dc769506a531ad44ea7f2cb863e30ad96e52d6fe2cd0943d4f7b49"
	sum := sha256.Sum256(blob)
	if hex.EncodeToString(sum[:]) != retailEmptyHash {
		t.Errorf("update partition sha256 = %x, want retail %s", sum, retailEmptyHash)
	}

	// Root secure entry: hash covers the secure partition's own header.
	_, secureHdrSize, err := ParseHFS0(r, 0xF600)
	if err != nil {
		t.Fatalf("ParseHFS0(secure): %v", err)
	}
	secureEntry := out[0xF000+secureEntryBase:]
	if got := binary.LittleEndian.Uint32(secureEntry[0x14:]); int64(got) != secureHdrSize {
		t.Errorf("root secure hashedRegionSize = %d, want secure header size %d", got, secureHdrSize)
	}

	// Secure contents round-trip.
	entries, secureBase, err := ParseXCI(r)
	if err != nil {
		t.Fatalf("ParseXCI: %v", err)
	}
	if secureBase != 0xF600+secureHdrSize {
		t.Errorf("secureBase = %#x, want %#x", secureBase, 0xF600+secureHdrSize)
	}
	for i, e := range entries {
		if e.Name != files[i].Name || e.Size != files[i].Size {
			t.Errorf("secure entry %d = %+v, want name %q size %d", i, e, files[i].Name, files[i].Size)
		}
		got, err := io.ReadAll(io.NewSectionReader(r, secureBase+e.Offset, e.Size))
		if err != nil {
			t.Fatalf("reading secure entry %d: %v", i, err)
		}
		if !bytes.Equal(got, contents[i]) {
			t.Errorf("secure file %d: bytes differ after round-trip", i)
		}
	}
}

// Non-seekable sources must go through the temp-file spool and still
// round-trip.
func TestWriteHFS0NonSeekableSource(t *testing.T) {
	content := bytes.Repeat([]byte{0xA5}, 1000)
	files := []NamedReader{{
		Name: "2e3189a3e841a99a88a5843d98f20cae.nca",
		R:    iotest.OneByteReader(bytes.NewReader(content)), // not a Seeker/ReaderAt
		Size: int64(len(content)),
	}}

	var buf bytes.Buffer
	if err := WriteHFS0(&buf, files); err != nil {
		t.Fatalf("WriteHFS0: %v", err)
	}
	entries, headerSize, err := ParseHFS0(bytes.NewReader(buf.Bytes()), 0)
	if err != nil || len(entries) != 1 {
		t.Fatalf("ParseHFS0: %v, %d entries", err, len(entries))
	}
	got, err := io.ReadAll(io.NewSectionReader(bytes.NewReader(buf.Bytes()), headerSize, entries[0].Size))
	if err != nil || !bytes.Equal(got, content) {
		t.Errorf("spooled round-trip failed: %v, %d bytes", err, len(got))
	}
}

func TestWriteShortSource(t *testing.T) {
	files := []NamedReader{{Name: "short.nca", R: bytes.NewReader([]byte("abc")), Size: 10}}
	for name, fn := range map[string]func() error{
		"WritePFS0": func() error {
			var b bytes.Buffer
			return WritePFS0(&b, files)
		},
		"WriteHFS0": func() error {
			var b bytes.Buffer
			return WriteHFS0(&b, files)
		},
	} {
		err := fn()
		if err == nil {
			t.Errorf("%s: no error for short source", name)
			continue
		}
		if want := "short.nca"; !bytes.Contains([]byte(err.Error()), []byte(want)) {
			t.Errorf("%s: error %q does not name the file", name, err)
		}
	}
}

func TestParseBadMagic(t *testing.T) {
	nsp := openSample(t, "cuphead.nsp.head")
	xci := openSample(t, "crysis.xci.head")

	if _, _, err := ParsePFS0(xci); err == nil {
		t.Error("ParsePFS0 accepted an XCI header")
	}
	if _, _, err := ParseHFS0(nsp, 0xF000); err == nil {
		t.Error("ParseHFS0 accepted a non-HFS0 base")
	}
	if _, _, err := ParseXCI(nsp); err == nil {
		t.Error("ParseXCI accepted an NSP")
	}
}

func TestXTSRoundTripAndDistribution(t *testing.T) {
	// XTS encrypt/decrypt round-trip with a 32-byte header key + distribution flip round-trip.
	headerKey := make([]byte, 32)
	for i := range headerKey {
		headerKey[i] = byte(i * 7)
	}
	// Synthetic NCA header: plaintext magic NCA3 + distribution 0x00
	plain := make([]byte, NCAHeaderEncSize)
	copy(plain, "NCA3")
	plain[NCADistributionOffset] = DistributionDownload

	hdr := make([]byte, 0x400)
	if err := EncryptNCAHeader(hdr, plain, headerKey); err != nil {
		t.Fatal(err)
	}
	got, err := DecryptNCAHeader(hdr, headerKey)
	if err != nil {
		t.Fatal(err)
	}
	if got[NCADistributionOffset] != DistributionDownload {
		t.Fatalf("roundtrip distribution = %#x", got[NCADistributionOffset])
	}

	flipped, changed, err := FlipDistribution(hdr, headerKey, DistributionGamecard)
	if err != nil {
		t.Fatal(err)
	}
	if !changed {
		t.Fatal("expected a change")
	}
	got2, _ := DecryptNCAHeader(flipped, headerKey)
	if got2[NCADistributionOffset] != DistributionGamecard {
		t.Fatalf("flipped distribution = %#x", got2[NCADistributionOffset])
	}
	// Flipping back yields bytes identical to the original header (idempotency)
	back, changed2, _ := FlipDistribution(flipped, headerKey, DistributionDownload)
	if !changed2 {
		t.Fatal("expected second change")
	}
	for i := range hdr {
		if hdr[i] != back[i] {
			t.Fatalf("double flip mismatch at %#x", i)
		}
	}
}

func TestParseProdKeys(t *testing.T) {
	in := "header_key = 000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f\n" +
		"# comment\nmaster_key_00 = deadbeef\nbroken = xyz\n\n"
	keys, err := ParseProdKeys(strings.NewReader(in))
	if err != nil {
		t.Fatal(err)
	}
	hk, ok := keys["header_key"]
	if !ok || len(hk) != 32 || hk[0] != 0 || hk[31] != 0x1f {
		t.Fatalf("header_key parse: %v", hk)
	}
	if string(keys["master_key_00"]) != "\xde\xad\xbe\xef" {
		t.Fatalf("master_key_00 = %v", keys["master_key_00"])
	}
	if _, bad := keys["broken"]; bad {
		t.Fatal("broken hex line should be skipped")
	}
}
