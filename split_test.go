package main

import (
	"bytes"
	"encoding/binary"
	"testing"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

// fakeNCA builds a synthetic NCA of the given size whose header_key-encrypted
// header decrypts to NCA3 + the given title ID (at +0x10) with the gamecard
// distribution byte set.
func fakeNCA(t *testing.T, key []byte, name string, titleID uint64, size int64) nxformat.NamedReader {
	t.Helper()
	body := make([]byte, size)
	plain := make([]byte, 0x200)
	copy(plain[:4], "NCA3")
	plain[4] = nxformat.DistributionGamecard
	binary.LittleEndian.PutUint64(plain[0x10:0x18], titleID)
	if err := nxformat.EncryptNCAHeader(body, plain, key); err != nil {
		t.Fatalf("%s: %v", name, err)
	}
	return nxformat.NamedReader{Name: name, Size: size, R: bytes.NewReader(body)}
}

func blob(name string, size int64) nxformat.NamedReader {
	return nxformat.NamedReader{Name: name, Size: size, R: bytes.NewReader(make([]byte, size))}
}

func groupNames(g *splitGroup) []string {
	names := make([]string, len(g.files))
	for i, f := range g.files {
		names[i] = f.Name
	}
	return names
}

// TestSplitClassifySecure covers split grouping over a synthetic multi-type
// XCI: one family with a base, an update (whose content NCAs carry the base
// title ID, like real retail update NSPs), and two DLC titles, plus ticket/
// cert/cnmt.xml ride-alongs. DLC titles must split into separate NSPs (each
// carries its own cnmt); tickets follow the title ID in their file name and
// cnmt.xml files follow their cnmt NCA.
func TestSplitClassifySecure(t *testing.T) {
	key := make([]byte, 32)
	for i := range key {
		key[i] = byte(i*11 + 3)
	}
	const (
		baseTID = 0x0100AA0000020000
		updTID  = 0x0100AA0000022800
		dlc1TID = 0x0100AA0000023001
		dlc2TID = 0x0100AA0000023002
	)
	files := []nxformat.NamedReader{
		fakeNCA(t, key, "aaaa0000000000000000000000000001.nca", baseTID, 0x1800),
		fakeNCA(t, key, "aaaa0000000000000000000000000002.cnmt.nca", baseTID, 0x1000),
		// Update content carries the BASE title ID; only its cnmt has +0x800.
		fakeNCA(t, key, "aaaa0000000000000000000000000003.nca", baseTID, 0x1400),
		fakeNCA(t, key, "aaaa0000000000000000000000000004.cnmt.nca", updTID, 0x1000),
		fakeNCA(t, key, "bbbb0000000000000000000000000001.cnmt.nca", dlc1TID, 0x1000),
		fakeNCA(t, key, "bbbb0000000000000000000000000002.nca", dlc1TID, 0x1200),
		fakeNCA(t, key, "cccc0000000000000000000000000001.cnmt.nca", dlc2TID, 0x1000),
		blob("0100aa00000228000000000000000004.tik", 0x400),
		blob("0100aa00000228000000000000000004.cert", 0x400),
		blob("0100aa0000023001000000000000000d.tik", 0x400),
		blob("aaaa0000000000000000000000000004.cnmt.xml", 0x100),
		blob("unidentifiable.bin", 0x40),
	}

	var xci bytes.Buffer
	if err := nxformat.WriteXCI(&xci, gamecardHeaderTemplate(), files); err != nil {
		t.Fatal(err)
	}
	rd := bytes.NewReader(xci.Bytes())
	entries, secureBase, err := nxformat.ParseXCI(rd)
	if err != nil {
		t.Fatal(err)
	}

	groups, err := classifySecure(entries, secureBase, int64(xci.Len()), rd, key)
	if err != nil {
		t.Fatal(err)
	}
	if len(groups) != 4 {
		t.Fatalf("got %d groups, want 4", len(groups))
	}
	want := []struct {
		name  string
		files []string
	}{
		{"BASE_0100AA0000020000.nsp", []string{
			"aaaa0000000000000000000000000001.nca",
			"aaaa0000000000000000000000000002.cnmt.nca",
			"aaaa0000000000000000000000000003.nca", // update content, base title ID
			"unidentifiable.bin",
		}},
		{"UPD_0100AA0000022800.nsp", []string{
			"aaaa0000000000000000000000000004.cnmt.nca",
			"0100aa00000228000000000000000004.tik",
			"0100aa00000228000000000000000004.cert",
			"aaaa0000000000000000000000000004.cnmt.xml",
		}},
		{"DLC_0100AA0000023001.nsp", []string{
			"bbbb0000000000000000000000000001.cnmt.nca",
			"bbbb0000000000000000000000000002.nca",
			"0100aa0000023001000000000000000d.tik",
		}},
		{"DLC_0100AA0000023002.nsp", []string{
			"cccc0000000000000000000000000001.cnmt.nca",
		}},
	}
	for i, w := range want {
		g := groups[i]
		if got := g.name(); got != w.name {
			t.Errorf("group %d: name %s, want %s", i, got, w.name)
		}
		got := groupNames(g)
		if len(got) != len(w.files) || !equalStrings(got, w.files) {
			t.Errorf("group %s: files %v, want %v", w.name, got, w.files)
		}
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// TestSplitKind pins the retail title-ID layout: low 12 bits 0x000 base,
// 0x800 update, 0x001+ add-on content; base IDs are not necessarily
// ...0000 (MK8D base ends 0x2000, Dead Cells base ends 0xE000).
func TestSplitKind(t *testing.T) {
	cases := []struct {
		tid  uint64
		kind string
	}{
		{0x0100152000022000, "BASE"}, // MK8D base
		{0x0100646009FBE000, "BASE"}, // Dead Cells base
		{0x0100000000010000, "BASE"}, // plain ...0000 base
		{0x0100152000022800, "UPD"},  // MK8D update
		{0x0100646009FBE800, "UPD"},  // Dead Cells update
		{0x0100152000023001, "DLC"},  // MK8D DLC
		{0x0100646009FBF005, "DLC"},  // Dead Cells DLC 5
	}
	for _, c := range cases {
		if got := splitKind(c.tid); got != c.kind {
			t.Errorf("splitKind(%016X) = %s, want %s", c.tid, got, c.kind)
		}
	}
}
