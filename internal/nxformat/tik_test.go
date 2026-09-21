package nxformat

import (
	"bytes"
	"crypto/aes"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"io"
	"os"
	"strings"
	"testing"
)

// deadCellsUpdNSP is the retail sample named by the ticket work: the BASE
// NSP of this title ships no ticket (its 4 PFS0 entries are all NCAs),
// while the update NSP carries the standard cert+tik pair. Both share the
// title ID base 0100646009FB, differing only in the type suffix (e800).
const deadCellsUpdNSP = "/Users/humphrey.park/Downloads/switch/Dead Cells/update/Dead Cells [UPD][0100646009FBE800][v3014656].nsp"

const prodKeysPath = "/tmp/prod.keys"

func openPath(t *testing.T, path string) io.ReaderAt {
	t.Helper()
	f, err := os.Open(path)
	if os.IsNotExist(err) {
		t.Skipf("fixture not present: %s", path)
	}
	if err != nil {
		t.Fatalf("opening %s: %v", path, err)
	}
	t.Cleanup(func() { f.Close() })
	return f
}

// mustHex decodes a pinned hex vector or fails the test.
func mustHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("bad hex vector: %v", err)
	}
	return b
}

// syntheticTicket builds a 0x2C0 RSA-2048-shaped ticket with the given
// signature type (stored little-endian, like retail), encrypted titlekey,
// and rights ID.
func syntheticTicket(t *testing.T, sig uint32, encTitleKey, rightsID string) []byte {
	t.Helper()
	tik := make([]byte, 0x2C0)
	binary.LittleEndian.PutUint32(tik, sig)
	copy(tik[tikEncTitleKeyOff:], mustHex(t, encTitleKey))
	copy(tik[tikRightsIDOff:], mustHex(t, rightsID))
	return tik
}

// --- ParseTicket: validation ---

func TestParseTicketRejectsShortBuffer(t *testing.T) {
	// A real RSA-2048 ticket is 0x2C0 bytes, but the parser only needs
	// through the end of the rights ID (0x2A0+16). Anything shorter must
	// be rejected without reading out of bounds.
	for _, n := range []int{0, 0x180, 0x2A0, 0x2AF} {
		if _, _, err := ParseTicket(make([]byte, n)); err == nil {
			t.Errorf("ticket of %d bytes accepted, want rejection", n)
		}
	}
}

func TestParseTicketRejectsNonRSA2048Signature(t *testing.T) {
	// RSA-4096 tickets (0x00010001) shift the body by +0x100 and ECDSA
	// tickets are 0x240 bytes total; the fixed offsets must not be
	// applied to either layout.
	for _, sig := range []uint32{0x00010001, 0x00010003, 0x00010005, 0} {
		tik := syntheticTicket(t, sig,
			"9c28ed1975baa80fd1ab8f4f14419d60",
			"0100646009fbe8000000000000000005")
		if _, _, err := ParseTicket(tik); err == nil {
			t.Errorf("signature type %#08x accepted, want rejection", sig)
		}
	}
}

func TestParseTicketAcceptsRSA2048SignatureTypes(t *testing.T) {
	for _, sig := range []uint32{tikSigRSA2048, tikSigHakRSA2048} {
		tik := syntheticTicket(t, sig,
			"9c28ed1975baa80fd1ab8f4f14419d60",
			"0100646009fbe8000000000000000005")
		rightsID, enc, err := ParseTicket(tik)
		if err != nil {
			t.Fatalf("signature type %#08x rejected: %v", sig, err)
		}
		if want := mustHex(t, "0100646009fbe8000000000000000005"); !bytes.Equal(rightsID, want) {
			t.Errorf("rights ID = %x, want %x", rightsID, want)
		}
		if want := mustHex(t, "9c28ed1975baa80fd1ab8f4f14419d60"); !bytes.Equal(enc, want) {
			t.Errorf("encrypted titlekey = %x, want %x", enc, want)
		}
	}
}

// --- ExtractTitleKey: ECB vector cross-checked against openssl ---

// The vector is the real Dead Cells update ticket: its 0x180 titlekey
// encrypted under titlekek_05, with the expected plaintext computed by an
// independent implementation (openssl enc -aes-128-ecb -d).
func TestExtractTitleKeyDeadCellsVector(t *testing.T) {
	tik := syntheticTicket(t, tikSigHakRSA2048,
		"9c28ed1975baa80fd1ab8f4f14419d60", // encrypted titlekey @0x180 of the retail tik
		"0100646009fbe8000000000000000005")
	titlekek := mustHex(t, "ddc67f7189f4527a37b519cb051eee21") // titlekek_05

	key, err := ExtractTitleKey(tik, titlekek)
	if err != nil {
		t.Fatalf("ExtractTitleKey: %v", err)
	}
	if want := mustHex(t, "8bade5239331240db1c12851b6e1a6bd"); !bytes.Equal(key, want) {
		t.Fatalf("titlekey = %x, want openssl-computed %x", key, want)
	}
}

func TestExtractTitleKeyRoundTrip(t *testing.T) {
	// Encrypting the recovered titlekey back under the same kek must
	// reproduce the ticket bytes (ECB, single block).
	tik := syntheticTicket(t, tikSigHakRSA2048,
		"0cc0a84d81a723fb36eee3c95cde6736", // Cuphead retail tik @0x180
		"0100a5c00d1620000000000000000007")
	kek := make([]byte, 16)
	for i := range kek {
		kek[i] = byte(3*i + 1)
	}
	key, err := ExtractTitleKey(tik, kek)
	if err != nil {
		t.Fatalf("ExtractTitleKey: %v", err)
	}
	block, err := aes.NewCipher(kek)
	if err != nil {
		t.Fatal(err)
	}
	reenc := make([]byte, 16)
	block.Encrypt(reenc, key)
	if !bytes.Equal(reenc, tik[tikEncTitleKeyOff:tikEncTitleKeyOff+16]) {
		t.Fatalf("re-encrypt gave %x, want original ciphertext", reenc)
	}
}

func TestExtractTitleKeyValidatesKEKAndTicket(t *testing.T) {
	tik := syntheticTicket(t, tikSigHakRSA2048,
		"9c28ed1975baa80fd1ab8f4f14419d60",
		"0100646009fbe8000000000000000005")
	if _, err := ExtractTitleKey(tik, make([]byte, 15)); err == nil {
		t.Error("15-byte titlekek accepted, want rejection")
	}
	if _, err := ExtractTitleKey(make([]byte, 0x100), make([]byte, 16)); err == nil {
		t.Error("truncated ticket accepted, want rejection")
	}
}

// --- ParseRightsID ---

func TestParseRightsID(t *testing.T) {
	// Real rights IDs: title ID big-endian hex ‖ generation counter with
	// the kek index in the low byte.
	for _, tc := range []struct {
		rid     string
		titleID string
		keyGen  int
	}{
		{"0100646009fbe8000000000000000005", "0100646009fbe800", 5},
		{"0100a5c00d1620000000000000000007", "0100a5c00d162000", 7},
		{"0100646009fbf0010000000000000000", "0100646009fbf001", 0},
	} {
		titleID, keyGen := ParseRightsID(mustHex(t, tc.rid))
		if titleID != tc.titleID || keyGen != tc.keyGen {
			t.Errorf("ParseRightsID(%s) = (%q, %d), want (%q, %d)", tc.rid, titleID, keyGen, tc.titleID, tc.keyGen)
		}
	}
	if titleID, keyGen := ParseRightsID([]byte("short")); titleID != "" || keyGen != -1 {
		t.Errorf("short rights ID gave (%q, %d), want (\"\", -1)", titleID, keyGen)
	}
}

// --- Integration: retail tickets from PFS0 containers ---

// findTicket parses a PFS0 container, returning its entry list and the
// raw bytes of the .tik entry. Fails if no ticket is present.
func findTicket(t *testing.T, r io.ReaderAt) (tik []byte, entries []FileEntry) {
	t.Helper()
	entries, _, err := ParsePFS0(r)
	if err != nil {
		t.Fatalf("ParsePFS0: %v", err)
	}
	var tikEntry *FileEntry
	for i := range entries {
		if strings.HasSuffix(entries[i].Name, ".tik") {
			tikEntry = &entries[i]
			break
		}
	}
	if tikEntry == nil {
		t.Fatal("no .tik entry in container")
	}
	if tikEntry.Size > 1<<16 {
		t.Fatalf("tik entry implausibly large: %d", tikEntry.Size)
	}
	tik, err = io.ReadAll(ReadPFS0File(r, *tikEntry))
	if err != nil {
		t.Fatalf("reading tik entry: %v", err)
	}
	return tik, entries
}

func TestTicketFromCupheadSample(t *testing.T) {
	r := openSample(t, "cuphead.nsp.head")
	tik, entries := findTicket(t, r)

	if len(tik) != 0x2C0 {
		t.Fatalf("retail tik is %#x bytes, want 0x2C0 (RSA-2048)", len(tik))
	}
	rightsID, enc, err := ParseTicket(tik)
	if err != nil {
		t.Fatalf("ParseTicket: %v", err)
	}
	if want := mustHex(t, "0100a5c00d1620000000000000000007"); !bytes.Equal(rightsID, want) {
		t.Errorf("rights ID = %x, want %x", rightsID, want)
	}
	if want := mustHex(t, "0cc0a84d81a723fb36eee3c95cde6736"); !bytes.Equal(enc, want) {
		t.Errorf("encrypted titlekey = %x, want %x", enc, want)
	}
	titleID, keyGen := ParseRightsID(rightsID)
	if titleID != "0100a5c00d162000" {
		t.Errorf("titleID = %q, want 0100a5c00d162000", titleID)
	}
	if keyGen != 7 {
		t.Errorf("keyGen = %d, want 7", keyGen)
	}
	// The ticket filename IS the rights ID (lowercase hex), a retail
	// property worth pinning since ParseRightsID chose that convention.
	for _, e := range entries {
		if strings.HasSuffix(e.Name, ".tik") {
			if want := hex.EncodeToString(rightsID) + ".tik"; e.Name != want {
				t.Errorf("tik filename %q != rights ID %q", e.Name, want)
			}
		}
	}
}

// TestTicketDeadCellsUpdate is the acceptance path named by the ticket
// work: pull the real ticket out of the Dead Cells update NSP, recover
// the titlekey with titlekek_05 from prod.keys, and cross-check the
// ticket against the NCA it covers (decrypted header rights ID).
func TestTicketDeadCellsUpdate(t *testing.T) {
	nsp := openPath(t, deadCellsUpdNSP)
	tik, entries := findTicket(t, nsp)

	rightsID, enc, err := ParseTicket(tik)
	if err != nil {
		t.Fatalf("ParseTicket: %v", err)
	}
	titleID, keyGen := ParseRightsID(rightsID)
	if !strings.HasPrefix(strings.ToUpper(titleID), "0100646009FB") {
		t.Fatalf("titleID = %q, want the Dead Cells base 0100646009FB*", titleID)
	}
	if keyGen != 5 {
		t.Fatalf("keyGen = %d, want 5", keyGen)
	}

	// The generation must index an actual titlekek in prod.keys, and that
	// kek must decrypt the retail ciphertext to the openssl-checked key.
	kek := loadProdKey(t, fmt.Sprintf("titlekek_%02d", keyGen))
	if len(kek) != 16 {
		t.Fatalf("titlekek_%02d absent from prod.keys", keyGen)
	}
	titleKey, err := ExtractTitleKey(tik, kek)
	if err != nil {
		t.Fatalf("ExtractTitleKey: %v", err)
	}
	if want := mustHex(t, "8bade5239331240db1c12851b6e1a6bd"); !bytes.Equal(titleKey, want) {
		t.Errorf("titlekey = %x, want openssl-computed %x", titleKey, want)
	}
	if bytes.Equal(titleKey, enc) {
		t.Error("titlekey equals the encrypted form — kek was not applied")
	}

	// Tie the ticket to its content: the first content NCA's decrypted
	// header carries the same rights ID.
	crossCheckTicketAgainstNCA(t, nsp, entries, rightsID)
}

// loadProdKey reads one named key from the prod.keys fixture, skipping
// the test if the file is not present on this machine.
func loadProdKey(t *testing.T, name string) []byte {
	t.Helper()
	f, err := os.Open(prodKeysPath)
	if os.IsNotExist(err) {
		t.Skipf("prod.keys not present: %s", prodKeysPath)
	}
	if err != nil {
		t.Fatalf("opening prod.keys: %v", err)
	}
	t.Cleanup(func() { f.Close() })
	keys, err := ParseProdKeys(f)
	if err != nil {
		t.Fatalf("ParseProdKeys: %v", err)
	}
	return keys[name]
}

// crossCheckTicketAgainstNCA decrypts the first content NCA's header with
// header_key and verifies its rights ID matches the ticket's — proving
// the parsed ticket is the one these NCAs are encrypted under.
func crossCheckTicketAgainstNCA(t *testing.T, nsp io.ReaderAt, entries []FileEntry, rightsID []byte) {
	t.Helper()
	var ncaEntry *FileEntry
	for i := range entries {
		if strings.HasSuffix(entries[i].Name, ".nca") && !strings.HasSuffix(entries[i].Name, ".cnmt.nca") {
			ncaEntry = &entries[i]
			break
		}
	}
	if ncaEntry == nil {
		t.Fatal("no .nca entry in container")
	}
	hdr := make([]byte, NCAHeaderEncOffset+NCAHeaderEncSize)
	if _, err := io.ReadFull(ReadPFS0File(nsp, *ncaEntry), hdr); err != nil {
		t.Fatalf("reading NCA header: %v", err)
	}
	plain, err := DecryptNCAHeader(hdr, loadProdKey(t, "header_key"))
	if err != nil {
		t.Fatalf("DecryptNCAHeader: %v", err)
	}
	// The decrypted region is the header's second half: plaintext index
	// 0 is absolute header offset 0x200, so the rights ID (absolute
	// 0x230) sits at index 0x30. (The key area is at +0x100, not +0x70
	// as the original brief said — reencrypt.go owns that surface.)
	if got := plain[0x30:0x40]; !bytes.Equal(got, rightsID) {
		t.Fatalf("NCA header rights ID %x != ticket rights ID %x", got, rightsID)
	}
}
