package nxformat

import (
	"crypto/aes"
	"fmt"
)

// Ticket (.tik) layout, verified byte-exact against retail scene tickets
// (Cuphead, Dead Cells v3014656 update): the files are RSA-2048 signed
// tickets of exactly 0x2C0 bytes whose first u32 is signature type
// 0x00010004 (HakRsa2048, the homebrew-signed variant; Nintendo-issued
// tickets use 0x00010002 with the same body layout):
//
//	0x000  u32 signature type (0x00010002 / 0x00010004)
//	0x004  signature, padding, issuer ... (sig-dependent, unused here)
//	0x180  16-byte titlekey, encrypted with titlekek_<gen> (AES-ECB)
//	0x281  u8 ticket titlekey generation (mirrors rights_id gen)
//	0x2A0  16-byte rights ID = title ID (8 bytes, big-endian) ‖
//	       master-key generation (8 bytes, big-endian; the low byte is
//	       the titlekek_XX index)
//
// RSA-4096 tickets (0x00010001) shift the whole body by +0x100 and
// ECDSA-family tickets are only 0x240 bytes, so the fixed offsets below
// hold only for the two RSA-2048 layouts; other signature types are
// rejected rather than misread.
const (
	tikMinSize        = 0x2B0 // 0x2A0 + 16: the last byte the parser touches
	tikEncTitleKeyOff = 0x180
	tikRightsIDOff    = 0x2A0
	tikKeySize        = 16
	tikSigRSA2048     = 0x00010002
	tikSigHakRSA2048  = 0x00010004
)

// sigType returns the ticket's signature type from its first u32,
// little-endian like every other integer in these formats (retail
// tickets store 0x00010004 as the bytes 04 00 01 00).
func sigType(data []byte) uint32 {
	return uint32(data[0]) | uint32(data[1])<<8 | uint32(data[2])<<16 | uint32(data[3])<<24
}

// ParseTicket extracts the rights ID and the encrypted titlekey from a
// ticket. Both returned slices are copies and exactly 16 bytes long. The
// titlekey must still be decrypted with the titlekek for its generation —
// see ExtractTitleKey.
func ParseTicket(data []byte) (rightsID []byte, encryptedTitleKey []byte, err error) {
	if len(data) < tikMinSize {
		return nil, nil, fmt.Errorf("nxformat: ticket is %d bytes, need at least %#x", len(data), tikMinSize)
	}
	if st := sigType(data); st != tikSigRSA2048 && st != tikSigHakRSA2048 {
		return nil, nil, fmt.Errorf("nxformat: ticket signature type %#08x is not RSA-2048 (offsets only hold for types %#08x/%#08x)",
			st, tikSigRSA2048, tikSigHakRSA2048)
	}
	rightsID = append([]byte(nil), data[tikRightsIDOff:tikRightsIDOff+tikKeySize]...)
	encryptedTitleKey = append([]byte(nil), data[tikEncTitleKeyOff:tikEncTitleKeyOff+tikKeySize]...)
	return rightsID, encryptedTitleKey, nil
}

// ExtractTitleKey decrypts the titlekey of a ticket with titlekek using
// AES-128-ECB (a single block — the whole point of the titlekek wrap).
// titlekek must be the key matching the ticket's generation, i.e.
// titlekek_%02x of the rights ID's low byte from prod.keys.
func ExtractTitleKey(tikData []byte, titlekek []byte) (titleKey []byte, err error) {
	if len(titlekek) != tikKeySize {
		return nil, fmt.Errorf("nxformat: titlekek is %d bytes, want %d", len(titlekek), tikKeySize)
	}
	_, encrypted, err := ParseTicket(tikData)
	if err != nil {
		return nil, err
	}
	block, err := aes.NewCipher(titlekek)
	if err != nil {
		return nil, fmt.Errorf("nxformat: titlekek: %w", err)
	}
	titleKey = make([]byte, tikKeySize)
	block.Decrypt(titleKey, encrypted)
	return titleKey, nil
}

// ParseRightsID splits a rights ID into its title ID (first 8 bytes as
// lowercase hex, the convention used by ticket filenames like
// "0100646009fbe800....tik") and the master-key generation (the low byte
// of the trailing 8-byte big-endian counter — the index of the
// titlekek_XX / key_area_key_application_XX keys to use). A rights ID
// shorter than 16 bytes cannot hold either field; "" and -1 are returned
// so a malformed value fails at the key lookup, not with a panic.
func ParseRightsID(rightsID []byte) (titleID string, keyGen int) {
	if len(rightsID) < 16 {
		return "", -1
	}
	const hexDigits = "0123456789abcdef"
	buf := make([]byte, 0, 16)
	for _, b := range rightsID[:8] {
		buf = append(buf, hexDigits[b>>4], hexDigits[b&0xF])
	}
	return string(buf), int(rightsID[15])
}
