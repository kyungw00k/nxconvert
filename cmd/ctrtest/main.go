package main

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"fmt"
	"io"
	"os"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

func main() {
	// CDN control NCA 읽기
	nsp, err := os.Open("/Users/humphrey.park/Downloads/switch/Dead Cells/Dead Cells [BASE][0100646009FB][v0].nsp")
	die(err)
	defer nsp.Close()
	entries, base, err := nxformat.ParsePFS0(nsp)
	die(err)
	var ctrl nxformat.FileEntry
	for _, e := range entries {
		if len(e.Name) > 4 && e.Name[0:4] == "c870" {
			ctrl = e
		}
	}
	nsp.Seek(base+ctrl.Offset, 0)
	full, err := io.ReadAll(io.NewSectionReader(nsp, base+ctrl.Offset, ctrl.Size))
	die(err)
	fmt.Printf("control NCA: %d bytes\n", len(full))

	kf, _ := os.Open("/tmp/prod.keys")
	keys, _ := nxformat.ParseProdKeys(kf)
	kf.Close()
	hk := keys["header_key"]

	plain, err := nxformat.DecryptNCAHeader(full[:0x400], hk)
	die(err)

	// slot2 키
	kaak := keys["key_area_key_application_03"]
	ka, _ := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
	oldKey := ka[2]
	fmt.Printf("oldKey: %x\n", oldKey)

	// 섹션
	secs := nxformat.ParseNCASections(plain)
	fmt.Printf("sections: %d\n", len(secs))
	for _, s := range secs {
		fmt.Printf("  slot=%d ord=%d off=0x%X size=%d\n", s.Slot, s.Ordinal, s.Offset, s.Size)
	}

	// fs_header[0] → IV
	fsRaw := full[0x400:0x600]
	fsPlain, err := nxformat.DecryptFSHeader(fsRaw, 0, hk)
	die(err)
	iv := nxformat.SectionIV(fsPlain, secs[0].Offset)
	fmt.Printf("IV: %x\n", iv)
	fmt.Printf("fs section_ctr: %x\n", fsPlain[0x140:0x148])

	// 수동 CTR 복호화 → 평문
	block, _ := aes.NewCipher(oldKey)
	secData := full[secs[0].Offset : secs[0].Offset+secs[0].Size]
	manualPlain := make([]byte, 32)
	stream := cipher.NewCTR(block, iv)
	stream.XORKeyStream(manualPlain, secData[:32])
	fmt.Printf("수동 복호화 첫 16B: %x\n", manualPlain[:16])

	// ReencryptNCA로 재암호화
	newKey := []byte{0xDE, 0xAD, 0xBE, 0xEF, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}
	var buf bytes.Buffer
	buf.Grow(len(full))
	ivs := [][]byte{iv}
	offs := []int64{secs[0].Offset}
	sizes := []int64{secs[0].Size}
	err = nxformat.ReencryptNCA(bytes.NewReader(full), &buf, oldKey, newKey, ivs, offs, sizes)
	die(err)
	re := buf.Bytes()
	fmt.Printf("재암호화 출력: %d bytes (원본 %d)\n", len(re), len(full))

	// 재암호화된 섹션을 newKey로 복호화
	newBlock, _ := aes.NewCipher(newKey)
	newStream := cipher.NewCTR(newBlock, iv)
	check := make([]byte, 32)
	newStream.XORKeyStream(check, re[secs[0].Offset:secs[0].Offset+32])
	fmt.Printf("newKey 복호화 첫 16B: %x\n", check[:16])
	fmt.Printf("평문 일치: %v\n", bytes.Equal(check, manualPlain))

	// 원본과 비교 (헤더 영역은 동일해야)
	fmt.Printf("헤더[0:0x200] 동일: %v\n", bytes.Equal(re[:0x200], full[:0x200]))
	fmt.Printf("fs_headers 동일: %v\n", bytes.Equal(re[0x400:0xC00], full[0x400:0xC00]))
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
