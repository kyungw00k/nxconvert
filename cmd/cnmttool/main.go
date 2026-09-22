package main

import (
	"crypto/aes"
	"crypto/cipher"
	"encoding/binary"
	"fmt"
	"io"
	"os"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

// cnmt 섹션 + fs_header 슈퍼블록 전수 분석
func main() {
	kf, _ := os.Open("/tmp/prod.keys")
	keys, _ := nxformat.ParseProdKeys(kf)
	kf.Close()
	hk := keys["header_key"]

	f, err := os.Open(os.Args[1])
	die(err)
	defer f.Close()
	entries, base, err := nxformat.ParsePFS0(f)
	die(err)
	for _, e := range entries {
		if len(e.Name) < 9 || e.Name[len(e.Name)-9:] != ".cnmt.nca" {
			continue
		}
		hdr := make([]byte, 0x400)
		f.Seek(base+e.Offset, 0)
		io.ReadFull(f, hdr)
		plain, err := nxformat.DecryptNCAHeader(hdr, hk)
		die(err)
		kaak := keys[nxformat.KAAKName(plain[7], plain[6], plain[0x20])]
		ka, _ := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
		secs := nxformat.ParseNCASections(plain)
		if len(secs) == 0 {
			continue
		}
		secOff, secSize := secs[0].Offset, secs[0].Size
		sec := make([]byte, secSize)
		f.Seek(base+e.Offset+secOff, 0)
		io.ReadFull(f, sec)
		block, _ := aes.NewCipher(ka[nxformat.NCASectionKeySlot])
		iv := make([]byte, 16)
		binary.BigEndian.PutUint64(iv[8:], uint64(secOff>>4))
		cipher.NewCTR(block, iv).XORKeyStream(sec, sec)

		pfs0Off := -1
		for i := 0; i < len(sec)-4; i++ {
			if string(sec[i:i+4]) == "PFS0" {
				pfs0Off = i
				break
			}
		}
		nf := binary.LittleEndian.Uint32(sec[pfs0Off+4:])
		ss := binary.LittleEndian.Uint32(sec[pfs0Off+8:])
		fsz := binary.LittleEndian.Uint64(sec[pfs0Off+0x10+8:])
		dataBase := pfs0Off + 0x10 + int(nf)*0x18 + int(ss)
		cnmt := sec[dataBase : dataBase+int(fsz)]

		fmt.Printf("=== %s ===\n", os.Args[2])
		fmt.Printf("섹션 %dB | PFS0@+%X | 테이블 %dB | cnmt %dB | 데이터@+%X\n",
			secSize, pfs0Off, pfs0Off, fsz, dataBase)

		// fs_header 슈퍼블록
		fsRaw := make([]byte, 0x200)
		f.Seek(base+e.Offset+0x400, 0)
		io.ReadFull(f, fsRaw)
		fs, err := nxformat.DecryptFSHeader(fsRaw, 0, hk)
		die(err)
		fmt.Println("fs_header[0:0x80] hexdump:")
		for i := 0; i < 0x80; i += 16 {
			fmt.Printf("  +%02X: %x\n", i, fs[i:i+16])
		}
		fmt.Printf("알려진 값 검색: PFS0오프셋 0x%X, 테이블크기 0x%X, cnmt크기 0x%X\n",
			pfs0Off, pfs0Off, fsz)
		for off := 0; off < 0x78; off += 4 {
			v := binary.LittleEndian.Uint64(append([]byte(nil), fs[off:off+8]...))
			if v == uint64(pfs0Off) || v == uint64(fsz) {
				fmt.Printf("  fs+0x%02X = 0x%X (%d)\n", off, v, v)
			}
		}
		_ = cnmt
		os.WriteFile(fmt.Sprintf("/tmp/sec_%s.bin", os.Args[2]), sec, 0644)
		os.WriteFile(fmt.Sprintf("/tmp/fs_%s.bin", os.Args[2]), fs, 0644)
		fmt.Printf("dumped /tmp/sec_%s.bin + fs_%s.bin\n\n", os.Args[2], os.Args[2])

	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
