package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

// key_area 슬롯 패턴 비교: 카드 "덤프" vs CDN NSP vs UPD NSP
func main() {
	kf, _ := os.Open("/tmp/prod.keys")
	keys, _ := nxformat.ParseProdKeys(kf)
	kf.Close()
	hk := keys["header_key"]

	check := func(path, label string) {
		f, err := os.Open(path)
		die(err)
		defer f.Close()
		entries, base, err := nxformat.ParsePFS0(f)
		die(err)
		for _, e := range entries {
			if len(e.Name) < 4 || e.Name[len(e.Name)-4:] != ".nca" {
				continue
			}
			if e.Size < 100000 { // 큰 것 위주 (program)
				continue
			}
			hdr := make([]byte, 0x400)
			f.Seek(base+e.Offset, 0)
			io.ReadFull(f, hdr)
			plain, err := nxformat.DecryptNCAHeader(hdr, hk)
			die(err)
			kaakName := nxformat.KAAKName(plain[7], plain[6], plain[0x20])
			kaak := keys[kaakName]
			ka, err := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
			die(err)
			rights := "없음"
			for _, b := range plain[0x30:0x40] {
				if b != 0 {
					rights = "있음"
					break
				}
			}
			fmt.Printf("%s | %-40s dist=0x%02X rights=%s gen=%d\n", label, e.Name[:min(36, len(e.Name))], plain[4], rights, max(plain[6], plain[0x20]))
			fmt.Printf("   slot0=%s\n   slot1=%s\n   slot2=%s\n   slot3=%s\n",
				hex.EncodeToString(ka[0])[:16], hex.EncodeToString(ka[1])[:16],
				hex.EncodeToString(ka[2])[:16], hex.EncodeToString(ka[3])[:16])
			pattern := "같음k"
			if allZeroB(ka[0]) && allZeroB(ka[1]) && allZeroB(ka[3]) {
				pattern = "{0,0,key,0} ← 실물 리테일 패턴"
			} else if eq(ka[0], ka[1]) && eq(ka[1], ka[3]) {
				pattern = "{k,k,key,k} ← 변환기 패턴(전슬롯 채움)"
			}
			fmt.Printf("   패턴: %s\n\n", pattern)
		}
	}

	// 1. 카드 "덤프"의 program NCA (secure @0x17018200)
	checkXCI("/Users/humphrey.park/Downloads/switch/Dead Cells.xci/Dead Cells.xci", "카드덤프")
	// 2. CDN BASE NSP
	check("/Users/humphrey.park/Downloads/switch/Dead Cells/Dead Cells [BASE][0100646009FB][v0].nsp", "CDN BASE")
	// 3. UPD NSP (rights 있음)
	check("/Users/humphrey.park/Downloads/switch/Dead Cells/update/Dead Cells [UPD][0100646009FBE800][v3014656].nsp", "CDN UPD ")
}

func checkXCI(path, label string) {
	f, err := os.Open(path)
	die(err)
	defer f.Close()
	entries, base, err := nxformat.ParseXCI(f)
	die(err)
	for _, e := range entries {
		if e.Size < 100000 {
			continue
		}
		hdr := make([]byte, 0x400)
		f.Seek(base+e.Offset, 0)
		io.ReadFull(f, hdr)
		kf2, _ := os.Open("/tmp/prod.keys")
		keys2, _ := nxformat.ParseProdKeys(kf2)
		kf2.Close()
		plain, err := nxformat.DecryptNCAHeader(hdr, keys2["header_key"])
		die(err)
		kaak := keys2[nxformat.KAAKName(plain[7], plain[6], plain[0x20])]
		ka, err := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
		die(err)
		fmt.Printf("%s | %-40s dist=0x%02X gen=%d\n", label, e.Name[:min(36, len(e.Name))], plain[4], max(plain[6], plain[0x20]))
		fmt.Printf("   slot0=%s\n   slot1=%s\n   slot2=%s\n   slot3=%s\n",
			hex.EncodeToString(ka[0])[:16], hex.EncodeToString(ka[1])[:16],
			hex.EncodeToString(ka[2])[:16], hex.EncodeToString(ka[3])[:16])
		p := "같음k"
		if allZeroB(ka[0]) && allZeroB(ka[1]) && allZeroB(ka[3]) {
			p = "{0,0,key,0} ← 실물 리테일 패턴"
		} else if eq(ka[0], ka[1]) && eq(ka[1], ka[3]) {
			p = "{k,k,key,k} ← 변환기 패턴"
		}
		fmt.Printf("   패턴: %s\n\n", p)
	}
}

func eq(a, b []byte) bool { return string(a) == string(b) }
func allZeroB(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
