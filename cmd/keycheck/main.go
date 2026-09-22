package main

import (
	"encoding/hex"
	"fmt"
	"io"
	"os"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

func main() {
	kf, _ := os.Open("/tmp/prod.keys")
	keys, _ := nxformat.ParseProdKeys(kf)
	kf.Close()
	hk := keys["header_key"]

	f, err := os.Open(os.Args[1])
	die(err)
	defer f.Close()

	// 카드 헤더
	hdr := make([]byte, 0x90)
	f.Seek(0x100, 0)
	io.ReadFull(f, hdr)
	fmt.Printf("PkgId: %s | RomSize: 0x%02X\n", hex.EncodeToString(hdr[0x10:0x18]), hdr[0x0D])

	entries, base, err := nxformat.ParseXCI(f)
	die(err)

	fmt.Printf("Secure @0x%X: %d NCAs\n\n", base, len(entries))
	for _, e := range entries {
		hdr4 := make([]byte, 0x400)
		f.Seek(base+e.Offset, 0)
		if _, err := io.ReadFull(f, hdr4); err != nil {
			fmt.Printf("%-18s %12d  READ_ERR\n", e.Name[:min(16, len(e.Name))], e.Size)
			continue
		}
		plain, err := nxformat.DecryptNCAHeader(hdr4, hk)
		if err != nil || string(plain[0:4]) != "NCA3" {
			fmt.Printf("%-18s %12d  DECRYPT_FAIL\n", e.Name[:min(16, len(e.Name))], e.Size)
			continue
		}
		dist := plain[4]
		gen := plain[6]
		if plain[0x20] > gen {
			gen = plain[0x20]
		}
		ctype := []string{"Meta", "Prog", "Data", "Ctrl", "Html", "Lgl", "Dlt"}[plain[5]]
		rights := "-"
		for _, b := range plain[0x30:0x40] {
			if b != 0 {
				rights = "R"
				break
			}
		}
		rev := gen - 1
		kaak := keys[fmt.Sprintf("key_area_key_application_%02d", rev)]
		s2 := "(no_key)"
		if kaak != nil {
			ka, _ := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
			s2 = hex.EncodeToString(ka[2])[:8]
		}
		fmt.Printf("%-18s %12d  dist=0x%02X gen=%d %s %s slot2=%s\n",
			e.Name[:min(16, len(e.Name))], e.Size, dist, gen, ctype, rights, s2)
	}
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
