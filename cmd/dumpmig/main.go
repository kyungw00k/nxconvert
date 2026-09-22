package main

import (
	"bytes"
	"fmt"
	"io"
	"os"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

func main() {
	src, err := os.Open("/tmp/dc-dump.xci")
	die(err)
	defer src.Close()
	entries, base, err := nxformat.ParseXCI(src)
	die(err)
	var files []nxformat.NamedReader
	for _, e := range entries {
		src.Seek(base+e.Offset, 0)
		data, err := io.ReadAll(io.LimitReader(src, e.Size))
		die(err)
		files = append(files, nxformat.NamedReader{Name: e.Name, Size: e.Size, R: bytes.NewReader(data)})
	}
	donor, err := os.Open("/Users/humphrey.park/Downloads/switch/Dead Cells.xci/Dead Cells.xci")
	die(err)
	defer donor.Close()
	st, _ := donor.Stat()
	out, err := os.Create("/tmp/dc-dumpmig.xci")
	die(err)
	defer out.Close()
	die(nxformat.TransplantXCI(out, donor, st.Size(), files))
	fmt.Println("wrote /tmp/dc-dumpmig.xci")
}

func die(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
