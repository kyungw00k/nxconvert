// nxconvert converts Nintendo Switch container files between NSP
// (PFS0) and XCI (gamecard HFS0) images by streaming container entries.
//
// Usage:
//
//	nxconvert to-nsp input.xci [-o output.nsp]
//	nxconvert to-xci input.nsp [-o output.xci]
//
// Both directions stream one entry at a time; input files are never loaded
// into memory whole. Progress is written to stderr, one line per entry.
package main

import (
	"bufio"
	"encoding/binary"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/kyungw00k/nxconvert/internal/nxformat"
)

const usageText = `Usage:
  nxconvert to-nsp input.xci [-o output.nsp]
  nxconvert to-xci input.nsp [-o output.xci]

nxconvert converts Nintendo Switch containers by streaming entries between
the XCI gamecard image and the NSP distribution container:

  to-nsp  Every file of the XCI's secure partition (HFS0) is streamed into a
          new PFS0 container. All secure-partition files are carried over.
  to-xci  Every file of the NSP container (including any .tik/.cert) is
          streamed into the secure partition of a newly built gamecard image.
          The gamecard header is a synthetic template: a zeroed 0xF000-byte
          header zone with the "HEAD" magic at 0x100, followed by the root
          HFS0 at 0xF000 with empty update/normal partitions.

Options (both subcommands):
  -o path      Output file. Default: the input path with its extension replaced
           by .nsp (to-nsp) or .xci (to-xci). An existing output file is
           never overwritten; a failed conversion removes its partial output.
  --keys path Optional prod.keys file. When given, the NCA distribution byte
          is rewritten for the target container (0x01 gamecard for to-xci,
          0x00 download for to-nsp) using the global header_key; content
          hashes are unaffected (they exclude the header). Auto-discovered
          at ~/.switch/prod.keys and ~/switch-prod.keys. The key is read at
          runtime and never embedded or written to outputs.
`

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintf(os.Stderr, "nxconvert: %v\n", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usageExit()
	}
	switch args[0] {
	case "to-nsp":
		return convertToNSP(args[1:])
	case "to-xci":
		return convertToXCI(args[1:])
	case "help", "-h", "--help":
		fmt.Print(usageText)
		return nil
	default:
		fmt.Fprintf(os.Stderr, "nxconvert: unknown subcommand %q\n\n", args[0])
		usageExit()
	}
	panic("unreachable")
}

func usageExit() {
	fmt.Fprint(os.Stderr, usageText)
	os.Exit(2)
}

// convertToNSP streams every file of an XCI's secure partition into a new
// PFS0 (NSP) container.
func convertToNSP(args []string) error {
	fs := flag.NewFlagSet("to-nsp", flag.ExitOnError)
	keysFlag := fs.String("keys", "", "prod.keys path (enables NCA distribution rewrite)")
	outFlag := fs.String("o", "", "output NSP path (default: input path with `.nsp`)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxconvert to-nsp input.xci [-o output.nsp]")
		fmt.Fprintln(os.Stderr, "Run 'nxconvert help' for full usage.")
	}
	if err := fs.Parse(permuteFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	inPath := fs.Arg(0)
	outPath, err := resolveOutput(inPath, *outFlag, ".nsp")
	if err != nil {
		return err
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	// Walk the gamecard header to the secure partition. ParseXCI reports the
	// secure partition's data-area base directly, so entry offsets are added
	// to it as-is.
	secure, secureBase, err := nxformat.ParseXCI(in)
	if err != nil {
		return fmt.Errorf("parse %s as XCI: %w", inPath, err)
	}
	if len(secure) == 0 {
		return fmt.Errorf("%s: gamecard secure partition holds no files", inPath)
	}

	st, err := in.Stat()
	if err != nil {
		return err
	}
	files := make([]nxformat.NamedReader, len(secure))
	var total int64
	for i, e := range secure {
		abs := secureBase + e.Offset
		if abs+e.Size > st.Size() {
			return fmt.Errorf("%s: entry %s extends past end of file (truncated input?)", inPath, e.Name)
		}
		total += e.Size
		files[i] = nxformat.NamedReader{
			Name: e.Name,
			Size: e.Size,
			R:    newProgressReader(e.Name, e.Size, io.NewSectionReader(in, abs, e.Size)),
		}
	}

	fmt.Fprintf(os.Stderr, "to-nsp: %s -> %s (%d files, %.1f MB)\n", inPath, outPath, len(files), megaBytes(total))
	headerKey, err := loadHeaderKey(*keysFlag)
	if err != nil {
		return err
	}
	if err := patchNCADistribution(files, headerKey, nxformat.DistributionDownload); err != nil {
		return err
	}
	if err := writeOutput(outPath, func(w io.Writer) error {
		return nxformat.WritePFS0(w, files)
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	return nil
}

// convertToXCI streams every file of an NSP container into the secure
// partition of a newly built gamecard (XCI) image.
func convertToXCI(args []string) error {
	fs := flag.NewFlagSet("to-xci", flag.ExitOnError)
	outFlag := fs.String("o", "", "output XCI path (default: input path with `.xci`)")
	keysFlag := fs.String("keys", "", "prod.keys path (enables NCA distribution rewrite)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxconvert to-xci input.nsp [-o output.xci]")
		fmt.Fprintln(os.Stderr, "Run 'nxconvert help' for full usage.")
	}
	if err := fs.Parse(permuteFlags(args)); err != nil {
		return err
	}
	if fs.NArg() != 1 {
		fs.Usage()
		os.Exit(2)
	}
	inPath := fs.Arg(0)
	outPath, err := resolveOutput(inPath, *outFlag, ".xci")
	if err != nil {
		return err
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	entries, headerSize, err := nxformat.ParsePFS0(in)
	if err != nil {
		return fmt.Errorf("parse %s as NSP: %w", inPath, err)
	}
	if len(entries) == 0 {
		return fmt.Errorf("%s: container holds no files", inPath)
	}

	st, err := in.Stat()
	if err != nil {
		return err
	}
	files := make([]nxformat.NamedReader, len(entries))
	var total int64
	for i, e := range entries {
		if headerSize+e.Offset+e.Size > st.Size() {
			return fmt.Errorf("%s: entry %s extends past end of file (truncated input?)", inPath, e.Name)
		}
		total += e.Size
		files[i] = nxformat.NamedReader{
			Name: e.Name,
			Size: e.Size,
			R:    newProgressReader(e.Name, e.Size, nxformat.ReadPFS0File(in, e)),
		}
	}

	headerKey, err := loadHeaderKey(*keysFlag)
	if err != nil {
		return err
	}
	if err := patchNCADistribution(files, headerKey, nxformat.DistributionGamecard); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "to-xci: %s -> %s (%d files, %.1f MB)\n", inPath, outPath, len(files), megaBytes(total))
	if err := writeOutput(outPath, func(w io.Writer) error {
		return nxformat.WriteXCI(w, gamecardHeaderTemplate(), files)
	}); err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	return nil
}

// gamecardHeaderTemplate returns the fixed 0xF000-byte gamecard header zone
// that precedes the root HFS0 partition of an XCI, following the layout
// observed on retail dumps (verified against the crysis sample header):
//
//   - 0x0000..0x00FF: RSA-2048 signature area. Real dumps carry per-card
//     garbage here; a zeroed area is accepted for conversion output.
//   - 0x0100: "HEAD" magic starting the gamecard header body, plus the
//     constant fields retail images share: u8 @0x104 = 0x7b, u32 @0x108 =
//     0xFFFFFFFF, u32 @0x130 = 0xF000 (the root HFS0 offset).
//     Per-card fields (package id etc.) stay zeroed.
//   - 0xF000: root HFS0 partition, written by nxformat.WriteXCI with the
//     empty "update"/"normal" partitions (0x200-byte bare HFS0 headers) and
//     the "secure" partition carrying the converted files. WriteXCI also
//     patches the last-valid-data-page field (u64 @0x118) into this
//     template based on the final output size.
func gamecardHeaderTemplate() [0xF000]byte {
	var h [0xF000]byte
	copy(h[0x100:], "HEAD")
	h[0x104] = 0x7b
	binary.LittleEndian.PutUint32(h[0x108:0x10C], 0xFFFFFFFF)
	binary.LittleEndian.PutUint32(h[0x130:0x134], 0xF000)
	return h
}

// resolveOutput picks the output path: the -o flag value if given, otherwise
// the input path with its extension replaced by ext. It refuses a path that
// would overwrite the input.
func resolveOutput(inPath, outFlag, ext string) (string, error) {
	out := outFlag
	if out == "" {
		base := strings.TrimSuffix(filepath.Base(inPath), filepath.Ext(inPath))
		if base == "" {
			base = filepath.Base(inPath)
		}
		out = filepath.Join(filepath.Dir(inPath), base+ext)
	}
	if out == inPath {
		return "", fmt.Errorf("output path %s would overwrite the input; pass -o to choose another path", out)
	}
	return out, nil
}

// writeOutput creates path (never overwriting an existing file), streams
// fn's output through a 1 MiB buffer, and removes the partial file again if
// any step fails.
func writeOutput(path string, fn func(w io.Writer) error) (err error) {
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o644)
	if err != nil {
		if os.IsExist(err) {
			return fmt.Errorf("output %s already exists (nxconvert does not overwrite; pass -o to choose another path)", path)
		}
		return err
	}
	defer func() {
		if closeErr := f.Close(); err == nil {
			err = closeErr
		}
		if err != nil {
			os.Remove(path)
		}
	}()
	w := bufio.NewWriterSize(f, 1<<20)
	if err = fn(w); err != nil {
		return err
	}
	if err = w.Flush(); err != nil {
		return err
	}
	return nil
}

// permuteFlags reorders args so flag tokens precede positional arguments,
// letting the documented "input.xci -o out.nsp" order work with the flag
// package (which stops flag parsing at the first positional). "-o" is the
// only flag that consumes a separate value argument.
func permuteFlags(args []string) []string {
	var flags, positional []string
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--":
			positional = append(positional, args[i+1:]...)
			return append(flags, positional...)
		case a == "-o" || a == "--o" || a == "--keys":
			flags = append(flags, a)
			if i+1 < len(args) {
				i++
				flags = append(flags, args[i])
			}
		case strings.HasPrefix(a, "--keys="):
			flags = append(flags, a)
		case strings.HasPrefix(a, "-"):
			flags = append(flags, a)
		default:
			positional = append(positional, a)
		}
	}
	return append(flags, positional...)
}

// progressReader counts the bytes streamed through it and reports one stderr
// line (entry name and megabytes) once the entry's known size has been read.
// The line fires on EOF or when the known size is reached, whichever comes
// first, so it works with both io.Copy-to-EOF and exact-size (io.CopyN)
// consumers. It also implements io.Seeker by forwarding to the wrapped
// reader: nxformat.WriteXCI hashes the first 0x200 bytes of each entry and
// then rewinds and streams the full entry, so seekability avoids its
// temp-file spool fallback; the extra hash-pass bytes only ever inflate the
// reported count by at most 0x200 bytes and never trigger the line early
// for entries larger than that.
type progressReader struct {
	name     string
	size     int64
	r        io.Reader
	n        int64
	reported bool
}

func newProgressReader(name string, size int64, r io.Reader) *progressReader {
	p := &progressReader{name: name, size: size, r: r}
	if size == 0 {
		// Writers skip reading empty entries entirely, so report now.
		p.reported = true
		fmt.Fprintf(os.Stderr, "  %s (0.0 MB)\n", name)
	}
	return p
}

func (p *progressReader) Read(buf []byte) (int, error) {
	n, err := p.r.Read(buf)
	p.n += int64(n)
	if !p.reported && (err == io.EOF || (p.size > 0 && p.n >= p.size)) {
		p.reported = true
		fmt.Fprintf(os.Stderr, "  %s (%.1f MB)\n", p.name, megaBytes(p.n))
	}
	return n, err
}

// Seek forwards to the wrapped reader so the XCI writer can rewind entries
// for its hash pass; the byte counter keeps running across the rewind by
// design (see the type comment).
func (p *progressReader) Seek(off int64, whence int) (int64, error) {
	s, ok := p.r.(io.Seeker)
	if !ok {
		return 0, fmt.Errorf("progressReader: entry %q is not seekable", p.name)
	}
	return s.Seek(off, whence)
}

func megaBytes(n int64) float64 { return float64(n) / 1e6 }

// loadHeaderKey resolves the global header_key from --keys, the
// NXSHELF_PROD_KEYS environment variable, or the conventional prod.keys
// locations. A nil key means "no key given" (keyless repack).
func loadHeaderKey(keysFlag string) ([]byte, error) {
	candidates := []string{}
	if keysFlag != "" {
		candidates = append(candidates, keysFlag)
	}
	if env := os.Getenv("NXSHELF_PROD_KEYS"); env != "" {
		candidates = append(candidates, env)
	}
	if home, err := os.UserHomeDir(); err == nil {
		candidates = append(candidates,
			filepath.Join(home, ".switch", "prod.keys"),
			filepath.Join(home, "switch-prod.keys"),
		)
	}
	for _, p := range candidates {
		f, err := os.Open(p)
		if err != nil {
			continue
		}
		keys, err := nxformat.ParseProdKeys(f)
		_ = f.Close()
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", p, err)
		}
		hk, ok := keys["header_key"]
		if !ok || len(hk) != 32 {
			return nil, fmt.Errorf("%s: header_key missing or not 32 bytes", p)
		}
		fmt.Fprintf(os.Stderr, "keys: using header_key from %s\n", p)
		return hk, nil
	}
	if keysFlag != "" {
		return nil, fmt.Errorf("--keys %s: not found (and no prod.keys at conventional paths)", keysFlag)
	}
	return nil, nil
}

// patchNCADistribution wraps the i-th file for target-container semantics
// when a header key is available. Only .nca entries are touched.
func patchNCADistribution(files []nxformat.NamedReader, headerKey []byte, want byte) error {
	if headerKey == nil {
		return nil
	}
	for i, f := range files {
		if !strings.HasSuffix(f.Name, ".nca") {
			continue
		}
		rs, ok := f.R.(io.ReadSeeker)
		if !ok {
			return fmt.Errorf("%s: entry reader not seekable; distribution patch unsupported", f.Name)
		}
		patched, was, err := nxformat.PatchDistribution(rs, headerKey, want)
		if err != nil {
			return fmt.Errorf("%s: %w", f.Name, err)
		}
		if was != want {
			fmt.Fprintf(os.Stderr, "  %s: distribution 0x%02X -> 0x%02X\n", f.Name, was, want)
		}
		files[i].R = patched
	}
	return nil
}
