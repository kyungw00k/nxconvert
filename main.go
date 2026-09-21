// nxconvert converts Nintendo Switch container files between NSP
// (PFS0) and XCI (gamecard HFS0) images by streaming container entries.
//
// Usage:
//
//	nxconvert to-nsp input.xci [-o output.nsp]
//	nxconvert to-xci input1.nsp [input2.nsp ...] [-o output.xci]
//
// Both directions stream one entry at a time; input files are never loaded
// into memory whole. Progress is written to stderr, one line per entry.
package main

import (
	"bufio"
	"crypto/rand"
	"encoding/binary"
	"encoding/hex"
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
  nxconvert to-xci input1.nsp [input2.nsp ...] [-o output.xci]
  nxconvert split input.xci [-o output_dir] [--keys prod.keys]

nxconvert converts Nintendo Switch containers by streaming entries between
the XCI gamecard image and the NSP distribution container:

  to-nsp  Every file of the XCI/XCZ secure partition (HFS0) is streamed
          into a new PFS0 container. .ncz entries are decompressed to .nca.
  to-xci  One or more NSP/NSZ containers: every file (including any
          .tik/.cert) is streamed into the secure partition of a single
          newly built gamecard. Entries whose name already appeared in an
          earlier input are skipped (first input wins; list BASE before
          UPDATE/DLC). .ncz entries are decompressed to .nca.
          The gamecard header is a synthetic template: a zeroed 0xF000-byte
          header zone with the "HEAD" magic at 0x100, followed by the root
          HFS0 at 0xF000 with empty update/normal partitions.
  split   The secure partition is regrouped by content: each NCA's title ID
          (decrypted from its header with header_key) sorts it into the base
          game, the update, or a DLC group, and every group is written as
          its own NSP named TYPE_TITLEID.nsp (BASE_/UPD_/DLC_). .tik/.cert/
          .xml files ride along with their title's group. Needs --keys.

Options (all subcommands):
  -o path      Output file. Default: the first input's path with its extension replaced
           by .nsp (to-nsp) or .xci (to-xci). An existing output file is
           never overwritten; a failed conversion removes its partial output.
  --keys path Optional prod.keys file.
  --card-titlekey hex  32-hex gamecard titlekey. When given (with --keys),
          NCA section keys are re-derived from this key: sections are
          decrypted with the CDN-derived key and re-encrypted with the
          gamecard key, making the XCI usable on MIG flashcarts. When given, the NCA distribution byte
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
	case "split":
		return splitXCI(args[1:])
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

	// Walk the gamecard header to the secure partition (works for both
	// .xci and .xcz — the container structure is identical).
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
	tracker := NewProgress(0)
	for i, e := range secure {
		abs := secureBase + e.Offset
		if abs+e.Size > st.Size() {
			return fmt.Errorf("%s: entry %s extends past end of file (truncated input?)", inPath, e.Name)
		}
		total += e.Size
		files[i] = nxformat.NamedReader{
			Name: e.Name,
			Size: e.Size,
			R:    newTrackedReader(e.Name, e.Size, io.NewSectionReader(in, abs, e.Size), tracker),
		}
	}
	tracker.SetTotal(total)
	tui := runProgressTUI(tracker)

	// Decompress .ncz entries (XCZ input)
	var cleanup func()
	if hasSuffix(inPath, ".xcz") {
		var err error
		cleanup, err = decompressNCZEntries(files, in)
		if err != nil {
			return err
		}
		defer cleanup()
	}

	fmt.Fprintf(os.Stderr, "to-nsp: %s -> %s (%d files, %.1f MB)\n", inPath, outPath, len(files), megaBytes(total))
	headerKey, err := loadHeaderKey(*keysFlag)
	if err != nil {
		return err
	}
	if err := patchNCADistribution(files, headerKey, nxformat.DistributionDownload); err != nil {
		return err
	}
	err = writeOutput(outPath, func(w io.Writer) error {
		return nxformat.WritePFS0(w, files)
	})
	tracker.Finish(err)
	WaitForDone(tui)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	return nil
}

// convertToXCI streams every file of one or more NSP containers into the
// secure partition of a newly built gamecard (XCI) image. Inputs are merged
// in the given order; entries whose name already appeared in an earlier
// input are skipped, so a BASE NSP listed before an UPDATE NSP keeps its
// copy of shared meta files.
func convertToXCI(args []string) error {
	fs := flag.NewFlagSet("to-xci", flag.ExitOnError)
	outFlag := fs.String("o", "", "output XCI path (default: first input path with `.xci`)")
	keysFlag := fs.String("keys", "", "prod.keys path (enables NCA distribution rewrite)")
	cardTitleKeyFlag := fs.String("card-titlekey", "", "32-hex gamecard titlekey for MIG re-encryption (requires --keys)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxconvert to-xci input1.nsp [input2.nsp ...] [-o output.xci]")
		fmt.Fprintln(os.Stderr, "Run 'nxconvert help' for full usage.")
	}
	if err := fs.Parse(permuteFlags(args)); err != nil {
		return err
	}
	if fs.NArg() < 1 {
		fs.Usage()
		os.Exit(2)
	}
	if fs.Arg(0) == "help" || fs.Arg(0) == "-h" || fs.Arg(0) == "--help" {
		fs.Usage()
		return nil
	}
	inPaths := fs.Args()
	outPath, err := resolveOutput(inPaths[0], *outFlag, ".xci")
	if err != nil {
		return err
	}
	for _, inPath := range inPaths {
		if outPath == inPath {
			return fmt.Errorf("output path %s would overwrite the input; pass -o to choose another path", outPath)
		}
	}

	var files []nxformat.NamedReader
	seen := make(map[string]bool)
	var total int64
	for _, inPath := range inPaths {
		in, err := os.Open(inPath)
		if err != nil {
			return err
		}
		defer in.Close() // entries stream lazily; every input stays open until the XCI is written

		entries, headerSize, err := nxformat.ParsePFS0(in)
		if err != nil {
			return fmt.Errorf("parse %s as NSP/NSZ: %w", inPath, err)
		}
		if len(entries) == 0 {
			return fmt.Errorf("%s: container holds no files", inPath)
		}

		st, err := in.Stat()
		if err != nil {
			return err
		}
		var inTotal int64
		var dups int
		for _, e := range entries {
			if headerSize+e.Offset+e.Size > st.Size() {
				return fmt.Errorf("%s: entry %s extends past end of file (truncated input?)", inPath, e.Name)
			}
			if seen[e.Name] {
				dups++
				continue
			}
			seen[e.Name] = true
			inTotal += e.Size
			files = append(files, nxformat.NamedReader{
				Name: e.Name,
				Size: e.Size,
				R:    newProgressReader(e.Name, e.Size, nxformat.ReadPFS0File(in, e)),
			})
		}
		total += inTotal
		fmt.Fprintf(os.Stderr, "  %s: %d files", inPath, len(entries)-dups)
		if dups > 0 {
			fmt.Fprintf(os.Stderr, ", %d duplicate(s) skipped", dups)
		}
		fmt.Fprintf(os.Stderr, ", %.1f MB\n", megaBytes(inTotal))
	}

	headerKey, err := loadHeaderKey(*keysFlag)
	if err != nil {
		return err
	}
	if err := patchNCADistribution(files, headerKey, nxformat.DistributionGamecard); err != nil {
		return err
	}
	// Gamecard titlekey re-encryption (MIG support)
	if *cardTitleKeyFlag != "" {
		if len(*keysFlag) == 0 && *cardTitleKeyFlag != "" {
			// --card-titlekey given without --keys; try auto-discover
		}
		cardTitleKey, err := parseHexKey(*cardTitleKeyFlag)
		if err != nil {
			return fmt.Errorf("--card-titlekey: %w (expected 32 hex chars)", err)
		}
		// Load prod.keys for CDN key extraction
		headerKey, err := loadHeaderKey(*keysFlag)
		if err != nil {
			return err
		}
		if headerKey == nil {
			return fmt.Errorf("--card-titlekey requires --keys (or prod.keys at a standard path)")
		}
		fmt.Fprintf(os.Stderr, "card-titlekey: %x (MIG re-encryption mode)\n", cardTitleKey)
		if err := reencryptForMIG(files, headerKey, cardTitleKey, inPaths); err != nil {
			return fmt.Errorf("MIG re-encryption: %w", err)
		}
	}

	// Set up progress tracking
	tracker := NewProgress(total)
	tui := runProgressTUI(tracker)
	for i := range files {
		if pr, ok := files[i].R.(*progressReader); ok {
			pr.tracker = tracker
		}
	}

	// Decompress .ncz entries (NSZ inputs). Entries from plain NSPs are
	// skipped by name; the fallback ReaderAt is never needed because PFS0
	// entry readers are section readers over their own input file.
	cleanup, err := decompressNCZEntries(files, nil)
	if err != nil {
		return err
	}
	defer cleanup()

	fmt.Fprintf(os.Stderr, "to-xci: %d input(s) -> %s (%d files, %.1f MB)\n", len(inPaths), outPath, len(files), megaBytes(total))
	err = writeOutput(outPath, func(w io.Writer) error {
		return nxformat.WriteXCI(w, gamecardHeaderTemplate(), files)
	})
	tracker.Finish(err)
	WaitForDone(tui)
	if err != nil {
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
		case a == "-o" || a == "--o" || a == "--keys" || a == "--card-titlekey":
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
	tracker  *Progress // non-nil = TUI mode, suppress stderr
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
	if p.tracker != nil {
		p.tracker.Add(int64(n))
		p.tracker.SetFile(p.name)
	} else if !p.reported && (err == io.EOF || (p.size > 0 && p.n >= p.size)) {
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

// decompressNCZEntries finds .ncz entries in the files slice, decompresses
// each to a temp file (.nca), and replaces the entry. The returned cleanup
// function removes all temp files and must be called after conversion.
func decompressNCZEntries(files []nxformat.NamedReader, in io.ReaderAt) (func(), error) {
	var cleanups []func()
	for i, f := range files {
		if !strings.HasSuffix(f.Name, ".ncz") {
			continue
		}
		// Find the entry's position: the NamedReader wraps a SectionReader
		// created by the caller; we need the raw underlying reader. The
		// progressReader forwards to it, so extract from there.
		pr, ok := f.R.(*progressReader)
		if !ok {
			continue // not a progressReader — shouldn't happen
		}
		sr, ok := pr.r.(io.ReaderAt)
		if !ok {
			sr = in // fall back to the whole file
		}
		newEntry, cleanup, err := decompressOneNCZ(f.Name, sr, f.Size)
		if err != nil {
			for _, c := range cleanups {
				c()
			}
			return nil, err
		}
		cleanups = append(cleanups, cleanup)
		files[i] = newEntry
		fmt.Fprintf(os.Stderr, "  %s -> %s (%.1f MB -> %.1f MB)\n",
			f.Name, newEntry.Name, megaBytes(f.Size), megaBytes(newEntry.Size))
	}
	return func() {
		for _, c := range cleanups {
			c()
		}
	}, nil
}

// decompressOneNCZ decompresses a single .ncz entry to a temp .nca file.
func decompressOneNCZ(name string, ra io.ReaderAt, entrySize int64) (nxformat.NamedReader, func(), error) {
	// The .ncz data starts at the entry's offset within the container.
	// The caller passes the whole file as ReaderAt; we need the entry's
	// absolute offset. Extract it from the progressReader's wrapped
	// SectionReader if possible; otherwise assume offset 0 (whole file).
	// For PFS0 entries the offset is already baked into ReadPFS0File;
	// for HFS0 it's in secureBase+e.Offset. In both cases the caller
	// created a SectionReader, so we use it directly.
	sec := io.NewSectionReader(ra, 0, entrySize)

	sections, _, err := nxformat.ParseNCZHeader(sec)
	if err != nil {
		return nxformat.NamedReader{}, nil, fmt.Errorf("%s: %w", name, err)
	}
	decompSize := nxformat.DecompressedNCASize(sections)

	tmp, err := os.CreateTemp("", "nxconvert-ncz-*.nca")
	if err != nil {
		return nxformat.NamedReader{}, nil, err
	}
	tmpName := tmp.Name()
	if err := nxformat.DecompressNCZ(sec, tmp); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return nxformat.NamedReader{}, nil, fmt.Errorf("%s: decompress: %w", name, err)
	}
	tmp.Close()

	f, err := os.Open(tmpName)
	if err != nil {
		os.Remove(tmpName)
		return nxformat.NamedReader{}, nil, err
	}

	newName := strings.TrimSuffix(name, ".ncz") + ".nca"
	return nxformat.NamedReader{
		Name: newName,
		Size: decompSize,
		R:    newProgressReader(newName, decompSize, f),
	}, func() { f.Close(); os.Remove(tmpName) }, nil
}

func hasSuffix(s, suffix string) bool {
	return strings.HasSuffix(strings.ToLower(s), suffix)
}

// splitGroup is one output NSP of a split: the NCAs of one installable
// title — a family's base game, its update, or a single DLC — plus any
// ticket/cert/xml files riding along with it.
type splitGroup struct {
	kind    string // "BASE", "UPD", or "DLC"
	titleID uint64 // representative title ID used in the output file name
	files   []nxformat.NamedReader
}

// name is the output NSP file name for the group, e.g. BASE_0100AA0000010000.nsp.
func (g *splitGroup) name() string {
	return fmt.Sprintf("%s_%016X.nsp", g.kind, g.titleID)
}

// splitKind classifies a title ID by the low 12 bits of its index, per the
// retail title-ID layout (verified against MK8D 010015200002{2000,2800,3001}
// and Dead Cells 0100646009FB{E000,E800,F001}): 0x000 is the base
// application, 0x800 its update, and anything else add-on content. Base and
// update share the upper 48 bits (the "family"); a DLC's type nibble is the
// base's +1, but it stays within the same 48-bit family.
func splitKind(titleID uint64) string {
	switch titleID & 0xFFF {
	case 0x000:
		return "BASE"
	case 0x800:
		return "UPD"
	default:
		return "DLC"
	}
}

// splitXCI splits an XCI gamecard image into one NSP per installable title:
// the base game, its update, and each DLC. NCA entries are classified by
// the title ID read from their decrypted NCA header; .tik/.cert/.xml files
// ride along with the group of the title ID embedded in their file name.
func splitXCI(args []string) error {
	fs := flag.NewFlagSet("split", flag.ExitOnError)
	outFlag := fs.String("o", "", "output directory (default: directory of the input XCI)")
	keysFlag := fs.String("keys", "", "prod.keys path (required: header_key decrypts NCA headers to read title IDs)")
	fs.Usage = func() {
		fmt.Fprintln(os.Stderr, "Usage: nxconvert split input.xci [-o output_dir] [--keys prod.keys]")
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
	outDir := *outFlag
	if outDir == "" {
		outDir = filepath.Dir(inPath)
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}

	in, err := os.Open(inPath)
	if err != nil {
		return err
	}
	defer in.Close()

	secure, secureBase, err := nxformat.ParseXCI(in)
	if err != nil {
		return fmt.Errorf("parse %s as XCI: %w", inPath, err)
	}
	if len(secure) == 0 {
		return fmt.Errorf("%s: gamecard secure partition holds no files", inPath)
	}

	// Title IDs are only readable from the encrypted NCA header, so split
	// cannot run keyless like the plain repacks.
	headerKey, err := loadHeaderKey(*keysFlag)
	if err != nil {
		return err
	}
	if headerKey == nil {
		return fmt.Errorf("split needs the header_key from prod.keys to read NCA title IDs; pass --keys prod.keys")
	}

	st, err := in.Stat()
	if err != nil {
		return err
	}
	groups, err := classifySecure(secure, secureBase, st.Size(), in, headerKey)
	if err != nil {
		return err
	}

	for _, g := range groups {
		// NSP is the download container: rewrite gamecard (0x01) NCAs to
		// download (0x00) distribution, like to-nsp does.
		if err := patchNCADistribution(g.files, headerKey, nxformat.DistributionDownload); err != nil {
			return err
		}
		var total int64
		for _, f := range g.files {
			total += f.Size
		}
		outPath := filepath.Join(outDir, g.name())
		fmt.Fprintf(os.Stderr, "split: %s [%s] -> %s (%d files, %.1f MB)\n",
			inPath, g.kind, outPath, len(g.files), megaBytes(total))
		if err := writeOutput(outPath, func(w io.Writer) error {
			return nxformat.WritePFS0(w, g.files)
		}); err != nil {
			return err
		}
		fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	}
	return nil
}

// classifySecure groups the secure-partition entries of an XCI by content
// type. Each .nca entry's first 0x400 bytes are decrypted with headerKey to
// read its title ID; the base (index 0x000) and update (index 0x800) NCAs of
// a title family share a group, while every DLC title ID gets its own group
// — each DLC carries its own cnmt, and a PFS0 holding several cnmts would
// not install. Note that update *content* NCAs carry the base application's
// title ID (only the update cnmt carries base+0x800; observed on retail
// MK8D and Dead Cells update NSPs), so on a merged base+update image the
// update's content lands in the BASE group. Non-NCA entries (.tik/.cert/.xml)
// join the group of the title ID naming them, falling back to the family's
// BASE group.
func classifySecure(entries []nxformat.FileEntry, secureBase, fileSize int64, in io.ReaderAt, headerKey []byte) ([]*splitGroup, error) {
	var groups []*splitGroup
	byKey := make(map[string]*splitGroup)     // grouping key -> group
	byTitleID := make(map[uint64]*splitGroup) // every NCA title ID -> its group
	byFamily := make(map[uint64]*splitGroup)  // title family (upper 48 bits) -> its BASE group
	byNCAName := make(map[string]*splitGroup) // lowercased NCA name -> its group
	newGroup := func(titleID uint64) *splitGroup {
		kind := splitKind(titleID)
		key := fmt.Sprintf("%012X/%s", titleID>>16, kind)
		if kind == "DLC" {
			key = fmt.Sprintf("%016X", titleID)
		}
		g := byKey[key]
		if g == nil {
			g = &splitGroup{kind: kind, titleID: titleID}
			byKey[key] = g
			groups = append(groups, g)
			family := titleID &^ 0xFFFF
			if kind == "BASE" && byFamily[family] == nil {
				byFamily[family] = g
			}
		}
		byTitleID[titleID] = g
		return g
	}
	addFile := func(e nxformat.FileEntry, abs int64, g *splitGroup) {
		g.files = append(g.files, nxformat.NamedReader{
			Name: e.Name,
			Size: e.Size,
			R:    newProgressReader(e.Name, e.Size, io.NewSectionReader(in, abs, e.Size)),
		})
	}

	var rideAlongs []nxformat.FileEntry
	for _, e := range entries {
		abs := secureBase + e.Offset
		if abs+e.Size > fileSize {
			return nil, fmt.Errorf("entry %s extends past end of file (truncated input?)", e.Name)
		}
		if hasSuffix(e.Name, ".ncz") {
			return nil, fmt.Errorf("%s: compressed XCZ entries are not supported by split; convert with to-nsp first", e.Name)
		}
		if !hasSuffix(e.Name, ".nca") {
			rideAlongs = append(rideAlongs, e)
			continue
		}
		if e.Size < 0x400 {
			return nil, fmt.Errorf("%s: NCA smaller than an NCA header (%d bytes)", e.Name, e.Size)
		}
		var hdr [0x400]byte
		if _, err := in.ReadAt(hdr[:], abs); err != nil {
			return nil, fmt.Errorf("%s: read header: %w", e.Name, err)
		}
		plain, err := nxformat.DecryptNCAHeader(hdr[:], headerKey)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name, err)
		}
		if magic := string(plain[:4]); magic != "NCA3" && magic != "NCA2" {
			return nil, fmt.Errorf("%s: decrypted header magic %q — wrong header_key?", e.Name, magic)
		}
		titleID := binary.LittleEndian.Uint64(plain[0x10:0x18])
		g := newGroup(titleID)
		fmt.Fprintf(os.Stderr, "  %s -> %s\n", e.Name, g.name())
		addFile(e, abs, g)
		byNCAName[strings.ToLower(e.Name)] = g
	}
	if len(groups) == 0 {
		return nil, fmt.Errorf("secure partition holds no NCA files")
	}

	// Tickets and certificates are named after their rights ID, whose
	// 16-hex-digit prefix is the title ID: route each one to its title's
	// group, or its family's BASE group. cnmt.xml files are named after
	// their cnmt NCA ("<id>.cnmt.xml" beside "<id>.cnmt.nca"), so follow
	// that; anything still unplaced joins the first BASE group.
	for _, e := range rideAlongs {
		var g *splitGroup
		if tid, ok := titleIDFromName(e.Name); ok {
			if cand := byTitleID[tid]; cand != nil {
				g = cand
			} else {
				g = byFamily[tid&^0xFFFF]
			}
		}
		if g == nil && hasSuffix(e.Name, ".xml") {
			companion := strings.ToLower(e.Name)
			companion = strings.TrimSuffix(companion, ".xml") + ".nca"
			g = byNCAName[companion]
		}
		if g == nil {
			for _, cand := range groups {
				if cand.kind == "BASE" {
					g = cand
					break
				}
			}
		}
		if g == nil {
			g = groups[0]
		}
		fmt.Fprintf(os.Stderr, "  %s -> %s\n", e.Name, g.name())
		addFile(e, secureBase+e.Offset, g)
	}
	return groups, nil
}

// titleIDFromName extracts the title ID from a rights-ID-named file:
// tickets and certificates are named "<titleid><keyrev>.tik"/".cert" and
// cnmt.xml files "<titleid>.cnmt.xml", so the first 16 characters of the
// name's stem are the title ID in hex.
func titleIDFromName(name string) (uint64, bool) {
	stem := name
	if i := strings.IndexByte(stem, '.'); i >= 0 {
		stem = stem[:i]
	}
	if len(stem) < 16 {
		return 0, false
	}
	var id uint64
	for _, c := range []byte(stem[:16]) {
		var v byte
		switch {
		case c >= '0' && c <= '9':
			v = c - '0'
		case c >= 'a' && c <= 'f':
			v = c - 'a' + 10
		case c >= 'A' && c <= 'F':
			v = c - 'A' + 10
		default:
			return 0, false
		}
		id = id<<4 | uint64(v)
	}
	return id, id != 0
}

// newTrackedReader wraps r with a progressReader connected to a TUI tracker.
func newTrackedReader(name string, size int64, r io.Reader, tracker *Progress) *progressReader {
	return &progressReader{name: name, size: size, r: r, tracker: tracker}
}

// parseHexKey validates a 32-char hex string and returns 16 bytes.
func parseHexKey(s string) ([]byte, error) {
	if len(s) != 32 {
		return nil, fmt.Errorf("got %d chars, want 32", len(s))
	}
	b, err := hex.DecodeString(s)
	if err != nil {
		return nil, err
	}
	return b, nil
}

// reencryptForMIG re-encrypts every NCA in files for MIG gamecard
// compatibility: sections are AES-CTR decrypted under the CDN-derived
// section key and re-encrypted under cardTitleKey, the key area is
// rewritten (slots 0/1/3 get fresh random XTS filler, slot 2 gets the
// card key), and distribution is flipped to gamecard. Each re-encrypted
// NCA lands in a temp file that replaces the original NamedReader.
func reencryptForMIG(files []nxformat.NamedReader, headerKey, cardTitleKey []byte, inPaths []string) error {
	prodKeys := loadAllKeys()
	kaakCache := map[string][]byte{}

	for i := range files {
		name := files[i].Name
		if !strings.HasSuffix(name, ".nca") && !strings.HasSuffix(name, ".cnmt.nca") {
			continue
		}
		rs, ok := files[i].R.(io.ReadSeeker)
		if !ok {
			continue
		}

		// 1. Read + decrypt NCA header
		hdr := make([]byte, 0x400)
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			return fmt.Errorf("%s: seek: %w", name, err)
		}
		if _, err := io.ReadFull(rs, hdr); err != nil {
			return fmt.Errorf("%s: header: %w", name, err)
		}
		plain, err := nxformat.DecryptNCAHeader(hdr, headerKey)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		kaakIdx := plain[0x07]
		cryptoType := plain[0x06]
		cryptoType2 := plain[0x05]

		// 2. kaak for this NCA's generation
		kaakName := nxformat.KAAKName(kaakIdx, cryptoType, cryptoType2)
		kaak, ok := kaakCache[kaakName]
		if !ok {
			kaak = prodKeys[kaakName]
			if kaak == nil {
				return fmt.Errorf("%s: %s missing from prod.keys", name, kaakName)
			}
			kaakCache[kaakName] = kaak
		}

		// 3. Old section key from key area
		oldKeys, err := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
		if err != nil {
			return fmt.Errorf("%s: key area: %w", name, err)
		}
		oldKey := oldKeys[nxformat.NCASectionKeySlot]

		// 4. New keys: slot 2 = card titlekey, others = fresh random
		rnd := make([]byte, 16)
		newKeys := make([][]byte, 4)
		for slot := range newKeys {
			if slot == nxformat.NCASectionKeySlot {
				newKeys[slot] = cardTitleKey
			} else {
				rand.Read(rnd)
				newKeys[slot] = append([]byte(nil), rnd...)
			}
		}

		// 5. Rewrite header: new key area + distribution=0x01
		newPlain := append([]byte(nil), plain...)
		newKeyArea, err := nxformat.EncryptKeyArea(newKeys, kaak)
		if err != nil {
			return fmt.Errorf("%s: encrypt key area: %w", name, err)
		}
		copy(newPlain[0x100:], newKeyArea)
		newPlain[0x04] = 1 // distribution = gamecard (relative to decrypted region)
		newHdr := make([]byte, 0x400)
		copy(newHdr, hdr) // keep the unencrypted first 0x200 bytes
		if err := nxformat.EncryptNCAHeader(newHdr, newPlain, headerKey); err != nil {
			return fmt.Errorf("%s: encrypt header: %w", name, err)
		}

		// 6. Sections to re-encrypt
		secs := nxformat.ParseNCASections(plain)
		var offs, sizes []int64
		for _, sc := range secs {
			offs = append(offs, sc.Offset)
			sizes = append(sizes, sc.Size)
		}

		// 7. Stream: new header + copied gap + re-encrypted sections
		tmp, err := os.CreateTemp("", "nxmig-*.nca")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("%s: rewind: %w", name, err)
		}
		if _, err := rs.Seek(0, io.SeekStart); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("%s: rewind: %w", name, err)
		}
		if err := nxformat.ReencryptNCA(rs, tmp, oldKey, cardTitleKey, offs, sizes); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("%s: sections: %w", name, err)
		}
		tmp.Close()

		// Patch the rewritten header into the temp file (ReencryptNCA
		// copies the original header verbatim; we need the new one).
		tf, err := os.OpenFile(tmpName, os.O_RDWR, 0)
		if err != nil {
			os.Remove(tmpName)
			return err
		}
		if _, err := tf.WriteAt(newHdr, 0); err != nil {
			tf.Close()
			os.Remove(tmpName)
			return fmt.Errorf("%s: header patch: %w", name, err)
		}
		tf.Close()

		// 8. Swap in the re-encrypted NCA
		fh, err := os.Open(tmpName)
		if err != nil {
			os.Remove(tmpName)
			return err
		}
		st, _ := fh.Stat()
		old := files[i]
		_ = old
		files[i].R = fh
		files[i].Size = st.Size()
		fmt.Fprintf(os.Stderr, "  %s: re-encrypted %d section(s), %d bytes (key %x → %x)\n",
			name, len(secs), st.Size(), oldKey[:4], cardTitleKey[:4])
	}
	return nil
}

// loadAllKeys parses prod.keys into a map. Returns an empty map on any
// failure (callers report missing keys per NCA).
func loadAllKeys() map[string][]byte {
	out := map[string][]byte{}
	path := findProdKeys()
	if path == "" {
		return out
	}
	f, err := os.Open(path)
	if err != nil {
		return out
	}
	defer f.Close()
	keys, _ := nxformat.ParseProdKeys(f)
	for k, v := range keys {
		out[k] = v
	}
	return out
}

func findProdKeys() string {
	if env := os.Getenv("NXSHELF_PROD_KEYS"); env != "" {
		return env
	}
	if home, err := os.UserHomeDir(); err == nil {
		for _, p := range []string{
			filepath.Join(home, ".switch", "prod.keys"),
			filepath.Join(home, "switch-prod.keys"),
			"/tmp/prod.keys",
		} {
			if _, err := os.Stat(p); err == nil {
				return p
			}
		}
	}
	return ""
}
