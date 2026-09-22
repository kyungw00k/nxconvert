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
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/hex"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
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
  --keys path Optional prod.keys file (to-xci requires it; auto-discovered
           at ~/.switch/prod.keys and other standard locations). The key is
           read at runtime and never embedded or written to outputs.
  --mig-folder dir   (to-xci) Write a MIG-ready game folder: the XCI (split
           into 0xFFFF0000-byte parts when over the FAT32 limit) plus the
           Certificate and Initial Data bins copied from --mig-bins.
  --mig-bins path    (to-xci) Donor card dump XCI to source the
           Certificate / Initial Data bins for --mig-folder.
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
	keysFlag := fs.String("keys", "", "prod.keys path (default: standard locations)")
	migFolderFlag := fs.String("mig-folder", "", "write a MIG-ready game folder here (XCI + FAT32 split + Certificate/Initial Data bins)")
	migBinsFlag := fs.String("mig-bins", "", "donor card dump (XCI path) whose Certificate/Initial Data bins to copy into --mig-folder")
	noRemasterFlag := fs.Bool("no-remaster", false, "skip NCA header rewriting (no keys needed; emulator-oriented output)")
	dumpStyleFlag := fs.Bool("dump-style", false, "fully self-consistent remaster: gamecard flags, recomputed NCA ids, repointed cnmt — the dump shape stock consoles accept")
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

	// NSC_BUILDER-style NCA header rewrite for XCI: gamecard-flag logic,
	// rights-id clearing, and titlekey->key-area slots — the header shape
	// every MIG-verified NSC conversion carries. --no-remaster skips it for
	// a pure container swap (rights-based NCAs stay untouched; emulators
	// read the ticket themselves).
	keysPath := *keysFlag
	if *dumpStyleFlag {
		keysPath2 := *keysFlag
		if keysPath2 == "" {
			keysPath2 = findProdKeys()
		}
		if keysPath2 == "" {
			return fmt.Errorf("--dump-style requires prod.keys")
		}
		if err := remasterDumpStyle(files, keysPath2, "", "", ""); err != nil {
			return fmt.Errorf("dump-style remaster: %w", err)
		}
	} else if !*noRemasterFlag {
		if keysPath == "" {
			keysPath = findProdKeys()
		}
		if keysPath == "" {
			return fmt.Errorf("to-xci requires prod.keys (or pass --no-remaster for a pure container swap)")
		}
		if err := nscRemasterNCAs(files, keysPath); err != nil {
			return fmt.Errorf("nsc remaster: %w", err)
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

	if *migFolderFlag != "" {
		if *migBinsFlag == "" {
			return fmt.Errorf("--mig-folder requires --mig-bins <donor dump xci> for the Certificate/Initial Data bins")
		}
		// Stage the XCI inside a MIG game folder: <folder>/<name>.xci/
		// with the XCI (split into 00,01,... parts over the FAT32 limit)
		// plus the card-side crypto bins from the donor dump.
		base := strings.TrimSuffix(filepath.Base(outPath), ".xci")
		gameDir := filepath.Join(*migFolderFlag, base+".xci")
		if err := os.MkdirAll(gameDir, 0o755); err != nil {
			return fmt.Errorf("--mig-folder: %w", err)
		}
		tmp, err := os.CreateTemp(*migFolderFlag, ".migtmp-*")
		if err != nil {
			return fmt.Errorf("--mig-folder: %w", err)
		}
		tmpName := tmp.Name()
		err = nxformat.WriteXCINSC(tmp, files)
		tmp.Close()
		if err == nil {
			err = splitForMIG(tmpName, gameDir, base+".xci")
		}
		os.Remove(tmpName)
		if err != nil {
			return fmt.Errorf("--mig-folder: %w", err)
		}
		donorDir := filepath.Dir(*migBinsFlag)
		donorBase := strings.TrimSuffix(filepath.Base(*migBinsFlag), ".xci")
		for _, suffix := range []string{"Certificate", "Initial Data"} {
			src := filepath.Join(donorDir, donorBase+" ("+suffix+").bin")
			dst := filepath.Join(gameDir, base+" ("+suffix+").bin")
			data, err := os.ReadFile(src)
			if err != nil {
				return fmt.Errorf("--mig-bins: donor card file: %w", err)
			}
			if err := os.WriteFile(dst, data, 0o644); err != nil {
				return fmt.Errorf("--mig-folder: %w", err)
			}
		}
		fmt.Fprintf(os.Stderr, "mig-folder: wrote %s (bins from %s)\n", gameDir, donorBase)
	}
	if *migFolderFlag == "" {
		err = writeOutput(outPath, func(w io.Writer) error {
			return nxformat.WriteXCINSC(w, files)
		})
		if err != nil {
			return err
		}
	}
	tracker.Finish(err)
	WaitForDone(tui)
	if err != nil {
		return err
	}
	fmt.Fprintf(os.Stderr, "wrote %s\n", outPath)
	return nil
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
		case a == "-o" || a == "--o" || a == "--keys" || a == "--mig-folder" || a == "--mig-bins":
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

// nscRemasterNCAs rewrites every NCA header in files following
// NSC_BUILDER's XCI conversion recipe (the form MIG flashcarts are
// verified to accept):
//
//  1. gamecard flag: 1 only when the whole batch looks like cartridge
//     content (every NCA has distribution != 0 or an all-zero key-area
//     slot 0); eShop batches keep distribution 0x00.
//  2. rights-id is cleared to zero.
//  3. NCAs that had a rights-id get all four key-area slots filled with
//     the titlekey (from the batch's .tik) ECB-encrypted under the
//     generation-matched key_area_key.
//
// NCA filenames are kept verbatim. Each patched NCA is spooled to a temp
// file and swapped in as the entry reader.
func nscRemasterNCAs(files []nxformat.NamedReader, keysPath string) error {
	kf, err := os.Open(keysPath)
	if err != nil {
		return err
	}
	keys, err := nxformat.ParseProdKeys(kf)
	kf.Close()
	if err != nil {
		return err
	}
	headerKey := keys["header_key"]
	if headerKey == nil {
		return fmt.Errorf("header_key missing from %s", keysPath)
	}

	// Tickets: rights-id (hex) -> encrypted titlekey.
	tickets := map[string][]byte{}
	for i := range files {
		if !strings.HasSuffix(files[i].Name, ".tik") {
			continue
		}
		rs, ok := files[i].R.(io.ReadSeeker)
		if !ok {
			continue
		}
		rs.Seek(0, io.SeekStart)
		data, err := io.ReadAll(rs)
		rs.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}
		rightsID, encTK, err := nxformat.ParseTicket(data)
		if err != nil {
			continue
		}
		tickets[hex.EncodeToString(rightsID)] = encTK
	}

	type info struct {
		plain     []byte
		hadRights bool
		slot0Zero bool
		gen       byte
	}
	infos := make([]*info, len(files))
	isCartridge := true
	sawNCA := false
	for i := range files {
		if !strings.HasSuffix(files[i].Name, ".nca") {
			continue
		}
		sawNCA = true
		plain, err := readDecryptHeader(files[i], headerKey)
		if err != nil {
			return fmt.Errorf("%s: %w", files[i].Name, err)
		}
		kaakName := nxformat.KAAKName(plain[7], plain[6], plain[0x20])
		kaak := keys[kaakName]
		// A missing generation key only blocks the key-area inspection
		// (treat the NCA as non-cartridge, mirroring nscb_rust); it is a
		// hard error later only if a rights-id NCA actually needs it.
		slot0Zero := false
		if kaak != nil {
			ka, err := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
			if err != nil {
				return fmt.Errorf("%s: key area: %w", files[i].Name, err)
			}
			slot0Zero = allZero(ka[0])
		}
		hadRights := !allZero(plain[0x30:0x40])
		gen := plain[6]
		if plain[0x20] > gen {
			gen = plain[0x20]
		}
		infos[i] = &info{plain: plain, hadRights: hadRights, slot0Zero: slot0Zero, gen: gen}
		if plain[4] == 0 && !slot0Zero {
			isCartridge = false
		}
	}
	if !sawNCA {
		return fmt.Errorf("no NCA files found in inputs")
	}

	for i := range files {
		if infos[i] == nil {
			continue
		}
		inf := infos[i]
		plain := append([]byte(nil), inf.plain...)

		gcFlag := byte(0)
		if isCartridge && (plain[4] != 0 || inf.slot0Zero) {
			gcFlag = 1
		}
		plain[4] = gcFlag
		rights := append([]byte(nil), plain[0x30:0x40]...)
		copy(plain[0x30:0x40], make([]byte, 16))
		if inf.hadRights {
			encTK, ok := tickets[hex.EncodeToString(rights)]
			if !ok {
				return fmt.Errorf("%s: rights id %x has no matching ticket in the batch", files[i].Name, rights)
			}
			rev := inf.gen
			if rev > 0 {
				rev--
			}
			titlekek := keys[fmt.Sprintf("titlekek_%02d", rev)]
			if titlekek == nil {
				return fmt.Errorf("%s: titlekek_%02d missing from prod.keys", files[i].Name, rev)
			}
			tk, err := decryptTitleKey(encTK, titlekek)
			if err != nil {
				return fmt.Errorf("%s: titlekey: %w", files[i].Name, err)
			}
			kaak := keys[nxformat.KAAKName(plain[7], plain[6], plain[0x20])]
			blob, err := nxformat.EncryptKeyArea([][]byte{tk, tk, tk, tk}, kaak)
			if err != nil {
				return fmt.Errorf("%s: key area encrypt: %w", files[i].Name, err)
			}
			copy(plain[0x100:0x140], blob)
		}

		// Spool: patched 0x400 header + body verbatim.
		rs, ok := files[i].R.(io.ReadSeeker)
		if !ok {
			return fmt.Errorf("%s: not seekable", files[i].Name)
		}
		rs.Seek(0, io.SeekStart)
		origHdr := make([]byte, 0x400)
		if _, err := io.ReadFull(rs, origHdr); err != nil {
			return fmt.Errorf("%s: %w", files[i].Name, err)
		}
		newHdr := append([]byte(nil), origHdr...)
		if err := nxformat.EncryptNCAHeader(newHdr, plain, headerKey); err != nil {
			return fmt.Errorf("%s: header encrypt: %w", files[i].Name, err)
		}
		tmp, err := os.CreateTemp("", "nxnsc-*.nca")
		if err != nil {
			return err
		}
		tmpName := tmp.Name()
		if _, err := tmp.Write(newHdr); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return err
		}
		if _, err := rs.Seek(0x400, io.SeekStart); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return err
		}
		if _, err := io.Copy(tmp, rs); err != nil {
			tmp.Close()
			os.Remove(tmpName)
			return fmt.Errorf("%s: %w", files[i].Name, err)
		}
		tmp.Close()
		fh, err := os.Open(tmpName)
		if err != nil {
			os.Remove(tmpName)
			return err
		}
		st, _ := fh.Stat()
		files[i].R = fh
		files[i].Size = st.Size()
		fmt.Fprintf(os.Stderr, "  %s: gc_flag=%d rights_cleared=%v\n", files[i].Name, gcFlag, inf.hadRights)
	}
	return nil
}

// readDecryptHeader reads an entry's first 0x400 bytes and returns the
// decrypted 0x200 header region.
func readDecryptHeader(f nxformat.NamedReader, headerKey []byte) ([]byte, error) {
	rs, ok := f.R.(io.ReadSeeker)
	if !ok {
		return nil, fmt.Errorf("not seekable")
	}
	rs.Seek(0, io.SeekStart)
	hdr := make([]byte, 0x400)
	if _, err := io.ReadFull(rs, hdr); err != nil {
		return nil, err
	}
	return nxformat.DecryptNCAHeader(hdr, headerKey)
}

func allZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}

// decryptTitleKey AES-ECB-decrypts an encrypted titlekey under titlekek
// (reusing DecryptKeyArea's single-block ECB path).
func decryptTitleKey(enc, titlekek []byte) ([]byte, error) {
	if len(enc) != 16 || len(titlekek) != 16 {
		return nil, fmt.Errorf("bad key length")
	}
	keys, err := nxformat.DecryptKeyArea(append([]byte(nil), enc...), titlekek)
	if err != nil {
		return nil, err
	}
	return keys[0], nil
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

// dumpMeta carries a remastered NCA's new identity.
type dumpMeta struct {
	newID   []byte
	newSHA  []byte
	content []byte
}

// remasterDumpStyle rewrites NCAs into a fully self-consistent,
// dump-shaped form — the recipe stock consoles + MIG flashcarts accept:
//
//  1. every NCA: distribution forced to gamecard (0x01); rights-based
//     NCAs get rights cleared and the titlekey (from the batch .tik)
//     ECB-encrypted into all four key-area slots.
//  2. NCA filenames recomputed: <sha256(new content)[:16]>.nca.
//  3. the cnmt NCA: content entries re-pointed at the new IDs+hashes,
//     the PFS0 hash table recomputed (0x1000 blocks, final block raw),
//     the master hash rewritten at fs_header+0x08, the section-header
//     hash at decrypted-header +0x80 refreshed, then renamed itself.
//
// Key chain verified against retail Dead Cells BASE/UPD NCAs.
func remasterDumpStyle(files []nxformat.NamedReader, keysPath string, donorXCI string, migFolder, gameName string) error {
	kf, err := os.Open(keysPath)
	if err != nil {
		return err
	}
	keys, err := nxformat.ParseProdKeys(kf)
	kf.Close()
	if err != nil {
		return err
	}
	headerKey := keys["header_key"]
	if headerKey == nil {
		return fmt.Errorf("header_key missing")
	}

	// Tickets.
	tickets := map[string][]byte{}
	for i := range files {
		if !strings.HasSuffix(files[i].Name, ".tik") {
			continue
		}
		rs, ok := files[i].R.(io.ReadSeeker)
		if !ok {
			continue
		}
		rs.Seek(0, io.SeekStart)
		data, err := io.ReadAll(rs)
		rs.Seek(0, io.SeekStart)
		if err != nil {
			return err
		}
		rightsID, encTK, err := nxformat.ParseTicket(data)
		if err != nil {
			continue
		}
		tickets[hex.EncodeToString(rightsID)] = encTK
	}

	rename := map[string]*dumpMeta{} // old name (no ext) -> meta

	// Phase 1: non-cnmt NCAs.
	var cnmtIdx = -1
	for i := range files {
		name := files[i].Name
		if !strings.HasSuffix(name, ".nca") {
			continue
		}
		if strings.HasSuffix(name, ".cnmt.nca") {
			if cnmtIdx >= 0 {
				return fmt.Errorf("multiple cnmt NCAs in batch")
			}
			cnmtIdx = i
			continue
		}
		rs, ok := files[i].R.(io.ReadSeeker)
		if !ok {
			return fmt.Errorf("%s: not seekable", name)
		}
		rs.Seek(0, io.SeekStart)
		full, err := io.ReadAll(rs)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		plain, err := nxformat.DecryptNCAHeader(full[:0x400], headerKey)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		plain, oldKey, newKey, err := patchHeaderForDump(plain, keys, tickets)
		if err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		// 섹션 재암호화: CDN 키 → 새 랜덤 키. IV = fs_header[서수]의
		// section_ctr 반전 ‖ be64(오프셋>>4) — 실측 규칙 (IVFC 마스터해시로 검증).
		if !allZero(oldKey) {
			secs := nxformat.ParseNCASections(plain)
			type secJob struct {
				off, size int64
				iv        []byte
			}
			var jobs []secJob
			for _, sc := range secs {
				fsRaw := full[0x400+sc.Ordinal*0x200 : 0x600+sc.Ordinal*0x200]
				fsPlain, err := nxformat.DecryptFSHeader(fsRaw, sc.Ordinal, headerKey)
				if err != nil {
					return fmt.Errorf("%s: fs header %d: %w", name, sc.Ordinal, err)
				}
				jobs = append(jobs, secJob{sc.Offset, sc.Size, nxformat.SectionIV(fsPlain, sc.Offset)})
			}
			sort.Slice(jobs, func(a, b int) bool { return jobs[a].off < jobs[b].off })
			var offs, sizes []int64
			var ivs [][]byte
			for _, j := range jobs {
				offs = append(offs, j.off)
				sizes = append(sizes, j.size)
				ivs = append(ivs, j.iv)
			}
			var buf bytes.Buffer
			buf.Grow(len(full))
			if err := nxformat.ReencryptNCA(bytes.NewReader(full), &buf, oldKey, newKey, ivs, offs, sizes); err != nil {
				return fmt.Errorf("%s: reencrypt: %w", name, err)
			}
			full = buf.Bytes()
			fmt.Fprintf(os.Stderr, "  %s: sections re-encrypted under fresh key %x\n", name[:12], newKey[:4])
		}
		if err := nxformat.EncryptNCAHeader(full, plain, headerKey); err != nil {
			return fmt.Errorf("%s: %w", name, err)
		}
		sum := sha256.Sum256(full)
		id := sum[:16]
		old := strings.TrimSuffix(name, ".nca")
		rename[old] = &dumpMeta{newID: id, newSHA: sum[:], content: full}
		files[i].R = bytes.NewReader(full)
		files[i].Size = int64(len(full))
		files[i].Name = hex.EncodeToString(id) + ".nca"
		fmt.Fprintf(os.Stderr, "  %s -> %s (%d B)\n", old[:12], files[i].Name[:12], len(full))
	}
	if cnmtIdx < 0 {
		return fmt.Errorf("no cnmt NCA in batch")
	}

	// Phase 2: cnmt NCA.
	if err := remasterCnmt(files, cnmtIdx, keys, headerKey, rename); err != nil {
		return err
	}
	return nil
}

// patchHeaderForDump applies dist/rights/key-area edits to a decrypted
// 0x200 header region. Returns the patched header and the OLD section key
// (for section re-encryption) plus the NEW random section key.
func patchHeaderForDump(plain []byte, keys map[string][]byte, tickets map[string][]byte) (out []byte, oldKey, newKey []byte, err error) {
	out = append([]byte(nil), plain...)
	out[4] = 0x01 // gamecard distribution

	// Fresh random section key — the working card "dumps" carry fresh
	// per-NCA keys ({0,0,key,0}), never the CDN ones.
	gen := out[6]
	if out[0x20] > gen {
		gen = out[0x20]
	}
	rev := gen
	if rev > 0 {
		rev--
	}
	kaak := keys[nxformat.KAAKName(out[7], out[6], out[0x20])]
	if kaak == nil {
		return nil, nil, nil, fmt.Errorf("%s missing", nxformat.KAAKName(out[7], out[6], out[0x20]))
	}
	ka, err2 := nxformat.DecryptKeyArea(out[0x100:0x140], kaak)
	if err2 != nil {
		return nil, nil, nil, err2
	}
	oldKey = ka[nxformat.NCASectionKeySlot]
	newKey = make([]byte, 16)
	rand.Read(newKey)
	z16 := make([]byte, 16)
	blob, err2 := nxformat.EncryptKeyArea([][]byte{z16, z16, newKey, z16}, kaak)
	if err2 != nil {
		return nil, nil, nil, err2
	}
	copy(out[0x100:0x140], blob)

	rights := append([]byte(nil), out[0x30:0x40]...)
	copy(out[0x30:0x40], make([]byte, 16))
	if allZero(rights) {
		return out, oldKey, newKey, nil
	}
	encTK, ok := tickets[hex.EncodeToString(rights)]
	if !ok {
		return nil, nil, nil, fmt.Errorf("rights id %x has no ticket in batch", rights)
	}
	titlekek := keys[fmt.Sprintf("titlekek_%02d", rev)]
	if titlekek == nil {
		return nil, nil, nil, fmt.Errorf("titlekek_%02d missing from prod.keys", rev)
	}
	tk, err := decryptTitleKey(encTK, titlekek)
	if err != nil {
		return nil, nil, nil, err
	}
	kaak2 := keys[nxformat.KAAKName(out[7], out[6], out[0x20])]
	if kaak2 == nil {
		return nil, nil, nil, fmt.Errorf("%s missing", nxformat.KAAKName(out[7], out[6], out[0x20]))
	}
	// rights 기반: titlekey를 새 키로 사용
	blob2, err := nxformat.EncryptKeyArea([][]byte{tk, tk, tk, tk}, kaak2)
	if err != nil {
		return nil, nil, nil, err
	}
	copy(out[0x100:0x140], blob2)
	return out, oldKey, tk, nil
}

// remasterCnmt patches the cnmt NCA: content entries, PFS0 hash table,
// master hash, section hash, then renames it.
func remasterCnmt(files []nxformat.NamedReader, idx int, keys map[string][]byte, headerKey []byte, rename map[string]*dumpMeta) error {
	rs, ok := files[idx].R.(io.ReadSeeker)
	if !ok {
		return fmt.Errorf("cnmt: not seekable")
	}
	rs.Seek(0, io.SeekStart)
	full, err := io.ReadAll(rs)
	if err != nil {
		return err
	}
	plain, err := nxformat.DecryptNCAHeader(full[:0x400], headerKey)
	if err != nil {
		return err
	}
	kaak := keys[nxformat.KAAKName(plain[7], plain[6], plain[0x20])]
	ka, err := nxformat.DecryptKeyArea(plain[0x100:0x140], kaak)
	if err != nil {
		return err
	}
	secKey := ka[nxformat.NCASectionKeySlot]
	secs := nxformat.ParseNCASections(plain)
	if len(secs) == 0 {
		return fmt.Errorf("cnmt: no sections")
	}
	secOff, secSize := secs[0].Offset, secs[0].Size
	if secOff+secSize > int64(len(full)) {
		return fmt.Errorf("cnmt: section beyond file")
	}

	// Decrypt section.
	block, _ := aes.NewCipher(secKey)
	iv := make([]byte, 16)
	binary.BigEndian.PutUint64(iv[8:], uint64(secOff>>4))
	secPlain := append([]byte(nil), full[secOff:secOff+secSize]...)
	cipher.NewCTR(block, iv).XORKeyStream(secPlain, secPlain)

	// fs_header[0] (raw at 0x400).
	fsRaw := append([]byte(nil), full[0x400:0x600]...)
	fsPlain, err := nxformat.DecryptFSHeader(fsRaw, 0, headerKey)
	if err != nil {
		return err
	}
	blockSize := int64(binary.LittleEndian.Uint32(fsPlain[0x28:]))
	pfs0Off := int64(binary.LittleEndian.Uint64(fsPlain[0x38:]))
	tableSize := int64(binary.LittleEndian.Uint64(fsPlain[0x40:]))
	partSize := int64(binary.LittleEndian.Uint64(fsPlain[0x48:]))

	// PFS0: single .cnmt file.
	nf := binary.LittleEndian.Uint32(secPlain[pfs0Off+4:])
	ss := binary.LittleEndian.Uint32(secPlain[pfs0Off+8:])
	fsz := binary.LittleEndian.Uint64(secPlain[pfs0Off+0x18:])
	dataBase := pfs0Off + 0x10 + int64(nf)*0x18 + int64(ss)
	cnmtFile := secPlain[dataBase : dataBase+int64(fsz)]

	// Patch content entries: 0x20+table_offset, 0x38 stride.
	tableOffset := int64(binary.LittleEndian.Uint16(cnmtFile[0x0E:]))
	count := int64(binary.LittleEndian.Uint16(cnmtFile[0x10:]))
	entriesOff := 0x20 + tableOffset
	patched := 0
	for i := int64(0); i < count; i++ {
		e := entriesOff + i*0x38
		if e+0x38 > int64(len(cnmtFile)) {
			break
		}
		oldID := cnmtFile[e+0x20 : e+0x30]
		meta, ok := rename[hex.EncodeToString(oldID)]
		if !ok {
			continue
		}
		copy(cnmtFile[e+0x00:e+0x20], meta.newSHA)
		copy(cnmtFile[e+0x20:e+0x30], meta.newID)
		patched++
	}
	fmt.Fprintf(os.Stderr, "  cnmt: %d/%d content entries repointed\n", patched, count)

	// Recompute hash table: blocks of blockSize over [pfs0Off, pfs0Off+partSize).
	nblocks := (partSize + blockSize - 1) / blockSize
	if nblocks*32 != tableSize {
		return fmt.Errorf("cnmt: table size mismatch (expect %d, have %d)", nblocks*32, tableSize)
	}
	for b := int64(0); b < nblocks; b++ {
		start := pfs0Off + b*blockSize
		end := min(start+blockSize, pfs0Off+partSize)
		h := sha256.Sum256(secPlain[start:end])
		copy(secPlain[b*32:b*32+32], h[:])
	}
	master := sha256.Sum256(secPlain[:tableSize])
	copy(fsPlain[0x08:0x28], master[:])

	// Re-encrypt fs_header + patch +0x80 section hash.
	newFs, err := nxformat.EncryptFSHeader(fsPlain, 0, headerKey)
	if err != nil {
		return err
	}
	copy(full[0x400:0x600], newFs)
	secHash := sha256.Sum256(fsPlain)
	copy(plain[0x80:0xA0], secHash[:])
	plain, _, _, err = patchHeaderForDump(plain, keys, map[string][]byte{})
	if err != nil {
		return err
	}
	if err := nxformat.EncryptNCAHeader(full, plain, headerKey); err != nil {
		return err
	}

	// Re-encrypt section.
	cipher.NewCTR(block, iv).XORKeyStream(secPlain, secPlain)
	copy(full[secOff:secOff+secSize], secPlain)

	sum := sha256.Sum256(full)
	os.WriteFile("/tmp/cnmt_debug.bin", full, 0644)
	id := sum[:16]
	old := strings.TrimSuffix(files[idx].Name, ".nca")
	fmt.Fprintf(os.Stderr, "  cnmt %s -> %s\n", old[:12], hex.EncodeToString(id)[:12])
	files[idx].R = bytes.NewReader(full)
	files[idx].Size = int64(len(full))
	files[idx].Name = hex.EncodeToString(id) + ".cnmt.nca"
	return nil
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

// migSplitSize is the per-part size retail dumpers use for split XCIs
// (verified: Mario Kart 8 Deluxe dump part 00 is exactly 0xFFFF0000).
const migSplitSize = 0xFFFF0000

// splitForMIG lays the image at src into the MIG game folder: a single
// <name>.xci file when it fits under the FAT32 limit, otherwise an
// inner <name>.xci/ directory of 00,01,... parts.
func splitForMIG(src, gameDir, name string) error {
	st, err := os.Stat(src)
	if err != nil {
		return err
	}
	if st.Size() <= migSplitSize {
		return os.Rename(src, filepath.Join(gameDir, name))
	}
	inner := filepath.Join(gameDir, name)
	if err := os.MkdirAll(inner, 0o755); err != nil {
		return err
	}
	in, err := os.Open(src)
	if err != nil {
		return err
	}
	defer in.Close()
	part := 0
	remaining := st.Size()
	buf := make([]byte, 1<<22)
	for remaining > 0 {
		out, err := os.Create(filepath.Join(inner, fmt.Sprintf("%02d", part)))
		if err != nil {
			return err
		}
		partSize := min(int64(migSplitSize), remaining)
		for copied := int64(0); copied < partSize; {
			chunk := min(int64(len(buf)), partSize-copied)
			read, err := io.ReadFull(in, buf[:chunk])
			if err != nil {
				out.Close()
				return err
			}
			if _, err := out.Write(buf[:read]); err != nil {
				out.Close()
				return err
			}
			copied += int64(read)
			remaining -= int64(read)
		}
		out.Close()
		part++
	}
	return nil
}
