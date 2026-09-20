# Reddit 소개글 초안

**대상 서브레딧**: r/SwitchPirates (본 목적) 또는 r/nintendoswitchhomebrew

---

## Title

nxconvert — a fast NSP⇄XCI converter written in Go (no Python, no Windows-only tools, brew install)

## Body

Tired of Windows-only .bat wrappers and Python dependencies just to convert between NSP and XCI? I wrote a small tool in pure Go — zero external dependencies, streams everything (26GB XCI in ~1s on SSD), works on macOS/Linux/Windows.

**GitHub**: https://github.com/kyungw00k/nxconvert

### What it does

- **NSP → XCI**: repacks all files into a gamecard HFS0 image
- **XCI → NSP**: extracts the secure partition into a PFS0 container
- **`--keys`** (optional): rewrites the NCA distribution flag (gamecard ⇄ CDN) using your own `prod.keys` — so converted files are structurally correct for their target format

### Install

```bash
brew install kyungw00k/tap/nxconvert
# or
go install github.com/kyungw00k/nxconvert@latest
```

### Usage

```bash
nxconvert to-nsp "Dead Cells.xci"
nxconvert to-xci "Dead Cells.nsp" --keys ~/.switch/prod.keys
```

### Why another converter?

The existing tools (XCI_Builder, NSP-to-XCI-Converter, hacbuild) are all Windows batch wrappers around Python/EXE chains. They strip manual NCAs to work around a 5-NCA limit, need specific directory layouts, and haven't been updated in years.

nxconvert:
- Pure Go, single binary, no dependencies
- Streams everything — memory-safe for 32GB XCIs
- No NCA limit (all files carried over, including manuals)
- Cross-platform (tested on macOS arm64, Linux amd64)
- Optional distribution rewrite with `--keys` (uses `header_key` from prod.keys, read at runtime only)

### Technical notes

- NSP = PFS0 container, XCI = GAMECARD header + HFS0 — the NCAs inside are the same payload, conversion is lossless repack with no re-signing
- The distribution flag (byte at +0x04 in the decrypted NCA header) determines gamecard vs CDN mode; flipping it requires AES-XTS encrypt/decrypt with `header_key` — your keys never touch disk
- Round-trip verified: XCI → NSP → XCI reproduces the original byte-for-byte (names, sizes, SHA-256)
- Content hashes and cnmt are unaffected by the header rewrite (they cover the NCA body only)

### Validated against

- Real Dead Cells cartridge dump (2GB) vs CDN NSP — decrypted headers match on every field after distribution rewrite
- Crysis 3 Remastered XCI header structure
- Cuphead NSP structure

Happy to take feature requests. NSZ/XCZ support is on the roadmap.
