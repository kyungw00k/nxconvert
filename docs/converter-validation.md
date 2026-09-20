# nxconvert Validation Record (2026-09-20, real cartridge dump)

## Test specimens
- Dead Cells cartridge dump: `Dead Cells.xci` 1,996,488,704 B (2GB card size class, 465MB used) + card certificate / Initial Data bin
- Same game CDN NSP: `Dead Cells [BASE][0100646009FB][v0].nsp` 464,974,608 B

## Conclusion: round-trip integrity passes

```
Original XCI ──to-nsp──▶ NSP' ──to-xci──▶ XCI'
Original XCI secure NCAs (4) ≡ XCI' secure NCAs (4)  (names, sizes, SHA-256 all identical)
```

| NCA | Size | Notes |
|-----|------|-------|
| e82c4e…92.nca | 463,634,432 | program |
| 2d432a…50.nca | 1,192,960 | control |
| c64b5d…b8.nca | 143,360 | html |
| 5877af…14.cnmt.nca | 3,584 | cnmt |

Gamecard naming convention (filename = content SHA-256) holds 4/4 — independent evidence of content integrity during conversion.

## Key finding: gamecard NCAs and CDN NCAs are different ciphertexts of the same plaintext

The NCAs extracted from an XCI and the NCAs in a CDN NSP have **identical sizes but entirely different hashes** (99.77% byte difference on the program NCA). Cause:
- Gamecard NCAs: encrypted with a card-unique titlekey
- CDN/eShop NCAs: encrypted with the ticket's titlekey
- cnmt embeds NCA hashes, so it differs as a consequence

Therefore **direct byte comparison between XCI↔NSP conversions and CDN releases is fundamentally impossible**. Conversion validation uses (1) structural integrity, (2) filename=hash integrity, (3) round-trip integrity. Converted files (preserving gamecard encryption) install fine in Tinfoil/GoldLeaf — the same semantics as 4NXCI and similar tools.

## Performance
- to-nsp: 2.0GB XCI → 465MB NSP in **0.95 seconds** (streaming, minimal RAM footprint)

## Second validation: --keys distribution rewrite (2026-09-20)

**Crypto structure (empirically verified with prod.keys `header_key`, AES-128-XTS):**
- NCA header [0x200, 0x400) = single XTS data unit, **tweak value = 1**
- Decrypted first 4 bytes = `NCA3` magic (self-verifying key check)
- Decrypted +0x04 = distribution: **0x01=gamecard, 0x00=CDN**
- nca_id / content hashes exclude the header (0x400) — flipping does not affect cnmt or filename integrity

**NSP→XCI (--keys) comparison validation** (Dead Cells, original card XCI vs CDN NSP conversion):

| Field | Card original | Converted | |
|-------|--------------|-----------|---|
| magic / distribution / content_type / crypto_type / size / titleId | — | — | **All match** (distribution 0x01 on both sides) |
| Entry count and size set | 4 | 4 | Match |

Card↔CDN body differences (titlekey divergence) are expected; header field equality is the proof of conversion correctness.

**Key handling policy**: header_key is read at runtime only from prod.keys (`--keys` / `NXSHELF_PROD_KEYS` / ~/.switch/prod.keys auto-discovery). Never embedded in the binary or written to outputs.

## XTS tweak evolution correction

The GF(2^128) tweak evolution in XTS was initially implemented with big-endian carry (toward byte 0, 0x87 into byte 15). Nintendo XTS evolves the tweak as a **little-endian** integer (carry toward byte 15, 0x87 into byte 0). The bug was invisible to FlipDistribution (which only touches block 0, where both conventions produce identical tweaks) but affected multi-block operations like title ID extraction from block 1. Fixed with a pinned test vector.

## Multi-NSP merge and split validation (Mario Kart 8 Deluxe)

**Merge**: 3 NSPs (BASE 6 files + UPD 8 files + DLC 4 files) → single XCI with 18 files, all distribution bytes rewritten to 0x01.

**Split**: Merged XCI → BASE (10 files, 12.1GB) + UPD (4 files: cnmt+tik+cert+xml) + DLC (4 files, 121KB). All outputs verified as valid PFS0.

**Round-trip**: Split outputs → to-xci → 18 files (identical to direct merge).

**Known limitation**: Update content NCAs carry the BASE title ID. Splitting a merged base+update XCI places update content in the BASE NSP; the UPD NSP gets only cnmt+tik+cert+xml. Full separation would require cnmt (titlekey) parsing. DLC and single-title XCIs split perfectly.

## NCZ format findings (SIGNALIS sample)

- Section entries are **0x40 bytes** (not 0x1C as some sources claim)
- Layout: u64 offset, u64 size, u64 crypto_type, u64 relative_offset, byte[16] IV, byte[16] reserved
- Compressed data is a single continuous zstd stream starting immediately after the section table
- Decompression: prepend the uncompressed 0x4000-byte NCA header + zstd-decompress the remaining data
