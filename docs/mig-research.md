# nxconvert MIG Flashcart Compatibility — Research Log & PRD

**Date**: 2026-09-21 ~ 2026-09-22
**Status**: Active investigation — one remaining bug (kaak double-decrement) fixed, final hardware test pending
**Repo**: github.com/kyungw00k/nxconvert

---

## 1. Problem Statement

Nintendo Switch games distributed as NSP (eShop/CDN format) cannot be played on the MIG Switch v1 flashcart, which only reads XCI (gamecard format). The goal is to convert NSP → XCI such that the output boots on a **stock (unmodified) Switch** via the MIG v1 flashcart.

**Why this is hard**: The Switch's gamecard subsystem validates content differently than the eShop path. The MIG v1 firmware adds its own validation layer. Neither is publicly documented.

---

## 2. Hardware & Software Context

| Component | Detail |
|-----------|--------|
| Flashcart | MIG Switch v1 (old firmware, eject/reinsert game cycling, no menu) |
| Console | Stock Nintendo Switch (no CFW, no sigpatches) |
| SD Card | 29GiB FAT32, dumper-style folder layout with `.bin` card identity files |
| Keys | prod.keys with master_key_00 through master_key_14 (FW ≤ 17.0 era dump) |
| Test game | Dead Cells (has BOTH card dump and CDN NSP — ideal for comparison) |
| Target games | DQVII, FFT, Trails in the Sky (NSP-only, no card dumps, gen 15+ keys needed) |

---

## 3. What the Working "Card Dump" Actually Is

**Critical discovery**: hactoolnet analysis proved the working Dead Cells "card dump" is itself a **conversion**, not a real card extraction:

```
Fixed-Key Signature (FAIL)     ← NCA header RSA signature broken
RomFS (436MB): 100% identical to CDN NSP plaintext
ExeFS: identical except 512B NPDM signature block
Master Key Revision: 4 (CDN has 3) — generation bumped +1
Distribution: GameCard (CDN has Download)
Key area: {0,0,fresh_random_key,0} (CDN has {0,0,cdn_key,0})
NCA IDs: SHA-256(content)[:16] — recomputed
cnmt: content entries repointed to new IDs/hashes
```

**Implication**: Stock Switch + MIG v1 does NOT verify NCA header signatures. The gate is structural self-consistency + the right generation flag.

---

## 4. MIG v1 Validation Model (Empirically Mapped)

```
Stage 1 (Green LED): Card identity check
  - XCI header PackageId ↔ Initial Data bin
  - XCI header InitialDataHash (0x160) ↔ SHA-256(Initial Data bin)
  - FAIL → no green LED, "게임카드를 읽을 수 없습니다"

Stage 2 (Game listed): Secure partition content validation
  - NCA structure and hash chain consistency
  - NCA distribution byte must be 0x01 (GameCard)
  - NCA crypto generation must match card header expectations
  - FAIL → green LED but game not recognized

Stage 3 (Boot): Content mounting
  - Section decryption with key_area keys
  - Internal hash verification (PFS0/IVFC chains)
  - FAIL → green LED, game listed, boot error
```

### What passes each stage:

| Requirement | Stage | How to satisfy |
|-------------|-------|----------------|
| Header ↔ bin consistency | 1 | Copy donor card's PackageId + InitialDataHash into XCI header |
| dist=0x01 on all NCAs | 2 | Set during remaster |
| Self-consistent hash chains | 2 | NCA name = SHA-256(content)[:16], cnmt entries match |
| Correct crypto generation | 2 | Bump cryptoType2 (+0x20) by +1 from CDN source |
| Section plaintext valid | 3 | Preserve CDN plaintext during re-encryption |
| Key area matches section key | 3 | Encrypt fresh random key under new-generation kaak |

---

## 5. The Working Recipe (Reverse-Engineered)

From the card dump vs CDN NSP byte-level comparison:

```
CDN NSP → Working MIG XCI:

1. For each NCA (program, control, legalinfo):
   a. Decrypt NCA header (header_key XTS, tweak=1)
   b. Set distribution byte (+0x04) = 0x01 (GameCard)
   c. Clear rights_id (+0x30..0x40) if present
      - For rights-based NCAs: decrypt titlekey from .tik (titlekek),
        encrypt into all 4 key_area slots under new kaak
   d. Bump cryptoType2 (+0x20) by +1 (e.g., 4→5)
      - CRITICAL: only +0x20, NOT +0x06 (format indicator!)
   e. Generate fresh random 16-byte section key
   f. Encrypt key area {0, 0, newKey, 0} under new-generation kaak
   g. Re-encrypt all sections: decrypt with CDN key → encrypt with newKey
      - IV = reverse(fs_header.sctr) ‖ be64(section_offset >> 4)
      - fs_header[ordinal] at NCA+0x400+ordinal*0x200, XTS tweak=2+ordinal
   h. Re-encrypt NCA header (header_key XTS, tweak=1)
   i. Rename to SHA-256(new_content)[:16] + ".nca"

2. For cnmt NCA:
   a. Decrypt, patch content entries (0x38 bytes each):
      - hash[32] @+0x00 = SHA-256(new NCA content)
      - id[16] @+0x20 = new NCA name bytes
      - (size and type unchanged)
   b. Recompute PFS0 hash table: 0x1000-byte blocks over partition,
      last block raw (no padding)
   c. Recompute master hash = SHA-256(hash_table) → fs_header+0x08
   d. Recompute section-header hash = SHA-256(fs_header) → header+0x80
   e. Apply same header patches (dist, gen, key area)
   f. Rename to SHA-256(new_content)[:16] + ".cnmt.nca"

3. Package as XCI (real card layout via transplant):
   - Copy donor card's [0x0000, secure_offset) verbatim
     (gamecard header, update firmware area, logo partition, normal)
   - Replace secure partition with new NCA HFS0
   - Patch root secure entry (size + hash)
   - Recompute root hash at header+0x140

4. MIG folder structure:
   GameName.xci/
   ├── GameName (Certificate).bin     ← from any real card dump
   ├── GameName (Initial Data).bin    ← from same dump
   └── GameName.xci                   ← the converted XCI
   (Card ID Set + Card UID bins optional but recommended)

5. Card header identity:
   - PackageId @0x110 = donor card's real PackageId
   - InitialDataHash @0x160 = SHA-256(donor's Initial Data bin)
```

---

## 6. Key Technical Discoveries

### 6.1 NCA Section CTR IV Rule
```
IV (16 bytes) = reverse(fs_header[ordinal].section_ctr[8]) ‖ be64(section_offset >> 4)
```
- `fs_header[ordinal]` at NCA+0x400+ordinal*0x200, XTS-encrypted with header_key at tweak 2+ordinal
- `section_ctr` at decrypted fs_header+0x140 (8 bytes, little-endian u64)
- Verified against retail IVFC master hash (Dead Cells program NCA)

### 6.2 NCA Key Area kaak Selection
```
kaak_name = key_area_key_{application|ocean|system}_{max(cryptoType, cryptoType2) - 1:02d}
```
- `cryptoType` = header byte at +0x06 (relative to decrypted region)
- `cryptoType2` = header byte at +0x20
- **NEVER pass pre-computed revision to KAAKName** — it does max()-1 internally
- Double-decrement caused the final key to differ from the encryption key (the LAST bug fixed)

### 6.3 cryptoType2-only Generation Bump
```
Working card dumps: cryptoType (+0x06) stays at 02, cryptoType2 (+0x20) bumped +1
```
Setting +0x06 changes the format indicator → console rejects the NCA.

### 6.4 PFS0 Hash Table (inside cnmt sections)
```
Block size: from fs_header+0x28 (typically 0x1000)
Partition: [fs_header+0x38 offset, +0x48 offset+size)
Entry[b] = SHA-256(partition[b*blocksize .. next]) — last block NO padding
Master hash = SHA-256(all entries) → fs_header+0x08
```

### 6.5 Section Header Hash
```
decrypted_header[0x80 + ordinal*0x20] = SHA-256(decrypted_fs_header[ordinal] full 0x200 bytes)
```

### 6.6 NCA Filename = SHA-256(content)[:16]
Verified on both card dump and CDN: `filename.hex() == SHA-256(entire_file).hexdigest()[:32]`

### 6.7 The 4-bin Card Identity Files
| File | Content | Reusable across games? |
|------|---------|----------------------|
| Certificate (512B) | Nintendo RSA-signed, per-card DeviceID→HwKey | Yes (copy from any dump) |
| Initial Data (512B) | PackageId + challenge-response + nonce | Yes (must match XCI header values) |
| Card ID Set (12B) | Chip manufacturer/capacity | Yes |
| Card UID (64B) | Chip serial | Yes |

The MIG validates **header ↔ bin consistency**, not the bins' game association.

---

## 7. All Approaches Tried (Chronological)

| # | Approach | Result | Root Cause |
|---|----------|--------|------------|
| 1 | NSP→XCI container swap (original WriteXCI) | ❌ Red LED | Zero-header template (RomSize=0, PackageId=0) |
| 2 | Distribution flag flip only (--keys) | ❌ Red LED | NCA names no longer match SHA-256 |
| 3 | Card-titlekey re-encryption (--card-titlekey) | ❌ Various | Section CTR IV wrong (offset-only, missing sctr high half) |
| 4 | Transplant into real card layout (--card-template) | ❌ No game listed | NCA content still CDN (dist=0x00 or broken hashes) |
| 5 | NSC_BUILDER spec synthetic header (WriteXCINSC) | ❌ Red LED | Fake InitialDataHash (0x160) ≠ bin hash |
| 6 | NSC spec + real PackageId/InitialDataHash | ❌ Green, no game | NCA names stale (CDN names ≠ SHA-256 of modified content) |
| 7 | Card NCA names + CDN content | ❌ Green, no game | Names don't match SHA-256 of CDN content |
| 8 | Untouched CDN NCAs + real header values | ❌ Green, no game | dist=0x00 (Download) on gamecard |
| 9 | Dump-style: self-consistent IDs + cnmt repointed | ❌ Green→off | CDN section keys (not fresh random) |
| 10 | Dump-style + fresh random keys + re-encryption | ❌ "읽지 못함" | Wrong IV for multi-section NCAs (missing sctr) |
| 11 | Correct IVs (sctr from fs_header) | ❌ Section corrupted | kaak double-decrement (oldKaak) — wrong decryption key |
| 12 | Fixed oldKaak + gen bump (+0x20 only) | ❌ Section corrupted | newKaak double-decrement — encryption key ≠ re-encryption key |
| 13 | **Fixed newKaak (raw bytes to KAAKName)** | ⏳ **PENDING TEST** | — |

---

## 8. nxconvert CLI Reference (Current)

```
Usage:
  nxconvert to-nsp input.xci [-o output.nsp]
  nxconvert to-xci input1.nsp [input2.nsp ...] [-o output.xci]
  nxconvert split input.xci --keys prod.keys -o outdir/
  nxconvert help

Options:
  --keys path          prod.keys (to-xci requires it)
  --no-remaster        Skip NCA header rewriting (emulator output)
  --dump-style         Fully self-consistent remaster (MIG v1 target)
  --mig-folder dir     MIG-ready game folder output
  --mig-bins path      Donor card dump for Certificate/Initial Data bins

Examples:
  # Emulator use (no keys needed):
  nxconvert to-xci game.nsp --no-remaster -o game.xci

  # MIG v1 use (full recipe):
  nxconvert to-xci game.nsp \
    --keys ~/.switch/prod.keys \
    --dump-style \
    --mig-folder /Volumes/SD \
    --mig-bins ~/dumps/donor.xci \
    -o game.xci
```

---

## 9. Known Limitations

1. **Gen 15+ games**: DQVII, FFT, Trails need master_key_15+ (user's prod.keys only has gen 14). Re-dump keys from console on current firmware.

2. **NSZ input**: Decompresses correctly but dump-style remaster hasn't been tested end-to-end with NSZ.

3. **Rights-based NCAs**: Recipe handles them (titlekey → key_area slots), but untested with a real rights-based game on hardware.

4. **nscb_rust (reference tool)**: Has cryptoType2 offset bug (+0x05 instead of +0x20), silently produces broken output for gen 15+ titles. Upstream issue worth reporting.

---

## 10. Architecture Notes

```
~/Sandbox/nxconvert/
├── main.go                          # CLI + remaster pipeline
├── internal/nxformat/
│   ├── ncaheader.go                 # NCA header XTS decrypt/encrypt, fs_header helpers
│   ├── reencrypt.go                 # Section CTR re-encryption, key area, section parsing
│   ├── xci.go                       # XCI writers (NSC-spec, transplant)
│   ├── hfs0.go                      # HFS0 partition builder (streaming, hash-chained)
│   ├── pfs0.go                      # PFS0/NSP parser
│   ├── tik.go                       # Ticket parser (rights_id, titlekey)
│   └── ncz.go                       # NSZ/NCZ decompression
└── cmd/
    ├── dumpmig/                     # One-off: transplant dump-style NCAs into card layout
    └── keycheck/                    # One-off: NCA key area pattern analysis
```

### Key functions:
- `patchHeaderForDump()` — the NCA header rewrite (dist, gen, key area, rights)
- `remasterDumpStyle()` — orchestrates Phase 1 (non-cnmt NCAs) + Phase 2 (cnmt)
- `remasterCnmt()` — cnmt content entry repointing + hash chain recomputation
- `ReencryptNCA()` — streaming section re-encryption with per-section IVs
- `SectionIV()` — builds the correct CTR IV from fs_header + offset
- `TransplantXCI()` — copies real card layout, replaces secure partition

---

## 11. References

- NSC_BUILDER: https://github.com/julesontheroad/NSC_BUILDER (Python original)
- nscb_rust: https://github.com/cxfcxf/nscb_rust (Rust port, has gen-15+ bug)
- hacbuild: https://github.com/LucaFraga/hacbuild (original XCI builder, constant identity source)
- NSP-to-XCI-Converter: https://github.com/davFaithid/NSP-to-XCI-Converter (hacbuild wrapper)
- LibHac/hactoolnet: https://git.ryujinx.app/projects/LibHac (authoritative format analysis)
- hactool: https://github.com/SciresM/hactool (C original, section CTR logic reference)
- XCI_Builder: https://github.com/julesontheroad/XCI_Builder (NSC predecessor)
- GBAtemp NSC_Builder thread: https://gbatemp.net/threads/522486/ ("requires sigpatches" — for CFW, not gamecard)
- GBAtemp flashcart thread: https://gbatemp.net/threads/mig-switch-not-working-updating.652425/ (MIG behavior)
- consolemods.org MIG Flash wiki ("NSP or XCI files without certificates will not work")
