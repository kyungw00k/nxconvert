# nxconvert

Nintendo Switch container converter. Repacks NSP ↔ XCI losslessly, and — with your own prod.keys — rewrites the NCA distribution flag so converted files match their target format properly.

## Quick start (3 steps)

1. `go build -o nxconvert .` (or `brew install kyungw00k/tap/nxconvert`)
2. `./nxconvert to-nsp game.xci` — writes `game.nsp` next to the input
3. `./nxconvert to-xci game.nsp --keys ~/.switch/prod.keys` — distribution rewritten to gamecard mode

Pure Go, zero external dependencies. Streams everything — a 26 GB XCI never touches RAM more than one buffer at a time (measured: 2 GB dump converts in 0.95 s).

## Commands

| Goal | Command |
|---|---|
| XCI → NSP | `nxconvert to-nsp input.xci [-o out.nsp]` |
| NSP → XCI | `nxconvert to-xci input.nsp [-o out.xci]` |
| Rewrite distribution flag | add `--keys <prod.keys>` to either (auto-discovered at `~/.switch/prod.keys`, `~/switch-prod.keys`, or `NXSHELF_PROD_KEYS`) |

Keys are read at runtime only — never embedded in the binary, never written to outputs.

## How it works

```
NSP = PFS0 container          XCI = GAMECARD header + HFS0 (update/normal/secure)
        └────────── the NCAs inside are the same payload ──────────┘
conversion = repack NCAs between containers (no re-signing)
--keys = decrypt NCA header [0x200,0x400) with header_key (AES-XTS) →
         flip distribution at +0x04 → re-encrypt (content hashes unaffected)
```

## Validation (real cartridge dump, 2026-09)

- **Round-trip integrity**: XCI→NSP→XCI reproduces the original secure partition byte-for-byte (names, sizes, SHA-256 all identical)
- **Distribution rewrite**: CDN NSP→XCI with `--keys` produces decrypted headers matching the original cartridge XCI on every field (distribution 0x01 on both sides)
- Gamecard naming convention (filename = content hash) verified 4/4

Details: [docs/converter-validation.md](docs/converter-validation.md)

## Notes

- Use converted files only for personal backups. Cartridge-dump NCAs keep their gamecard titlekey encryption (bytes legitimately differ from CDN releases); installs work in Tinfoil/GoldLeaf/sigpatch environments.
- NSZ/XCZ (compressed containers) are not supported yet.
