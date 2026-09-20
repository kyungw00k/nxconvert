# nxconvert

닌텐도 스위치 컨테이너 변환기. NSP↔XCI를 무손실로 재포장하고, prod.keys가 있으면 NCA distribution 플래그까지 올바르게 재작성한다.

## 지금 시작 (3단계)

1. `go build -o nxconvert .` (또는 `brew install kyungw00k/stash/nxconvert`)
2. `./nxconvert to-nsp game.xci` — 같은 폴더에 `game.nsp` 생성
3. `./nxconvert to-xci game.nsp --keys ~/.switch/prod.keys` — distribution까지 카드 모드로

순수 Go 표준라이브러리만 사용 (외부 의존성 0). 스트리밍이라 26GB XCI도 RAM 안전 (실측: 2GB 덤프 → 0.95초).

## 명령어

| 하고 싶은 것 | 명령 |
|---|---|
| XCI → NSP | `nxconvert to-nsp input.xci [-o out.nsp]` |
| NSP → XCI | `nxconvert to-xci input.nsp [-o out.xci]` |
| 배포 플래그 재작성 | 양쪽에 `--keys prod.keys경로` (자동탐색: `~/.switch/prod.keys`, `~/switch-prod.keys`, env `NXSHELF_PROD_KEYS`) |

키는 런타임에만 읽는다 — 바이너리·출력에 절대 쓰이지 않는다.

## 검증 (실물 카드 덤프, 2026-09)

- **왕복 무결성**: XCI→NSP→XCI 하면 원본 secure 파티션과 이름·크기·SHA-256 전부 동일
- **distribution 재작성**: CDN NSP→XCI(`--keys`)의 복호화 헤더가 원본 카드 XCI와 전 필드 일치 (distribution 양쪽 0x01)
- 게임카드 명명규칙(파일명=콘텐츠 해시) 4/4 성립

상세: [docs/converter-validation.md](docs/converter-validation.md)

## 동작 원리 (한 눈에)

```
NSP = PFS0 컨테이너        XCI = GAMECARD 헤더 + HFS0 (update/normal/secure)
        └────────── NCA 파일들은 동일한 내용물 ──────────┘
변환 = NCA를 컨테이너 사이에서 재포장 (재서명 불필요)
--keys = NCA 헤더[0x200,0x400)을 header_key AES-XTS로 복호화 →
         +0x04 distribution 플립 → 재암호화 (해시·cnmt 영향 없음)
```

## 주의

변환물은 개인 백업 범위에서만 사용할 것. 카드 덤프의 NCA는 카드 타이틀키 암호를 유지하며 (CDN 배포본과 바이트가 다른 것이 정상), 설치는 Tinfoil/GoldLeaf/sigpatch 환경에서 동작한다.
