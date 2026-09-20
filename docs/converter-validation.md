# nxconvert 검증 기록 (2026-09-20, 실물 카드 덤프 기준)

## 검체
- Dead Cells 카트리지 덤프: `Dead Cells.xci` 1,996,488,704 B (2GB 카드 사이즈 클래스, 실사용 465MB) + 카드 인증서/Initial Data bin
- 동일 게임 CDN NSP: `Dead Cells [BASE][0100646009FB][v0].nsp` 464,974,608 B

## 결론: 왕복 무결성 통과

```
원본 XCI ──to-nsp──▶ NSP' ──to-xci──▶ XCI'
원본 XCI secure NCA 4개 ≡ XCI' secure NCA 4개  (이름·크기·SHA-256 전부 동일)
```

| NCA | 크기 | 비고 |
|-----|------|------|
| e82c4e…92.nca | 463,634,432 | program |
| 2d432a…50.nca | 1,192,960 | control |
| c64b5d…b8.nca | 143,360 | html |
| 5877af…14.cnmt.nca | 3,584 | cnmt |

게임카드 명명규칙(파일명 = 콘텐츠 SHA-256)이 4/4 성립 — 변환 중 콘텐츠 무결성 유지의 독립적 증거.

## 핵심 발견: 게임카드 NCA와 CDN NCA는 같은 평문의 다른 암호문이다

XCI에서 추출한 NCA와 CDN NSP의 NCA는 **크기는 전부 같지만 해시가 전부 다르다** (program NCA 기준 99.77% 바이트 상이). 원인:
- 게임카드 NCA: 카드 고유 타이틀키로 암호화
- CDN/eShop NCA: 티켓의 타이틀키로 암호화
- cnmt는 NCA 해시 목록을 내장하므로 연쇄적으로 달라짐

따라서 **XCI↔NSP 변환물과 CDN 배포본의 직접 바이트 비교는 원리적으로 불가능**하다. 변환 검증은 (1) 구조 정합, (2) 파일명=해시 무결성, (3) 왕복 무결성으로 수행한다. 변환물(게임카드 암호 유지)은 Tinfoil/GoldLeaf 등에서 그대로 설치된다 — 4NXCI 등 기존 도구와 동일한 의미 구조.

## 성능
- to-nsp 2.0GB XCI → 465MB NSP: **0.95초** (스트리밍, RAM 상주 최소)

## 2차 검증: --keys distribution 재작성 (2026-09-20 추가)

**암호 구조 실측** (prod.keys의 `header_key`, AES-128-XTS):
- NCA 헤더 [0x200, 0x400) = XTS 단일 데이터유닛, **tweak 값 = 1**
- 복호화 첫 4바이트 = `NCA3` 매직 (키 검증의 자기증명)
- 복호화 +0x04 = distribution: **0x01=게임카드, 0x00=CDN**
- nca_id/콘텐츠 해시는 헤더(0x400) 제외 바디만 커버 → 플립해도 cnmt·파일명 정합 유지

**NSP→XCI (--keys) 대조 검증** (Dead Cells, 원본 카드 XCI vs CDN NSP 변환):

| 필드 | 카드 원본 | 변환 | |
|------|----------|------|---|
| magic / distribution / content_type / crypto_type / size / titleId | — | — | **전부 일치** (distribution 양쪽 0x01) |
| 엔트리 수·크기 집합 | 4 | 4 | 일치 |

카드↔CDN 간 바디가 다른 것(titlekey 차이)은 원리적이며, 헤더 필드의 완전 일치가 변환 정확성의 증거다.

**키 취급 원칙**: header_key는 prod.keys에서 런타임에만 읽는다 (`--keys` / `NXSHELF_PROD_KEYS` / ~/.switch/prod.keys 자동탐색). 바이너리·리포에 내장하지 않는다.
