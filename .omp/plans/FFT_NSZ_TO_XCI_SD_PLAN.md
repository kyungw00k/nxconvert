# FFT NSZ → XCI → Switch SD 변환 배치 계획

## Context

`~/Downloads/switch/Final Fantasy Tactics the Ivalice Chronicles [NSZ]/` 의 NSZ 세트를
하나의 XCI로 변환해 Switch SD 카드(`/Volumes/NO NAME`, FAT32/msdos, MIG 플래시카트 덤프
레이아웃)에 복사한다. 사용자 결정사항: **BASE+업데이트+DLC 2종 병합**, prod.keys는
**사용자 지정 GitHub 소스에서 다운로드해 사용**(NCA distribution을 gamecard 0x01로
재작성), 공간 부족 시 **Super Mario Bros Wonder 삭제**.

- 도구: `~/Sandbox/nxconvert/nxconvert` (prebuilt arm64, 2026-09-21 07:59 빌드).
  `to-xci`는 NSZ 입력을 지원함(.ncz 엔트리를 $TMPDIR 임시 .nca로 해제 후 스트리밍,
  변환 종료 시 자동 삭제). 병합은 입력 순서대로, 이전 입력에 같은 이름 엔트리가 있으면
  스킵(첫 입력 우선) → 반드시 BASE → UPDATE → DLC 순서.
- SD 레이아웃(실측, 기존 3개 게임과 동일): `"/Volumes/NO NAME/<Game>.xci/<Game>.xci/00, 01"`
  분할 파트. 파트 크기: 첫 파트 4,294,907,660 B (0xFFFD8000), 나머지는 꼬리.
  FAT32 단일 파일 4GiB−1 제한 때문에 분할 필수(병합 XCI ≈7.2GB).
- 공간: SD 여유 6.9GiB, 필요 ≈6.7GiB — 아슬아슬하게 맞음. 로컬 디스크 716GiB 여유
  (NCZ 임시파일 + XCI + 분할 파트 피크 ≈22GiB, 문제없음).

## Approach

작업 디렉터리: `/tmp/fft-ivalice/`. 모든 경로에 공백·대괄호 있음 — 항상 따옴표.

### 1. 사전 확인 (변경 없음)

```bash
cd ~/Sandbox/nxconvert
test -x ./nxconvert || echo "BINARY MISSING"
mount | grep "NO NAME"          # /dev/diskNs1 ... (msdos ...) 마운트 확인
mkdir -p /tmp/fft-ivalice
```

prod.keys 다운로드 (사용자 지정 소스 — 2026-09-21 확인: 파일 존재, `header_key` 포함.
nxconvert는 이 header_key 하나만 사용):

```bash
curl -fL -o /tmp/fft-ivalice/prod.keys \
  https://raw.githubusercontent.com/THZoria/NX_Firmware/main/prod.keys
grep -q '^header_key = ' /tmp/fft-ivalice/prod.keys && echo KEYS-OK
```

`KEYS-OK` 확인 후 진행. 다운로드/검증 실패 시 1회 재시도 후에도 실패하면 중단·보고
(keyless로 대체 진행하지 않는다 — 키 사용이 사용자 명시 요구사항).

### 2. 변환 (BASE → UPDATE → DLC 순서 고정)

```bash
SRC="$HOME/Downloads/switch/Final Fantasy Tactics the Ivalice Chronicles [NSZ]"
./nxconvert to-xci \
  "$SRC/Final Fantasy Tactics the Ivalice Chronicles [010038B015560000][v0] (6.78 GB).nsz" \
  "$SRC/Final Fantasy Tactics the Ivalice Chronicles [010038B015560800][v458752] (0.39 GB).nsz" \
  "$SRC/2 DLC/Final Fantasy Tactics the Ivalice Chronicles [DLC Pre-Order Bonuses] [010038B015561001][v0].nsp" \
  "$SRC/2 DLC/Final Fantasy Tactics the Ivalice Chronicles [DLC Deluxe Edition Bonuses] [010038B015561002][v0].nsp" \
  -o /tmp/fft-ivalice/FFT.xci --keys /tmp/fft-ivalice/prod.keys
```

성공 기준: exit 0, stderr에 입력별 "`  <input>: N files, X MB`" 라인(중복 스킵 있으면
"duplicate(s) skipped" 표시), `.ncz -> .nca` 해제 라인, 요약
"`to-xci: 4 input(s) -> /tmp/fft-ivalice/FFT.xci (N files, X MB)`", "`wrote …`".
N과 X를 기록(다음 단계 검증에 사용). 입력 파싱 오류가 나면 해당 파일명과 stderr 그대로
보고하고 중단 — 입력을 빼고 진행하지 않는다.

### 3. 로컬 검증 (round-trip)

```bash
./nxconvert to-nsp /tmp/fft-ivalice/FFT.xci -o /tmp/fft-ivalice/roundtrip.nsp
```

성공 기준: exit 0. to-nsp가 보고한 파일 수/총 MB가 2단계 요약의 N, X와 일치(엔트리
집합이 그대로 왕복했음이 증명). 불일치면 중단·보고. 확인 후
`rm /tmp/fft-ivalice/roundtrip.nsp`.

### 4. MIG 규격 분할

```bash
mkdir -p /tmp/fft-ivalice/parts && cd /tmp/fft-ivalice/parts
split -b 4294901760 -d -a 2 ../FFT.xci part   # → part00, part01
mv part00 00 && mv part01 01
cat 00 01 | cmp - ../FFT.xci && echo SPLIT-OK
```

- macOS BSD `split`은 `-d`(숫자 접미), `-a`(길이) 지원. `-d` 미지원 에러 시 대체:
  `python3 -c 'import sys;[open(f"{i:02d}","wb").write(c) for i in range(0,sys.argv[3] and 99) ]'`
  대신 단순 루프 스크립트로 4294901760 B씩 `00`,`01`,… 생성(같은 검증 통과하면 됨).
- 예상: 2개 파트(`00` = 4,294,907,660 B, `01` = 나머지 ≈2.9GB). XCI가 8.59GB를 넘으면
  3개 파트 — 그대로 전부 복사(동작 변화 없음).
- `cmp` exit 0 필수. 실패 시 재분할, 재확인.

### 5. SD 공간 확보 + 복사

```bash
V="/Volumes/NO NAME"
XCI_SIZE=$(stat -f%z /tmp/fft-ivalice/FFT.xci)
AVAIL=$(df -k "$V" | awk 'NR==2{print $4*1024}')
if [ "$AVAIL" -lt $((XCI_SIZE + 104857600)) ]; then     # 100MiB 여유
  rm -rf "$V/Super Mario Bros Wonder.xci"               # 사용자 지정 삭제 대상
  AVAIL=$(df -k "$V" | awk 'NR==2{print $4*1024}')
  [ "$AVAIL" -lt $((XCI_SIZE + 104857600)) ] && echo "STILL SHORT — STOP, report" && exit 1
fi
DST="$V/Final Fantasy Tactics the Ivalice Chronicles.xci/Final Fantasy Tactics the Ivalice Chronicles.xci"
mkdir -p "$DST"
cp /tmp/fft-ivalice/parts/00 /tmp/fft-ivalice/parts/01 "$DST/"
```

- 삭제는 오직 공간 부족 때만(예상으로는 불필요). 삭제 실행 시 최종 보고에 명시.
- `(Certificate).bin`/`(Initial Data).bin`은 만들지 않는다 — CDN NSZ 원본에 카드
  인증서가 없어 위조 불가. 기존 3게임의 bin은 실물 덤프 부산물. MIG는 cert 없는
  이미지도 로드(보고에 한계로 기록).

### 6. SD 검증 + 마무리

```bash
cmp /tmp/fft-ivalice/parts/00 "$DST/00" && cmp /tmp/fft-ivalice/parts/01 "$DST/01" && echo COPY-OK
ls -l "$DST"          # 00, 01 크기 확인 (00=4294901760)
df -h "$V"
diskutil eject "$V"   # 안전 분리
rm -rf /tmp/fft-ivalice
```

`cmp` exit 0 필수. 최종 보고: 병합 파일 수/총 MB, keys 사용(다운로드 소스),
파트 경로·크기, 삭제 여부, eject 완료.

## Critical files & anchors

- `~/Sandbox/nxconvert/nxconvert` — 실행 대상 prebuilt 바이너리(재빌드 불필요).
- `main.go:192-306` (`convertToXCI`) — 병합 순서/첫입력-우선 중복 스킵/`-o`/`--keys` 동작.
- `main.go:529-609` (`decompressNCZEntries`) — .ncz → $TMPDIR 임시 .nca(피크 ≈7.2GB, 자동 정리).
- 입력 4파일 — `~/Downloads/switch/Final Fantasy Tactics the Ivalice Chronicles [NSZ]/` 및 `2 DLC/`.
- 레이아웃 근거 — `/Volumes/NO NAME/Mario Kart 8 Deluxe.xci/Mario Kart 8 Deluxe.xci/{00,01}` (실측 4294901760B+꼬리).

## Verification

1. 변환 출력: 2단계 "wrote /tmp/fft-ivalice/FFT.xci" + 기록된 N files / X MB.
2. 왕복 무결성: to-nsp 파일 수·총 MB 일치(3단계).
3. 분할 무결성: `cat 00 01 | cmp - FFT.xci` → SPLIT-OK(4단계).
4. 최종: SD 파트 `cmp` COPY-OK, `00`=4,294,907,660B, `df`로 잔여 확인, eject(6단계).
   → SD에서 `<FFT>.xci/<FFT>.xci/00,01` 구조가 기존 3게임과 동일한 관측 가능한 결과.

## Assumptions & contingencies

- **prod.keys**: THZoria/NX_Firmware raw URL에서 다운로드(원본 콘텐츠는 실행 시점
  확인). `--keys` 지정 시 patchNCADistribution이 NCA3 매직 셀프체크로 키를 검증하므로,
  키가 틀리면 to-xci가 오류로 종료됨(잘못된 결과물이 나오지 않음). 다운로드 실패 →
  재시도 1회 → 중단·보고(keyless 폴백 없음).
- **공간**: 예상 6.7GiB ≤ 여유 6.9GiB로 삭제 없이 통과 예정. 실제 해제 크기가 파일명
  표기(6.78+0.39GB, 반올림)보다 커서 부족하면 → Super Mario Bros Wonder 삭제(유일 지정).
  삭제 후에도 부족(있을 수 없음, +7.4G)하면 중단·보고.
- **러시아어 번역 NSZ**(하위 폴더의 v262144/v393216 업데이트 NSZ)와 atmosphere 모드는
  원 요청(BASE+UPD+DLC) 밖 — 제외.
- XCI가 3분할이어도 전부 복사(파트 수는 검증 조건 아님).
