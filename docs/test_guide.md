# SysGuard 테스트 가이드

SysGuard를 **실제로 돌려서** 확인하는 종합 가이드. 두 단계로 나뉜다.

- **Part A — root 불필요**: fake 모드 + Python 테스트. eBPF/디스플레이 없이 파이프라인·판정·리포트를 검증한다. (개발 환경에서 이미 통과 확인됨)
- **Part B — 라이브 eBPF (sudo 필요)**: 실제 syscall을 잡아 9개 tracepoint(7종 event)·13개 규칙이 동작하는지 확인한다. 이건 **타깃 VM에서 직접** 해야 한다.

경로는 이 저장소 기준이다. 다른 곳이면 `SG=/path/to/SysGuard` 로 바꿔 쓴다.

```bash
SG=/home/vboxuser/SysGuard
cd "$SG"
```

## ⚠️ 안전 수칙

- 위험 명령/민감 파일은 **저장소 안의 일회용 샌드박스**(`demo/sandbox_test/`)와 **더미 파일**로만 재현한다. 실제 credential/SSH 키를 쓰지 않는다.
- `git reset --hard` 같은 **파괴적 명령은 실제로 실행하지 말고** `echo`로 재현한다 (규칙은 argv 문자열을 매칭하므로 `echo git reset --hard` 만으로 발화한다).
- 모니터링을 켜두면 이후 셸 활동이 전부 로그에 섞인다. 테스트가 끝나면 반드시 `Ctrl-C`/Stop 한다.

---

## 1. 사전 준비

패키지 (Ubuntu 24.04 기준):

```bash
sudo apt update
sudo apt install -y clang llvm make gcc libbpf-dev libelf-dev zlib1g-dev \
                    bpftool linux-tools-common python3 python3-tk
```

BTF 확인 (CO-RE에 필요):

```bash
ls -l /sys/kernel/btf/vmlinux     # 있어야 함
```

빌드 — `make` 하나면 3개 산출물이 전부 생성된다 (README "Build" 계약):

```bash
cd "$SG"
make
ls -l build/sysguard.bpf.o build/sysguard.skel.h build/sysguard
```

- [ ] `build/sysguard` 가 존재하고 실행 가능하다
- [ ] 빌드 경고가 없다

---

## Part A — root 없이 검증

### 2.1 Python 테스트 스위트 (핵심 로직 회귀)

정책·시퀀스·판정·리포트·이벤트 계약을 non-sudo로 전부 검증한다.

```bash
cd "$SG"
python3 -m unittest discover -s tests -t .
```

- [ ] `OK` 로 끝난다 (실패 0건. 총 개수는 테스트가 늘면서 바뀌므로 숫자가 아니라 `OK` 여부로 판단한다)

### 2.2 fake 모드 → JSONL → 리포트

eBPF/root 없이 결정적 이벤트를 만들어 파이프라인 전체를 확인한다.

```bash
cd "$SG"
mkdir -p logs
./build/sysguard --fake --agent-mode --target-comm claude \
  --project-path "$SG" --output logs/session_fake.jsonl

python3 app/report.py logs/session_fake.jsonl --agent claude --project-path "$SG"
xdg-open logs/session_fake.html    # 또는 브라우저로 직접 열기
```

빠른 JSONL 점검 (전 이벤트 타입이 나오는지):

```bash
python3 -c 'import json,collections; \
rows=[json.loads(l) for l in open("logs/session_fake.jsonl") if l.strip()]; \
print("events:", dict(collections.Counter(r["event"] for r in rows))); \
print("alerts:", sorted({r["rule_id"] for r in rows if r.get("alert")}))'
```

- [ ] `events` 에 `execve/openat/unlinkat/renameat2/fchmodat/exit_group/connect` 7종이 보인다
- [ ] `alerts` 에 12개 C 규칙 ID가 보인다 (아래 표 3.2의 C 규칙 전부; `possible-secret-exfiltration`은 C alert이 아니라 리포트가 계산 — 3.3 참고)
- [ ] 리포트 배지가 **UNSAFE** (fake 데이터에 `.env`→curl 시퀀스 등이 섞여 있음)
- [ ] 리포트 섹션 순서가 README §9대로: Session Metadata → Commit Safety badge → Normal Activity → Boundary Violations → Protected Path Access → Dangerous Commands → Git Summary → Alert Details → **Recent Events** → Recommended Actions

---

## Part B — 라이브 eBPF (sudo 필요) ★핵심★

실제 syscall을 잡는 진짜 검증. **타깃 VM에서** 한다.

### 3.1 기본 실행

터미널 1 — 수집기 시작 (`bash` 서브트리를 감시):

```bash
cd "$SG"
mkdir -p logs
sudo ./build/sysguard --agent-mode --target-comm bash \
  --project-path "$SG" --output logs/session_live.jsonl
```

터미널 2 — **이미 열려 있던** 셸에서 (새 터미널을 열면 셸 시작 과정이 잡힌다) 샌드박스를 만들고 아래 트리거들을 실행한다:

```bash
cd "$SG"
mkdir -p demo/sandbox_test/.ssh demo/sandbox_test/build
echo "SECRET_KEY=dummy" > demo/sandbox_test/.env
: > demo/sandbox_test/.ssh/id_rsa
: > demo/sandbox_test/test.sh
: > demo/sandbox_test/tmpfile
```

끝나면 터미널 1에서 `Ctrl-C` → JSONL이 flush/close 된다. 그다음 리포트:

```bash
python3 app/report.py logs/session_live.jsonl --agent bash --project-path "$SG"
xdg-open logs/session_live.html
```

> sudo로 돌린 뒤 파일 소유권이 root면: `sudo chown $USER logs/session_live.*`

### 3.2 규칙별 트리거 표 (9 tracepoint / 7종 event · 13 규칙)

터미널 2(감시 대상 셸)에서 실행. 규칙은 **syscall 진입 시점**에 잡히므로 명령이 실패해도(권한 거부 등) "시도"로 기록된다.

| # | tracepoint | 규칙 (severity) | 안전한 트리거 명령 |
|---|---|---|---|
| 1 | execve | `downloader-exec` (medium) | `curl --version` *(URL 없이 — 네트워크 안 씀)* |
| 2 | execve | `destructive-rm` (high) | `rm -rf demo/sandbox_test/build` |
| 3 | execve | `git-reset-hard` (high) | `echo git reset --hard` *(실제 실행 금지)* |
| 4 | execve | `git-clean-force` (high) | `echo git clean -fd` |
| 5 | execve | `unsafe-chmod` (medium) | `chmod 777 demo/sandbox_test/test.sh` *(argv 매칭)* |
| 6 | openat | `env-file-access` (high) | `cat demo/sandbox_test/.env` |
| 7 | openat | `ssh-key-access` (critical) | `cat demo/sandbox_test/.ssh/id_rsa` *(더미 파일)* |
| 8 | openat | `shadow-access` (critical) | `cat /etc/shadow 2>/dev/null` *(읽기 시도만)* |
| 9 | openat | `sudoers-access` (high) | `cat /etc/sudoers 2>/dev/null` |
| 10 | openat | `project-boundary-access` (high) | `cat ~/.bashrc` *(프로젝트 밖 · allowlist 아님)* |
| 11 | unlinkat | `file-unlink` (medium) | `rm demo/sandbox_test/tmpfile` |
| 12 | fchmodat | `unsafe-chmod` (high) | `chmod 777 demo/sandbox_test/test.sh` *(mode 0777 = world-writable; #5와 동시에 잡힘)* |
| 13 | connect | `outbound-connect` (medium) | `curl -s --max-time 2 http://example.com >/dev/null` *(외부 IP 접속)* |

payload만 잡히고 규칙은 없는 이벤트(정상):

| tracepoint | 트리거 | 확인 |
|---|---|---|
| renameat2 | `mv demo/sandbox_test/tmpfile demo/sandbox_test/renamed` | Recent Events에 `old → new` |
| exit_group | (모든 프로세스 종료 시 자동) | Recent Events / Process Exits 카운트 |

**로컬 vs 외부 대비 (connect 오탐 방지 확인):**

```bash
curl -s --max-time 2 http://127.0.0.1 >/dev/null   # loopback -> outbound-connect 안 뜸
curl -s --max-time 2 http://example.com >/dev/null  # 외부   -> outbound-connect 뜸
```

### 3.3 시퀀스 규칙 — possible-secret-exfiltration (critical, Python)

`.env` 접근 **후** curl/wget 실행 순서가 있으면 리포트가 CRITICAL로 승격한다. 터미널 2에서 **순서대로**:

```bash
cat demo/sandbox_test/.env >/dev/null      # 1) .env 접근
curl -s --max-time 2 http://example.com >/dev/null   # 2) 외부 전송 도구
```

Stop 후 리포트 → **Commit Safety: UNSAFE**, Alert Details의 "Suspicious Sequences"에 `possible-secret-exfiltration`.

> 이건 C 실시간 알림이 아니라 **Python 리포트 계층**이 세션 전체 순서를 보고 판정한다. curl이 `.env` **앞에** 오면 발화하지 않는다(순서 중요).

### 3.4 터미널 캡처 눈으로 보기 (선택)

수집기는 규칙에 걸린 이벤트를 실행 중 터미널에 즉시 출력한다. 터미널 1에서 예:

```text
  [high] env-file-access — .env file accessed: .../demo/sandbox_test/.env by cat (pid ...)
  [medium] outbound-connect — Outbound connection attempt to 93.184.216.34:80 by curl (pid ...)
```

---

## 4. GUI 테스트 (safety 미리보기 · B-007)

```bash
cd "$SG"
sudo -E python3 app/main.py      # 라이브 eBPF는 root 필요; fake만 쓸 땐 sudo 불필요
```

1. **Project Path** = 저장소 경로, **Target Process** = `bash`(또는 `claude`)
2. fake만 볼 거면 **"Use fake collector"** 체크, 실제면 해제
3. **▶ Start Monitoring** → 터미널에서 위 트리거 실행 → **■ Stop**
4. **🔄 Refresh** → 세션 목록의 각 행에 **`[SAFE]/[REVIEW_NEEDED]/[UNSAFE]/[UNKNOWN]`** 미리보기 + 배지 색(녹/주황/빨강/회색)이 붙는지 확인 ← B-007 핵심
5. 세션 선택 → **📄 Open Report** → 브라우저에 상세 리포트

- [ ] 목록 각 행에 verdict 미리보기와 색이 보인다
- [ ] Open Report가 올바른 세션의 리포트를 연다

> 미리보기는 빠른 event 기반 판정이라 git 휴리스틱을 뺀다. **Open Report가 authoritative** (git status/diff 반영). 그래서 미리보기 `SAFE` ↔ 리포트 `REVIEW_NEEDED`가 다를 수 있음(정상).

---

## 5. 데모 스크립트 (한 번에 재현)

수집기 실행(3.1) 상태에서 터미널 2:

```bash
cd "$SG"
bash demo/agent_normal_simulator.sh            # 기대: SAFE / REVIEW_NEEDED
bash demo/agent_boundary_violation_simulator.sh # 기대: UNSAFE (.env, chmod 777, rm -rf 등)
```

각각 별도 세션으로 나눠 캡처하려면 스크립트 사이에 Stop/Start 하거나 `--session-id`를 다르게 준다.

---

## 6. 실제 AI Agent 감시 (본래 목적)

```bash
# 터미널 1
sudo ./build/sysguard --agent-mode --target-comm claude \
  --project-path "$SG" --output logs/session_claude.jsonl
# 터미널 2 (기존 셸)
cd "$SG" && claude    # 예: "README.md 요약해줘"
```

Stop → 리포트. Claude가 실행한 명령(execve)·연 파일(openat)·프로젝트 밖 접근·네트워크 연결이 요약된다. Git이 못 보는 로컬 행위가 syscall 증거로 보이는지 확인한다.

---

## 7. 트러블슈팅

| 증상 | 원인 / 해결 |
|---|---|
| fake 없이 Start했는데 즉시 종료(0-byte) | root 필요 → `sudo ./build/sysguard ...` 또는 `sudo -E python3 app/main.py` |
| 이벤트 0건 | Target 이름 오타, 또는 대상 프로세스를 **시작 전에** 띄워둠(시작 후 실행해야 서브트리에 등록됨) |
| SAFE여야 하는데 boundary 위반이 뜸 | 감시 중 **새 터미널**을 열어 `.bashrc` 등이 잡힘 → 기존 셸 사용 |
| skeleton/verifier 로드 실패 | BTF 미지원 커널이거나 `bpftool`/`libbpf-dev` 누락 → 1장 재확인, `bpf/vmlinux.h` 재생성: `make vmlinux` |
| sudo GUI에서 브라우저 안 열림 | 일반 사용자로 `xdg-open logs/<세션>.html` |
| 로그 소유권이 root | `sudo chown $USER logs/*` |
| 켜둔 걸 잊음 | `pgrep sysguard` 로 확인 후 종료 |

정리:

```bash
rm -rf demo/sandbox_test        # 테스트 샌드박스 제거
# logs/ 는 .gitignore 대상이라 커밋에 안 섞임
```

---

## 8. 성공 기준 체크리스트

```text
Part A
  [ ] python -m unittest ... -> OK (실패 0건)
  [ ] fake 세션에서 7개 event 타입 + 12개 C 규칙 발화, 리포트 UNSAFE, §9 섹션 순서

Part B (sudo, 타깃 VM)
  [ ] 13개 규칙 각각 트리거로 발화 (표 3.2)
  [ ] renameat2/exit_group 이벤트가 Recent Events에 기록
  [ ] loopback은 outbound-connect 미발화 / 외부는 발화
  [ ] .env→curl 순서로 possible-secret-exfiltration(critical)
  [ ] 정상 demo -> SAFE, 위험 demo -> UNSAFE
  [ ] GUI 목록에 세션별 safety 미리보기 + 색
  [ ] 실제 Claude Code 세션이 리포트로 요약됨
```

Part A는 개발 환경에서 자동 검증 완료. **Part B(라이브 eBPF)는 sudo가 필요해 직접 확인해야 하는 마지막 검증**이다.
