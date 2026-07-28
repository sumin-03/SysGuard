# SysGuard

**eBPF 기반 AI 에이전트 감시 및 Commit Safety 분석 도구**

SysGuard는 Linux kernel의 syscall event를 eBPF로 수집하고, Claude Code, Codex CLI, Gemini CLI 같은 AI coding agent의 작업을 user space에서 분석하는 경량 보안 모니터링 도구다.

Git이 저장소 내부의 변경 사항을 추적한다면, SysGuard는 Git이 기록하지 못하는 다음 행위를 가시화한다.

- project boundary 외부 파일 접근
- `.env`, `~/.ssh`, `/etc/shadow` 등 protected path 접근
- `rm -rf`, `git reset --hard`, `chmod 777` 등 dangerous command 실행
- 민감 파일 접근 후 `curl`/`wget` 등 외부 전송 도구를 실행하는 suspicious sequence
- AI agent와 그 child process가 수행한 syscall evidence

분석 결과는 세션 단위 HTML **Commit Safety Report**로 생성되며, 최종 상태를 `SAFE`, `REVIEW_NEEDED`, `UNSAFE` 중 하나로 판정한다.

> SysGuard는 AI agent의 행위를 차단하는 sandbox가 아니다. 현재 구현은 **수집, 필터링, 분석, 판정, 권고**에 집중한다.

---

## 핵심 질문

```text
이 AI agent 세션의 결과물을 commit해도 안전한가?
AI agent가 허용된 project boundary를 벗어났는가?
Git이 추적하지 못하는 local security risk가 있었는가?
```

---

## 주요 기능

### 1. eBPF syscall 수집

다음 7개 syscall tracepoint를 수집한다.

| Event | Tracepoint | 수집 정보 |
|---|---|---|
| Process execution | `sys_enter_execve` | executable path, argv |
| File open | `sys_enter_openat` | path, flags |
| File deletion | `sys_enter_unlinkat` | target path |
| File rename | `sys_enter_renameat2` | old path, new path |
| Permission change | `sys_enter_fchmodat` | path, mode |
| Network connection | `sys_enter_connect` | destination address |
| Process exit | `sys_enter_exit_group` | process context |

공통으로 다음 정보를 기록한다.

```text
timestamp_ns, pid, ppid, uid, comm
```

구현 특성:

- syscall `kprobe` 대신 ABI가 비교적 안정적인 tracepoint 사용
- BTF 기반 CO-RE 구조
- `bpftool gen skeleton`로 libbpf skeleton 생성
- 256 KB BPF ring buffer로 kernel-to-user event 전달
- kernel space에서는 event 수집만 수행하고 정책 판단은 user space에서 처리

### 2. BPF verifier-safe argv 수집

`execve`의 `argv`는 가변 길이 문자열 배열이므로 verifier가 memory access bound를 정적으로 증명할 수 있어야 한다.

SysGuard는 다음 고정 크기 전략을 사용한다.

```text
최대 argument 수: 7
argument당 최대 크기: 32 bytes
총 사용 크기: 7 x 32 = 224 bytes
argv buffer: 256 bytes
```

상수 크기의 unrolled loop를 사용하여 verifier를 통과하면서도 `rm -rf`, `git reset --hard` 같은 명령 패턴을 판별할 수 있는 정보를 확보한다.

### 3. Target process subtree filtering

`--target-comm` 또는 `--target-pid`로 지정한 process와 그 descendants만 세션에 포함한다.

```text
claude
└── bash
    └── git
```

- target process의 `execve`를 관측하면 root PID로 등록
- 추적 중인 PID를 `ppid`로 가진 process를 동적으로 추적 집합에 추가
- AI agent가 실행한 shell, compiler, test runner, Git command를 하나의 session으로 묶음

### 4. Path normalization

`openat` 등의 상대 경로는 `/proc/<pid>/cwd`를 `readlink()`로 조회해 절대 경로로 변환한다.

Python 정책 계층에서는 추가로 `os.path.realpath()`를 적용하여 다음 우회 가능성을 줄인다.

- `../` 기반 boundary traversal
- symbolic link를 통한 project boundary 우회

### 5. 실시간 Rule Engine

C engine은 event 단위로 13개 rule을 평가한다. 탐지된 event는 terminal에 즉시 출력되고 JSONL에 alert metadata와 함께 기록된다.

| Rule ID | 기준 | Severity | 설명 |
|---|---|---:|---|
| `outside-project-write` | mutation-capable `openat` | high | project path 밖 파일에 대한 write/create/truncate/append 시도 |
| `env-file-access` | `openat` | high | `.env` 계열 파일 접근 |
| `ssh-key-access` | `openat` | critical | SSH key/config 접근 |
| `shadow-access` | `openat` | critical | `/etc/shadow` 접근 |
| `sudoers-access` | `openat` | high | `/etc/sudoers` 접근 |
| `destructive-rm` | `execve` | high | `rm -rf` 실행 |
| `git-reset-hard` | `execve` | high | `git reset --hard` 실행 |
| `git-clean-force` | `execve` | high | `git clean -fd` 실행 |
| `unsafe-chmod` | `execve`, `fchmodat` | medium/high | `chmod 777` 등 위험 권한 변경 |
| `downloader-exec` | `execve` | medium | `curl`, `wget` 등 외부 전송 도구 실행 |
| `file-unlink` | `unlinkat` | medium | 실제 파일 삭제 발생 |
| `outbound-connect` | `connect` | medium | 외부 network 연결 시도 |
| `possible-secret-exfiltration` | sequence | critical | `.env` 접근 후 외부 전송 도구 실행 |

> AI agent와 그 도구체인(node, npm, git, …)은 자기 런타임·설정·캐시·인증서·node_modules 등 project 밖 파일을 **정상적으로 읽는다.** 따라서 "위치(project 밖)"만으로는 위험 신호가 되지 못한다. SysGuard는 먼저 protected(민감) path를 분류한 뒤 **읽기와 쓰기를 구분**한다. project 밖 **비민감 읽기는 위반이 아니라 정보성 증거**로 요약되고, project 밖 **write/create만** `outside-project-write` 위반으로 잡는다. protected path 접근은 read/write와 무관하게 위반이다. (system path allowlist는 이제 주요 보안 경계가 아니라 표시·소음 최적화용으로만 유지한다.)

실시간 경고 예시:

```text
[HIGH] env-file-access - Sensitive file accessed: demo/sandbox_risky/.env by cat
[HIGH] destructive-rm - Dangerous command executed: rm -rf demo/sandbox_risky/build
[CRITICAL] possible-secret-exfiltration - .env read followed by curl execution
```

### 6. Python Policy Engine

JSONL event를 다음 네 범주로 분류한다.

- outside-project write (+ 정보성 outside read)
- protected path access
- dangerous command
- suspicious sequence

기본 protected path:

```text
.env
.env.local
.env.production
config/secrets.json
~/.ssh/
~/.aws/credentials
/etc/shadow
/etc/sudoers
```

런타임 프로세스는 repository 밖의 코드·설정·캐시·인증서 저장소·plugin·language toolchain 파일을 정상적으로 읽는다. 따라서 경로 위치만으로는 위험 신호가 되지 못한다. SysGuard는 먼저 protected path를 분류한 뒤, 읽기 전용 open과 mutation(write/create/truncate/append) open을 구분한다.

- project 밖 **비민감 읽기**: 정보성(위반 아님). 리포트에 건수와 소량의 sample path만 요약한다.
- project 밖 **write/create**: `outside-project-write` (검토 대상). 런타임 디렉터리(plugin/cache 등)로의 쓰기도 persistence·변조 위험이 있어 면제하지 않는다.
- protected path 접근: read/write 무관하게 위반.
- flags가 없는 legacy record: operation unknown으로 별도 집계하며, 읽기로 단정하지 않는다.

system/tool-config path allowlist는 주요 보안 경계가 아니라 표시·소음 최적화용으로만 유지한다.

### 7. Commit Safety 평가

| 판정 | 조건 | 권고 |
|---|---|---|
| `SAFE` | 위반과 위험 명령이 없음. project 밖 **비민감 읽기**나 단독 network 관찰은 허용된다(정보성) | commit 가능 |
| `REVIEW_NEEDED` | `outside-project-write`, sandbox 한정 삭제, 다수 파일 변경, build/config 수정, operation-unknown open 등 검토가 필요한 신호 | Git diff·변경 파일과 project 밖 쓰기 검토 |
| `UNSAFE` | protected path 접근, destructive command, secret exfiltration 의심 중 하나 이상 | commit 보류, credential rotation 및 `git reflog` 확인 |

`.env` 접근이 감지되면 세션은 `UNSAFE`로 승격된다. `.env`의 내용이나 secret value는 JSONL과 HTML report에 저장하지 않고 **접근 사실만** 기록한다.

### 8. Git summary 연동

세션 종료 시 다음 명령 결과를 수집하여 report에 포함한다.

```bash
# Summarize changed files.
git status --short

# Summarize diff size without storing file contents in the report.
git diff --stat
```

각 command는 10초 timeout으로 실행되며, 실패할 경우 안전한 빈 결과로 처리한다.

이를 통해 사용자는 다음 두 정보를 한 화면에서 비교할 수 있다.

```text
Git      : repository 내부에서 무엇이 변경되었는가?
SysGuard : repository 외부에서 어떤 local action이 발생했는가?
```

### 9. HTML Commit Safety Report

Report는 다음 순서로 구성된다.

1. session metadata
2. Commit Safety badge
3. normal development activity
4. outside-project writes (+ 정보성 outside read 요약)
5. protected path access
6. dangerous commands
7. Git status/diff summary
8. alert details
9. recent events
10. recommended actions

판정 badge:

```text
SAFE          -> green
REVIEW_NEEDED -> orange
UNSAFE        -> red
```

모든 사용자 입력과 event value는 HTML escaping을 거쳐 report 자체가 XSS 경로가 되지 않도록 처리한다.

### 10. Tkinter GUI

GUI 구성:

- Project Path 입력
- Target Process 입력
- Start Monitoring
- Stop
- Refresh
- Use fake collector toggle
- session log 목록
- session별 safety 결과 미리보기
- Open Report
- status bar

동작 흐름:

```text
Project Path / Target Process 입력
-> Start Monitoring
-> AI agent 또는 demo script 실행
-> Stop
-> session 선택
-> Open Commit Safety Report
```

Start 시 timestamp 기반 session filename을 만들고 engine을 별도 process group으로 실행한다. GUI는 500 ms 주기로 process 상태를 확인한다.

Stop 시 process group 전체에 `SIGINT`를 전달한다. C engine의 signal handler가 polling loop를 종료하므로 JSONL이 flush/close된 후 정상 종료된다.

GUI를 `sudo`로 실행하는 환경에서도 실제 desktop 사용자의 browser로 report를 열 수 있도록 다음 환경을 복원한다.

- `SUDO_USER`
- user `HOME`
- D-Bus session bus
- `XDG_DATA_DIRS`
- `WAYLAND_DISPLAY`
- `XAUTHORITY`

생성된 log/report의 소유권도 실제 사용자에게 복원한다.

### 11. Fake Collector

`--fake` mode는 root 권한과 eBPF 지원 없이 deterministic event를 생성한다.

Fake event도 real mode와 동일한 다음 component를 통과한다.

```text
Rule Engine -> JSONL Writer -> Python Policy -> HTML Report -> GUI
```

따라서 다음 용도로 사용할 수 있다.

- 분석 계층 병렬 개발
- GUI regression test
- eBPF를 사용할 수 없는 심사/발표 환경에서 시연
- JSONL schema compatibility 검증

---

## Architecture

```text
[Target Process / AI Agent]
  claude, codex, gemini, bash, python, git, ...
                |
                | syscall tracepoints
                v
[Linux Kernel]
  eBPF CO-RE programs
  execve / openat / unlinkat / renameat2
  fchmodat / connect / exit_group
                |
                | 256 KB BPF ring buffer
                v
[C/eBPF SysGuard Engine]
  libbpf skeleton loader
  ring buffer reader (100 ms poll)
  event decoder
  target subtree filter
  rule engine (13 rules)
  CLI alerts
  JSONL evidence writer
                |
                | logs/session_*.jsonl
                v
[Python Analysis Layer]
  boundary/protected path policy
  dangerous command/sequence analysis
  path allowlist + realpath normalization
  Git status/diff summary
  Commit Safety evaluator
  HTML report generator
                |
                v
[Tkinter GUI Wrapper]
  Start / Stop / Refresh
  fake collector toggle
  session list + safety preview
  Open Report
```

핵심 interface contract는 C engine이 출력하는 고정 JSONL schema다. 이 계약으로 eBPF engine과 Python analysis/GUI를 독립적으로 개발하고 테스트할 수 있다.

---

## JSONL Evidence Format

기본 field:

| Field | 설명 | 생성 계층 |
|---|---|---|
| `timestamp_ns` | event 발생 시각 | eBPF |
| `session_id` | session 식별자 | C engine |
| `event` | syscall event type | C engine |
| `pid` | process ID | eBPF |
| `ppid` | parent process ID | eBPF |
| `uid` | user ID | eBPF |
| `comm` | process name | eBPF |
| `argv` | `execve` command line | eBPF |
| `path` | normalized target path | eBPF + C engine |
| `project_path` | project root | CLI/GUI |
| `target_comm` | target process name | CLI/GUI |
| `alert`, `rule_id`, `severity`, `reason`, `recommendation` | rule match 결과 | C rule engine |

예시:

```json
{
  "timestamp_ns": 4399090000000,
  "session_id": "session_20260702_180240",
  "event": "openat",
  "pid": 3000,
  "ppid": 2500,
  "uid": 1000,
  "comm": "claude",
  "argv": "",
  "path": "/home/user/project/.env",
  "project_path": "/home/user/project",
  "target_comm": "claude",
  "alert": true,
  "rule_id": "env-file-access",
  "severity": "high"
}
```

JSON serializer는 다음 문자를 JSON 규격에 맞게 escape한다.

- double quote
- backslash
- newline (`\n`)
- tab (`\t`)
- 기타 control character (`\uXXXX`)

이는 `python3 -c` 형태의 multiline command가 JSONL 한 행을 깨뜨리지 않도록 하기 위한 처리다.

---

## Project Structure

```text
sysguard/
├── bpf/
│   ├── sysguard.bpf.c          # eBPF tracepoint programs
│   └── vmlinux.h               # generated from kernel BTF
├── src/
│   ├── main.c                  # CLI entry point
│   ├── event.h                 # shared event schema
│   ├── alert.h                 # rule result and severity
│   ├── collector.h             # collector interface
│   ├── bpf_collector.c         # libbpf loader and ring buffer reader
│   ├── fake_collector.c        # deterministic fake events
│   ├── rules.c
│   ├── rules.h                 # 13 event/sequence rules
│   ├── jsonl_writer.c
│   └── jsonl_writer.h          # JSONL serialization
├── app/
│   ├── main.py                 # Tkinter GUI wrapper
│   ├── report.py               # JSONL to HTML report
│   ├── policy.py               # path/command/sequence policy
│   ├── git_summary.py          # git status/diff collector
│   └── session_analyzer.py     # session-level analysis
├── demo/
│   ├── agent_normal_simulator.sh
│   ├── agent_boundary_violation_simulator.sh
│   ├── sandbox_normal/
│   └── sandbox_risky/
├── logs/
│   ├── session_*.jsonl
│   └── session_*.html
├── reports/
│   └── sample_report.html
├── build/
├── docs/
├── Makefile
└── README.md
```

---

## Requirements

검증 환경:

| 구분 | 환경 |
|---|---|
| OS | Ubuntu 24.04 LTS |
| Kernel | Linux 6.17, BTF enabled |
| Virtualization | VirtualBox VM |
| Kernel layer | C, eBPF CO-RE, libbpf, bpftool, BPF ring buffer |
| Engine | C, clang, Makefile, JSONL |
| Analysis/GUI | Python 3.12, Tkinter, HTML |

필수 package 설치:

```bash
# Install build tools, libbpf, bpftool, and Tkinter.
sudo apt update
sudo apt install -y \
  clang \
  llvm \
  make \
  gcc \
  libbpf-dev \
  libelf-dev \
  zlib1g-dev \
  bpftool \
  linux-tools-common \
  python3 \
  python3-tk
```

BTF 확인:

```bash
# CO-RE build requires BTF data from the running kernel.
ls -l /sys/kernel/btf/vmlinux
```

`vmlinux.h`를 수동 생성해야 하는 build 구성이라면 다음 명령을 사용한다.

```bash
# Generate kernel type definitions from BTF.
mkdir -p bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

> Distribution에 따라 `bpftool` package 이름이 다를 수 있다. `/sys/kernel/btf/vmlinux`가 없으면 현재 kernel의 BTF 지원 여부를 먼저 확인해야 한다.

---

## Build

```bash
# Build the eBPF object, skeleton header, and user-space engine.
make
```

생성 결과:

```text
build/sysguard.bpf.o
build/sysguard.skel.h
build/sysguard
```

Clean build:

```bash
# Remove generated build artifacts.
make clean

# Rebuild all components.
make
```

---

## Run

### GUI mode

```bash
# eBPF loading requires elevated privileges in the current MVP.
sudo python3 app/main.py
```

GUI에서 다음 값을 지정한다.

```text
Project Path   : repository root
Target Process : claude, codex, gemini, ...
Use fake collector : eBPF 없이 시연할 때 활성화
```

### Fake mode

```bash
# Generate deterministic events without root or eBPF.
mkdir -p logs
./build/sysguard \
  --fake \
  --agent-mode \
  --target-comm claude \
  --project-path "$(pwd)" \
  --output logs/session_fake.jsonl
```

### Real eBPF mode

```bash
# Monitor system events and write normalized JSONL evidence.
mkdir -p logs
sudo ./build/sysguard \
  --agent-mode \
  --target-comm claude \
  --project-path "$(pwd)" \
  --output logs/session_claude.jsonl
```

특정 PID 기준:

```bash
# Restrict the session to one PID and its descendants.
sudo ./build/sysguard \
  --agent-mode \
  --target-pid 12345 \
  --project-path "$(pwd)" \
  --output logs/session_pid_12345.jsonl
```

종료:

```text
Ctrl-C 또는 GUI Stop
-> SIGINT 전달
-> ring buffer polling loop 종료
-> JSONL flush/close
```

### Report 생성

```bash
# Convert one JSONL session into an HTML Commit Safety Report.
python3 app/report.py \
  --input logs/session_claude.jsonl \
  --agent claude \
  --project-path "$(pwd)" \
  --output logs/session_claude.html
```

```bash
# Open the generated report in the default browser.
xdg-open logs/session_claude.html
```

---

## CLI Options

| Option | 설명 |
|---|---|
| `--output <path>` | JSONL session log 경로, 필수 |
| `--fake` | eBPF 없이 deterministic event 생성 |
| `--agent-mode` | AI agent monitoring session 표시 |
| `--target-comm <name>` | process name과 descendants만 추적 |
| `--target-pid <pid>` | PID와 descendants만 추적 |
| `--project-path <dir>` | project boundary root |
| `--session-id <id>` | session ID, 생략 시 output filename에서 유도 |

---

## Demo

데모는 실제 credential이나 system file을 사용하지 않는다. 모든 위험 행위는 project 내부 sandbox에서 재현한다.

### Normal development scenario

```bash
# Run a harmless project-local development workload.
bash demo/agent_normal_simulator.sh
```

수행 예시:

- project 내부 파일 읽기/수정
- `git status`
- `make --version`
- Python 실행

예상 결과:

```text
Commit Safety: SAFE
Boundary Violations: 0
Protected Path Access: 0
```

### Risky scenario

```bash
# Run controlled risky patterns only inside demo/sandbox_risky.
bash demo/agent_boundary_violation_simulator.sh
```

수행 예시:

- fake `.env` 읽기
- sandbox file에 `chmod 777`
- sandbox build directory에 `rm -rf`
- `git reset --hard` command pattern 재현

예상 결과:

```text
Commit Safety: UNSAFE
Detected: env-file-access, unsafe-chmod, destructive-rm, git-reset-hard
```

### Demo safety constraints

금지:

```text
실제 API key/SSH key 읽기
/etc/shadow 등 실제 protected system file 접근
외부 server로 data 전송
권한 상승
persistence 설치
사용자 file 삭제/암호화
실제 repository에 git reset --hard 실행
```

허용:

```text
project-local fake .env
project-local sandbox chmod/rm
version/status command
echo 기반 dangerous command pattern 재현
```

---

## Validation Results

| Scenario | 구성 | 기대 결과 | 검증 결과 |
|---|---|---|---|
| GUI 기본 흐름 | fake collector `Start -> Stop -> Report` | `UNSAFE` mock report | 통과 |
| 정상 개발 활동 | real eBPF + normal simulator, 127 events | `SAFE`, violation 0 | 통과 |
| 위험 행위 | real eBPF + risky simulator, 40 events | `UNSAFE` | 통과: `.env` 2건, `chmod 777`, `rm -rf`, `git reset --hard` 탐지 |
| 실제 AI agent | real eBPF + Claude Code, 4,548 events | 전체 활동 기록 | 통과: `~/.bashrc` **읽기**는 정보성 outside-read로 요약(위반 아님), 밖으로의 write/create만 `outside-project-write`로 판정 |

실제 Claude Code session에서도 project 외부 설정, 인증 관련 file, TLS certificate 등 다양한 local resource access가 관측되었다. 이 결과는 Git만으로 확인할 수 없는 agent의 local behavior를 syscall evidence로 가시화할 수 있음을 보여준다.

---

## strace / auditd와의 차이

| 항목 | strace | auditd | SysGuard |
|---|---|---|---|
| 주 목적 | syscall debugging | system-wide auditing | AI agent session safety review |
| 출력 | raw syscall log | audit record | session summary + Commit Safety Report |
| target process subtree | `-f` 기반 trace | rule 구성 필요 | AI agent와 descendants를 session으로 자동 그룹화 |
| project boundary 판단 | 없음 | 수동 rule 필요 | 내장 policy |
| protected path policy | 없음 | watch rule 필요 | `.env`, `.ssh`, credential path 중심 기본 정책 |
| dangerous command 해석 | 없음 | 별도 분석 필요 | 13개 rule과 sequence 분석 |
| Git summary | 없음 | 없음 | `git status`/`diff --stat` 결합 |
| GUI/HTML report | 없음 | 없음 | 제공 |

SysGuard는 strace나 auditd를 대체하지 않는다. 두 도구가 low-level evidence collection에 강점이 있다면, SysGuard는 이를 **AI agent development workflow의 commit safety 관점으로 해석하는 계층**에 초점을 둔다.

---

## Security and Privacy Principles

- secret content를 log/report에 저장하지 않는다.
- protected file은 접근 사실과 metadata만 기록한다.
- HTML output은 escaping 처리한다.
- demo는 project-local dummy data만 사용한다.
- current version은 blocking보다 explainable detection을 우선한다.
- destructive behavior는 자동 rollback하지 않고 사람이 검토할 수 있는 evidence와 권고를 제공한다.

---

## Known Limitations

- target filtering이 user space에서 수행되므로 system-wide event가 우선 ring buffer를 통과한다.
- current GUI와 privileged eBPF engine이 완전히 분리된 service architecture는 아니다.
- detection 중심이며 protected path access를 사전에 차단하지 않는다.
- policy가 Python constant 기반이라 외부 configuration으로 교체하려면 code 수정이 필요하다.
- network monitoring은 connection metadata 중심이며 packet payload를 분석하지 않는다.
- process tree는 event stream에 의존하므로 collector 시작 전에 이미 생성된 일부 ancestor 관계는 제한적으로 보일 수 있다.

---

## Future Work

- BPF map 기반 kernel-side PID filtering
- privileged backend와 unprivileged GUI 분리
- eBPF LSM 또는 `fanotify` permission event 기반 blocking mode
- YAML policy configuration
- session 간 통계/위험도 비교
- real-time GUI alert table
- systemd service/package 제공
- network destination enrichment
- policy별 allowlist/denylist profile
- optional isolated workspace 또는 Git worktree integration

---

## Team

- 김수민: eBPF collector, C engine, JSONL evidence pipeline
- 이현창: Python policy, Git summary, HTML report, Tkinter GUI
