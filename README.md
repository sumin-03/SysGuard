# SysGuard

**eBPF/libbpf 기반 Linux Process-Specific Syscall Monitoring + AI Agent Session Profiling + GUI Report Viewer**

SysGuard는 Linux kernel의 주요 syscall event를 eBPF로 수집하고, user-space engine에서 특정 process와 child process의 활동을 session 단위로 분석하는 경량 runtime security monitor이다.

기존 SysGuard의 핵심은 `execve`, `openat` syscall event를 수집해 의심 명령 실행과 민감 파일 접근을 탐지하는 것이다. 확장된 SysGuard는 여기서 한 단계 더 나아가 Codex, Claude Code, Gemini CLI 같은 AI 개발 에이전트가 로컬 시스템에서 어떤 명령을 실행하고 어떤 파일에 접근했는지를 session report로 요약한다.

중요한 설계 원칙은 다음과 같다.

```text
eBPF는 시스템 전체에서 발생하는 주요 syscall event를 가볍게 수집한다.
User-space engine은 target process와 child process에 해당하는 event만 필터링한다.
Session analyzer는 필터링된 event를 시간 순서와 process tree 기준으로 묶어 report를 생성한다.
```

공모전 시연에서는 사용자가 직접 조작할 수 있는 GUI를 제공한다. GUI에서 monitoring을 Start/Stop하고, 수집된 log session 목록을 확인하며, 선택한 log를 HTML report로 열람할 수 있다.

---

## 1. 완성품 형태

SysGuard는 내부적으로 세 부분으로 나뉜다.

```text
SysGuard Monitor App
├── Python GUI wrapper
│   ├── Start Monitoring button
│   ├── Stop button
│   ├── Refresh Logs button
│   ├── Log session list
│   ├── Open HTML Report button
│   └── Agent Session Summary view
│
├── User-space analysis layer
│   ├── JSONL event reader
│   ├── target process filter
│   ├── process tree tracker
│   ├── AI agent session analyzer
│   ├── risk score calculator
│   └── HTML report generator
│
└── C/eBPF monitoring engine
    ├── eBPF syscall collector
    ├── libbpf loader
    ├── ring buffer reader
    ├── event decoder
    ├── rule engine
    ├── CLI alert output
    └── JSONL log writer
```

핵심 원칙은 다음과 같다.

```text
GUI는 eBPF를 직접 다루지 않는다.
GUI는 C/eBPF engine을 실행/종료하고, 생성된 JSONL log를 HTML report로 보여준다.
AI agent profiling은 kernel space가 아니라 user-space 분석 계층에서 수행한다.
```

---

## 2. 프로젝트 목표

### 핵심 목표

- Linux process execution event 수집
- Linux file access event 수집
- 특정 process의 syscall activity 모니터링
- target process와 child process의 event filtering
- AI agent session profiling
- 의심 명령 실행 탐지
- 민감 파일 접근 탐지
- AI agent의 민감 파일 접근 탐지
- CLI alert 출력
- JSONL session log 생성
- GUI 기반 Start/Stop 제어
- GUI 기반 log session 목록 조회
- 선택한 log를 HTML report로 변환 및 표시
- harmless demo script 기반 재현 가능한 시연

### MVP 범위

| 구분 | 내용 |
|---|---|
| 필수 감시 syscall | `execve`, `openat` |
| optional 감시 syscall | `unlinkat`, `renameat`, `fchmodat`, `connect`, `exit_group` |
| 수집 방식 | eBPF tracepoint |
| engine | C + libbpf |
| GUI | Python wrapper app |
| event 전달 | BPF ring buffer |
| process filtering | user-space PID/PPID 기반 filtering |
| target mode | `--target-pid`, `--target-comm`, `--agent-mode` |
| 탐지 방식 | built-in rule 기반 |
| session 분석 | Python `session_analyzer.py` |
| log format | JSONL |
| report | HTML |
| 시연 | harmless command 기반 demo script |

---

## 3. 하지 않는 것

5주 MVP에서는 아래 기능을 제외한다.

| 제외 기능 | 제외 이유 |
|---|---|
| kernel-side target PID filtering | BPF map 기반 filtering과 child tracking 부담 증가 |
| 실시간 차단 기능 | LSM eBPF, seccomp, fanotify permission event 등 별도 설계 필요 |
| 모든 syscall 감시 | event 폭증 및 false positive 증가 |
| `write` 기반 정확한 파일 수정 추적 | fd-to-path mapping이 필요해 MVP 범위를 초과 |
| packet payload 분석 | 보안/개인정보/구현 부담 증가 |
| 실시간 Web dashboard | GUI와 engine 동기화 부담 증가 |
| C 기반 GUI | GTK/Qt C API 학습 부담 증가 |
| YAML rule parser | C에서 parser 구현 부담 증가 |
| SQLite 저장 | JSONL로 충분 |
| ML anomaly detection | 데이터셋 부족, 설명 가능성 낮음 |

주의할 점:

```text
MVP는 AI agent를 차단하지 않는다.
MVP는 AI agent의 행위를 수집, 필터링, 요약, 위험도 평가, report 생성까지만 수행한다.
```

---

## 4. 전체 아키텍처

```text
[Target Process / AI Agent]
  claude, codex, gemini, cursor, code, bash, python, git, etc.
        |
        | execve(), openat(), optional syscalls
        v
[Linux Kernel]
  eBPF programs attached to syscall tracepoints
        |
        | BPF ring buffer
        v
[C/eBPF SysGuard Engine]
  libbpf loader
  ring buffer reader
  event decoder
  rule engine
  alert manager
  CLI output
  JSONL output
        |
        | logs/session_*.jsonl
        v
[Python Analysis Layer]
  target process filter
  process tree tracker
  AI agent session analyzer
  risk score calculator
  JSONL -> HTML report
        |
        v
[Python GUI Wrapper]
  Start / Stop
  Log session list
  Open Agent Session Report
```

설계상 eBPF program은 특정 AI agent를 직접 판단하지 않는다. eBPF는 syscall event를 수집하고, user-space에서 `pid`, `ppid`, `comm`, `exe_path`, `argv`, `path`를 이용해 target process 여부를 판단한다.

---

## 5. 기술 스택

| 영역 | 기술 |
|---|---|
| eBPF program | C |
| user-space monitoring engine | C |
| eBPF loader | libbpf |
| skeleton 생성 | bpftool gen skeleton |
| compiler | clang |
| build | Makefile |
| engine output | CLI, JSONL |
| session analyzer | Python |
| GUI app | Python |
| GUI toolkit | Tkinter 또는 PySide6 |
| report | HTML |
| demo | Bash script |

MVP에서는 **Tkinter + 외부 browser HTML report** 구성을 우선한다. Tkinter는 Python 기본 GUI라 설치 부담이 낮고, HTML report는 브라우저에서 열면 되므로 GUI 구현량을 줄일 수 있다.

---

## 6. 역할 분담

### 담당자 A: eBPF / Collector / Engine

**역할:** 커널에서 syscall event를 수집해 C engine으로 전달한다.

주요 작업:

- `bpf/sysguard.bpf.c` 작성
- `execve` tracepoint attach
- `openat` tracepoint attach
- BPF ring buffer로 event 전달
- `timestamp_ns`, `pid`, `ppid`, `uid`, `comm` 수집
- `execve`에서 `exe_path`, `argv` 수집
- `openat`에서 `path`, `flags` 수집
- `bpftool gen skeleton` 기반 build 구성
- `src/bpf_collector.c`에서 ring buffer event 수신
- real eBPF mode 안정화
- 시간이 남으면 optional syscall 1~2개 추가

완료 기준:

```text
sudo ./build/sysguard --output logs/session_test.jsonl
실행 후 bash, curl, git, python, cat /etc/passwd 같은 실제 행위가 event 또는 alert로 출력된다.
```

A의 핵심 책임은 session 분석이 아니라 **분석 가능한 event를 정확히 넘겨주는 것**이다.

### 담당자 B: Rule Engine / Session Analyzer / Report / GUI

**역할:** 수집된 event를 보안적으로 해석하고, 특정 process의 session activity로 요약해 사용자에게 보여준다.

주요 작업:

- `src/event.h` 작성
- `src/alert.h` 작성
- `src/fake_collector.c` 작성
- `src/rules.c` 작성
- CLI alert 출력
- JSONL writer 구현
- `app/session_analyzer.py` 작성
- `app/report.py` JSONL to HTML report 구현
- `app/main.py` GUI 작성
- AI agent demo script 작성
- README 및 발표용 sample report 정리

완료 기준:

```text
./build/sysguard --fake --output logs/session_fake.jsonl
실행 후 fake event 기반 alert가 출력되고,
GUI에서 해당 log를 선택해 AI Agent Session Report로 볼 수 있다.
```

---

## 7. 디렉터리 구조

```text
sysguard/
├── src/
│   ├── main.c                 # CLI entry point
│   ├── event.h                # shared event struct
│   ├── alert.h                # alert struct and severity
│   ├── collector.h            # collector-related declarations
│   ├── fake_collector.c       # fake event generator
│   ├── bpf_collector.c        # libbpf skeleton loader + ringbuf reader
│   ├── rules.c                # rule matching logic
│   ├── rules.h
│   ├── jsonl_writer.c         # JSONL output writer
│   └── jsonl_writer.h
├── bpf/
│   ├── sysguard.bpf.c         # eBPF program
│   └── vmlinux.h              # kernel type definitions
├── app/
│   ├── main.py                # GUI wrapper app
│   ├── session_analyzer.py    # target process and AI agent session analysis
│   ├── risk_score.py          # session-level risk score calculation
│   ├── report.py              # JSONL to HTML report generator
│   └── README.md              # GUI usage note
├── logs/
│   ├── session_*.jsonl        # monitoring session logs
│   └── session_*.html         # generated reports
├── build/
│   └── generated files and sysguard binary
├── demo/
│   ├── benign_simulator.sh
│   └── ai_agent_simulator.sh
├── reports/
│   ├── sample_alerts.jsonl
│   └── sample_agent_report.html
├── docs/
│   ├── architecture.md
│   ├── rules.md
│   └── agent_session_model.md
├── Makefile
└── README.md
```

---

## 8. Event Interface

`struct sysguard_event`는 eBPF collector와 rule engine 사이의 공통 계약이다.

```c
#ifndef SYSGUARD_EVENT_H
#define SYSGUARD_EVENT_H

#include <stdint.h>

#define TASK_COMM_LEN 16
#define SYSGUARD_MAX_PATH 256
#define SYSGUARD_MAX_ARGV 256

// Event types shared by eBPF and user-space code.
// Keep these values synchronized with bpf/sysguard.bpf.c.
enum sysguard_event_type {
    SYSGUARD_EVENT_EXEC = 1,
    SYSGUARD_EVENT_OPEN = 2,

    // Optional events. Implement only when MVP is stable.
    SYSGUARD_EVENT_UNLINK = 3,
    SYSGUARD_EVENT_RENAME = 4,
    SYSGUARD_EVENT_CHMOD = 5,
    SYSGUARD_EVENT_CONNECT = 6,
    SYSGUARD_EVENT_EXIT = 7,
};

// Normalized event consumed by the rule engine and session analyzer.
struct sysguard_event {
    uint64_t timestamp_ns;
    uint32_t type;

    // Process context.
    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char comm[TASK_COMM_LEN];

    // Exec event fields.
    char exe_path[SYSGUARD_MAX_PATH];
    char argv[SYSGUARD_MAX_ARGV];

    // File event fields.
    char path[SYSGUARD_MAX_PATH];
    char path2[SYSGUARD_MAX_PATH];  // Used by rename-like events.
    int32_t flags;
    uint32_t mode;

    // Network event fields. Optional for MVP.
    uint32_t dst_ip;
    uint16_t dst_port;
};

#endif
```

MVP에서는 `SYSGUARD_EVENT_EXEC`, `SYSGUARD_EVENT_OPEN`만 반드시 구현한다. Optional event field는 interface 확장성을 위해 예약해둔다.

---

## 9. Alert Interface

모든 alert는 `severity`, `reason`, `recommendation`을 포함해야 한다.

```c
#ifndef SYSGUARD_ALERT_H
#define SYSGUARD_ALERT_H

#include <stdint.h>

#define SYSGUARD_MAX_REASON 256
#define SYSGUARD_MAX_RECOMMENDATION 256
#define SYSGUARD_MAX_RULE_ID 64

// Alert severity levels used by the rule engine.
enum sysguard_severity {
    SYSGUARD_SEV_LOW = 1,
    SYSGUARD_SEV_MEDIUM = 2,
    SYSGUARD_SEV_HIGH = 3,
    SYSGUARD_SEV_CRITICAL = 4,
};

// Security alert produced by rule evaluation.
struct sysguard_alert {
    uint64_t timestamp_ns;
    char rule_id[SYSGUARD_MAX_RULE_ID];
    enum sysguard_severity severity;

    uint32_t pid;
    uint32_t ppid;
    uint32_t uid;
    char comm[16];

    char reason[SYSGUARD_MAX_REASON];
    char recommendation[SYSGUARD_MAX_RECOMMENDATION];
};

const char *sysguard_severity_string(enum sysguard_severity severity);

#endif
```

---

## 10. JSONL Log Format

JSONL은 event와 alert를 모두 저장한다. session analyzer는 이 파일을 읽어 target process report를 만든다.

Event line 예시:

```json
{"record_type":"event","timestamp_ns":123456789,"event":"exec","pid":3101,"ppid":3000,"uid":1000,"comm":"git","exe_path":"/usr/bin/git","argv":"git status"}
```

Alert line 예시:

```json
{"record_type":"alert","timestamp_ns":123456999,"rule_id":"env-file-access","severity":"high","pid":3102,"ppid":3000,"comm":"cat","reason":".env file was accessed","recommendation":"Review whether secrets were exposed."}
```

---

## 11. Target Process / AI Agent Session Model

SysGuard의 process-specific monitoring은 kernel-space attach 대상 자체를 특정 process로 제한하는 방식이 아니다.

```text
시스템 전체 syscall event 수집
→ user-space에서 target process 식별
→ target process와 child process event만 filtering
→ session 단위로 activity report 생성
```

### Target process 지정 방식

```bash
# Monitor events related to a specific PID and its child processes.
sudo ./build/sysguard --target-pid 3000 --output logs/session_target.jsonl

# Monitor events related to processes whose command name matches claude.
sudo ./build/sysguard --target-comm claude --output logs/session_claude.jsonl

# Enable built-in AI agent process detection.
sudo ./build/sysguard --agent-mode --output logs/session_agent.jsonl
```

MVP에서는 CLI option이 완전히 동작하지 않더라도, JSONL 생성 후 `session_analyzer.py`에서 같은 filtering을 수행해도 된다.

### AI agent process 후보

```text
claude
codex
gemini
cursor
code
node
python
bash
```

`node`, `python`, `bash`는 너무 일반적이므로 단독으로 AI agent로 확정하지 않는다. 다음 조건을 같이 본다.

```text
argv에 claude, codex, gemini, cursor 관련 문자열 포함
parent process가 claude/codex/gemini/cursor/code 계열
프로젝트 디렉터리에서 짧은 시간 안에 다수 file open/exec event 발생
```

### Process tree tracking

```text
AI Agent PID 3000
├── git PID 3010
├── python PID 3011
├── bash PID 3012
└── cat PID 3013
```

Session analyzer는 다음 규칙으로 event를 session에 포함한다.

```text
event.pid == target_pid
또는 event.ppid == target_pid
또는 event.ppid가 이미 session에 포함된 child pid
```

---

## 12. 이상행위 기준

SysGuard에서 이상행위는 악성행위의 확정 판정이 아니다.

본 프로젝트에서는 이상행위를 다음과 같이 정의한다.

> Linux 환경에서 침해 사고, 권한 상승, 정보 탈취, 컨테이너 오남용, AI agent의 과도한 로컬 권한 사용과 연관될 가능성이 높은 syscall event 또는 event sequence

### 기준 1: 민감 자원 접근

```text
/etc/shadow
/etc/sudoers
/var/run/docker.sock
/home/*/.ssh/id_rsa
/home/*/.ssh/config
.env
.env.local
.env.production
config/secrets.*
```

### 기준 2: 위험 command 실행

```text
bash, sh, zsh
nc, netcat, ncat
curl, wget
python, perl, ruby
git reset --hard
rm -rf
chmod 777
chown root
```

### 기준 3: 정책 위반

```text
일반 사용자 프로세스가 /etc/shadow 접근
non-allowlisted process가 Docker socket 접근
학생 실습 VM에서 netcat 실행
AI agent session에서 .env 또는 SSH private key 접근
AI agent session에서 destructive command 실행
```

### 기준 4: event sequence

MVP에서는 optional이다.

```text
curl 실행 → shell 실행
shell 실행 → 민감 파일 접근
AI agent 실행 → .env 접근 → 외부 연결
AI agent 실행 → 다수 파일 접근 → rm/chmod 실행
```

---

## 13. MVP Rule 목록

| Rule ID | Event | Severity | 설명 |
|---|---|---|---|
| `shell-exec` | `execve` | medium | shell process 실행 |
| `suspicious-netcat` | `execve` | high | netcat 계열 command 실행 |
| `downloader-exec` | `execve` | medium | `curl`, `wget` 실행 |
| `sensitive-shadow-access` | `openat` | critical | `/etc/shadow` 접근 |
| `sudoers-access` | `openat` | high | `/etc/sudoers` 접근 |
| `docker-sock-access` | `openat` | high | Docker socket 접근 |
| `ssh-key-access` | `openat` | high | SSH private key 접근 |
| `env-file-access` | `openat` | high | `.env` 계열 파일 접근 |
| `agent-sensitive-access` | sequence | high | AI agent session 중 민감 파일 접근 |
| `agent-dangerous-command` | sequence | high | AI agent session 중 위험 명령 실행 |

Optional rule:

| Rule ID | Event | Severity | 설명 |
|---|---|---|---|
| `download-and-shell` | sequence | high | downloader 실행 후 shell 실행 |
| `agent-mass-file-access` | sequence | medium | AI agent session 중 짧은 시간 내 다수 파일 접근 |
| `agent-delete-file` | `unlinkat` | high | AI agent session 중 파일 삭제 |
| `agent-rename-burst` | `renameat` | high | AI agent session 중 다수 파일 이름 변경 |
| `agent-outbound-connect` | `connect` | medium | AI agent session 중 외부 연결 |

---

## 14. Optional Syscall 확장 우선순위

`execve`, `openat`이 안정화된 뒤 시간이 남으면 아래 순서로 추가한다.

| 우선순위 | syscall | 목적 | 난이도 | 추천 여부 |
|---:|---|---|---|---|
| 1 | `unlinkat` / `unlink` | 파일 삭제 탐지 | 낮음~중간 | 가장 추천 |
| 2 | `renameat` / `renameat2` | 파일 rename, ransomware-like rename 탐지 | 중간 | 추천 |
| 3 | `fchmodat` / `chmod` | 권한 변경 탐지, `chmod 777` 탐지 | 중간 | 추천 |
| 4 | `exit_group` | process/session 종료 시점 파악 | 낮음 | report 품질 개선용 |
| 5 | `connect` | outbound network 연결 탐지 | 중간~높음 | 시간 남을 때 |
| 6 | `execveat` | `execve` 변형 대응 | 낮음~중간 | 보완용 |
| 7 | `openat2` | 최신 open 계열 syscall 대응 | 중간 | 보완용 |

### 가장 먼저 추가할 syscall

```text
1순위: unlinkat
2순위: renameat 또는 renameat2
3순위: fchmodat 또는 chmod
```

이 세 개는 AI agent가 로컬 파일을 건드릴 때 발생할 수 있는 문제와 직접 연결된다.

```text
unlinkat  → 파일 삭제
renameat  → 파일 이름 변경 또는 대량 rename
fchmodat  → 파일 권한 변경
```

`connect`도 매력적이지만 IPv4/IPv6 구조체 decoding과 테스트 부담이 있어 5주 MVP에서는 후순위로 둔다.

`write`는 직관적으로 좋아 보이지만 MVP에서는 비추천한다. `write(fd, buf, count)`는 path를 직접 주지 않기 때문에 fd-to-path mapping을 따로 유지해야 한다.

---

## 15. Build Requirements

Ubuntu VM 기준으로 개발한다.

```bash
# Build tools and eBPF-related packages.
sudo apt update
sudo apt install -y \
  clang \
  llvm \
  make \
  gcc \
  libbpf-dev \
  bpftool \
  linux-headers-$(uname -r) \
  python3 \
  python3-tk
```

커널 BTF 확인:

```bash
# vmlinux BTF file is required for CO-RE-based eBPF development.
ls -l /sys/kernel/btf/vmlinux
```

`vmlinux.h` 생성:

```bash
# Generate vmlinux.h from the running kernel's BTF information.
mkdir -p bpf
bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```

---

## 16. Build & Run

```bash
# Build SysGuard engine.
make
```

Fake mode:

```bash
# Run without eBPF.
./build/sysguard --fake --output logs/session_fake.jsonl
```

Real eBPF mode:

```bash
# Run real eBPF collector.
sudo ./build/sysguard --output logs/session_real.jsonl
```

Target process mode:

```bash
# Monitor a specific PID and its child processes.
sudo ./build/sysguard --target-pid 3000 --output logs/session_target.jsonl
```

Agent mode:

```bash
# Monitor AI-agent-like process activity.
sudo ./build/sysguard --agent-mode --output logs/session_agent.jsonl
```

GUI mode:

```bash
# Run GUI wrapper.
sudo python3 app/main.py
```

공모전 demo에서는 eBPF load 권한 문제를 단순화하기 위해 GUI를 `sudo`로 실행한다. 실서비스 수준에서는 GUI와 privileged backend를 분리하는 구조가 필요하다.

---

## 17. GUI 동작 방식

### Start Monitoring

```text
Start button 클릭
→ logs/session_YYYYMMDD_HHMMSS.jsonl 생성
→ ./build/sysguard --agent-mode --output logs/session_YYYYMMDD_HHMMSS.jsonl 실행
→ GUI status를 Running으로 변경
```

### Stop Monitoring

```text
Stop button 클릭
→ sysguard process에 SIGINT 또는 SIGTERM 전달
→ JSONL file close
→ log session 목록 갱신
→ GUI status를 Stopped로 변경
```

### Log Session List

```text
logs/*.jsonl scan
→ file name, modified time, alert count, critical/high count, agent session count 표시
```

### Open HTML Report

```text
선택한 JSONL log 읽기
→ session_analyzer.py로 target/agent session summary 생성
→ HTML report 생성
→ logs/session_YYYYMMDD_HHMMSS.html 저장
→ browser 또는 GUI WebView로 열기
```

---

## 18. GUI 화면 MVP

```text
+------------------------------------------------------------------+
| SysGuard Monitor                                                 |
| eBPF Linux Runtime Security Monitor + AI Agent Profiler          |
+------------------------------------------------------------------+
| [ Start Monitoring ] [ Stop ] [ Refresh Logs ]                   |
| Status: Stopped                                                  |
+------------------------------------------------------------------+
| Log Sessions                                                     |
|------------------------------------------------------------------|
| session_20260624_142100.jsonl | 12 alerts | 2 crit | 1 agent   |
| session_20260624_143500.jsonl |  8 alerts | 1 crit | 0 agent   |
| session_20260624_151000.jsonl | 15 alerts | 3 crit | 2 agents  |
+------------------------------------------------------------------+
| [ Open HTML Report ]                                             |
+------------------------------------------------------------------+
```

---

## 19. HTML Report 구성

HTML report는 선택한 JSONL session을 사람이 보기 쉽게 요약한다.

포함 항목:

```text
1. Session file name
2. Total event count
3. Total alert count
4. Severity summary
5. Rule별 발생 횟수
6. Target process summary
7. AI agent session summary
8. Files accessed
9. Commands executed
10. Sensitive files accessed
11. Dangerous commands
12. Risk score
13. Recommendation
14. Recent alert table
```

예시:

```text
SysGuard Agent Session Report

Target: claude
Duration: 14:01:03 ~ 14:18:42
Total Events: 184
Executed Commands: 32
Files Accessed: 104
Sensitive Files Accessed: 2
Dangerous Commands: 1

Risk: HIGH

Key Findings
- .env file was accessed by an AI-agent-related process.
- git reset --hard was executed during the session.
- Multiple project files were accessed in a short time window.

Recommended Actions
- Review git diff before commit.
- Check whether secrets were exposed.
- Rotate API keys if .env contains real credentials.

Recent Alerts
- [high] env-file-access pid=18345 comm=cat path=/home/user/project/.env
- [high] agent-dangerous-command pid=18350 comm=git argv="git reset --hard"
- [medium] downloader-exec pid=18331 comm=curl
```

---

## 20. Makefile 예시

```makefile
# SysGuard C MVP Makefile.

CC := clang
CFLAGS := -Wall -Wextra -O2 -g
BPF_CLANG := clang
BPF_CFLAGS := -g -O2 -target bpf

BIN := build/sysguard
BPF_OBJ := build/sysguard.bpf.o
BPF_SKEL := build/sysguard.skel.h

USER_SRC := \
	src/main.c \
	src/rules.c \
	src/fake_collector.c \
	src/jsonl_writer.c \
	src/bpf_collector.c

.PHONY: all clean run-fake run-real run-agent run-gui

all: $(BIN)

# Compile eBPF program into BPF object.
$(BPF_OBJ): bpf/sysguard.bpf.c bpf/vmlinux.h
	mkdir -p build
	$(BPF_CLANG) $(BPF_CFLAGS) -I bpf -c bpf/sysguard.bpf.c -o $(BPF_OBJ)

# Generate libbpf skeleton header from BPF object.
$(BPF_SKEL): $(BPF_OBJ)
	bpftool gen skeleton $(BPF_OBJ) > $(BPF_SKEL)

# Build user-space SysGuard binary.
$(BIN): $(BPF_SKEL) $(USER_SRC)
	mkdir -p build
	$(CC) $(CFLAGS) -I build -I src -o $(BIN) $(USER_SRC) -lbpf -lelf -lz

# Run with deterministic fake events.
run-fake: $(BIN)
	mkdir -p logs
	./$(BIN) --fake --output logs/session_fake.jsonl

# Run real eBPF collector.
run-real: $(BIN)
	mkdir -p logs
	sudo ./$(BIN) --output logs/session_real.jsonl

# Run AI-agent mode.
run-agent: $(BIN)
	mkdir -p logs
	sudo ./$(BIN) --agent-mode --output logs/session_agent.jsonl

# Run GUI wrapper.
run-gui: $(BIN)
	mkdir -p logs
	sudo python3 app/main.py

clean:
	rm -rf build
```

---

## 21. Demo Script

### Basic demo

`demo/benign_simulator.sh`

```bash
#!/usr/bin/env bash
# This script triggers SysGuard rules using harmless commands.
# It must not exploit, persist, exfiltrate, or damage the system.

set -euo pipefail

echo "[demo] Trigger shell execution event"
bash -c 'echo hello-from-demo'

echo "[demo] Trigger sensitive file access event"
cat /etc/passwd >/dev/null

echo "[demo] Trigger downloader-like execution event"
curl --version >/dev/null || true

echo "[demo] Trigger docker socket path check if it exists"
if [ -S /var/run/docker.sock ]; then
  ls -l /var/run/docker.sock >/dev/null
fi

echo "[demo] Done"
```

### AI agent session demo

`demo/ai_agent_simulator.sh`

```bash
#!/usr/bin/env bash
# This script simulates AI-agent-like local activity using harmless commands.
# It does not delete, encrypt, exfiltrate, exploit, or persist anything.

set -euo pipefail

DEMO_DIR="/tmp/sysguard-agent-demo"
mkdir -p "$DEMO_DIR"
cd "$DEMO_DIR"

# Create harmless project-like files.
echo 'print("hello")' > main.py
echo 'demo_key=not-a-real-secret' > .env
echo '# demo' > README.md

echo "[agent-demo] Simulate reading project files"
cat README.md >/dev/null
cat main.py >/dev/null

# This intentionally touches .env to trigger a sensitive-file rule.
echo "[agent-demo] Simulate sensitive file access"
cat .env >/dev/null

echo "[agent-demo] Simulate development commands"
git --version >/dev/null || true
python3 --version >/dev/null || true

echo "[agent-demo] Done"
```

GUI 시연 순서:

```text
1. sudo python3 app/main.py
2. Start Monitoring 클릭
3. demo/ai_agent_simulator.sh 실행
4. Stop 클릭
5. Refresh Logs 클릭
6. 생성된 session log 선택
7. Open HTML Report 클릭
8. AI Agent Session Summary 확인
```

---

## 22. 5주 개발 계획

| 주차 | 담당자 A | 담당자 B | 완료 기준 |
|---|---|---|---|
| Week 1 | libbpf-bootstrap 구조 파악, skeleton build 실험 | C fake collector, event/alert/rule engine | `make run-fake`로 alert 출력 |
| Week 2 | `execve` tracepoint PoC, `pid/ppid/uid/comm/argv` 수집 | CLI 출력, JSONL writer, GUI skeleton | fake mode에서 JSONL 생성, GUI 실행 |
| Week 3 | ring buffer event decode, 실제 `execve` 통합 | target process filter, process tree tracker 초안 | 실제 `bash`, `curl`, `git` event가 target session에 포함됨 |
| Week 4 | `openat` tracepoint, path 수집 | sensitive file rule, agent session analyzer, GUI Start/Stop 안정화 | `.env`, `/etc/passwd`, Docker socket alert 및 agent summary 생성 |
| Week 5 | Ubuntu VM 재현성, Makefile 정리, optional syscall 1개 검토 | README, sample report, 발표자료, demo flow | GUI에서 Start→Stop→Agent Report 시연 가능 |

Optional syscall 개발은 Week 5 이전에 `execve/openat`이 안정화된 경우에만 진행한다.

---

## 23. 개발 순서

```text
1. event.h 작성
2. alert.h 작성
3. fake_collector.c 작성
4. rules.c 작성
5. main.c에서 --fake mode 실행
6. JSONL writer 추가
7. app/report.py 작성
8. app/main.py GUI skeleton 작성
9. app/session_analyzer.py 작성
10. target process filtering 구현
11. process tree tracking 구현
12. demo script 작성
13. execve eBPF collector 구현
14. openat eBPF collector 구현
15. GUI Start/Stop과 real engine 연결
16. Agent Session Report 생성
17. optional syscall 추가 여부 결정
18. README 기준으로 clean VM 재현성 테스트
```

최종 완료 흐름:

```text
GUI에서 Start Monitoring
→ AI-agent-like demo script 실행
→ Stop
→ log session 선택
→ Open HTML Report
→ Agent Session Summary 확인
```

---

## 24. 안전 기준

공모전 demo는 실제 공격 도구처럼 동작하면 안 된다.

금지:

```text
reverse shell 실행
exploit 자동화
권한 상승 시도
persistence 생성
외부 서버로 데이터 전송
파일 삭제/암호화/변조
실제 credential 출력 또는 저장
실제 SSH private key 접근 demo
```

허용:

```text
bash -c 'echo hello'
cat /etc/passwd >/dev/null
cat /tmp/sysguard-agent-demo/.env >/dev/null
curl --version
ls -l /var/run/docker.sock
python3 --version
git --version
```

`.env` demo는 반드시 `/tmp/sysguard-agent-demo/.env`처럼 직접 만든 가짜 파일을 사용한다.

---

## 25. 발표 포인트

### 시스템 관점

- eBPF program이 syscall tracepoint에 attach된다.
- kernel space에서는 event 수집만 수행한다.
- ring buffer를 통해 user-space C engine으로 event를 전달한다.
- C engine이 rule engine을 통해 alert를 생성한다.
- Python 분석 계층이 target process와 child process event를 session으로 묶는다.
- Python GUI는 privileged engine을 제어하고 report를 시각화한다.

### 보안 관점

- 이상행위는 악성 확정이 아니라 조사할 가치가 있는 suspicious behavior로 정의한다.
- `execve` 기반으로 의심 command 실행을 탐지한다.
- `openat` 기반으로 민감 파일 접근을 탐지한다.
- AI agent session에서 민감 파일 접근, 위험 명령 실행, 다수 파일 접근을 분석한다.
- 각 alert는 `severity`, `reason`, `recommendation`을 제공한다.

### 제품 관점

- 사용자는 GUI에서 monitoring session을 시작/중지할 수 있다.
- 각 session은 JSONL log로 저장된다.
- 저장된 session log는 HTML report로 열람할 수 있다.
- 단순 event 나열이 아니라 target process의 activity summary를 제공한다.
- AI agent가 로컬 시스템에서 수행한 작업을 사후 검토할 수 있다.
- CLI와 GUI를 모두 지원하므로 개발/시연/디버깅이 분리된다.

---

## 26. Future Work

```text
BPF map 기반 kernel-side target PID filtering
connect syscall 기반 outbound network monitoring
unlinkat/renameat 기반 파일 삭제/rename 탐지
chmod/fchmodat 기반 권한 변경 탐지
download-and-shell sequence rule
process tree correlation 고도화
allowlist/denylist config
YAML rule parser
real-time GUI alert table
systemd service packaging
privileged backend + unprivileged GUI 분리
eBPF LSM 기반 차단 기능
fanotify 기반 permission prompt
```

---

## 27. 최종 완료 기준

- clean Ubuntu VM에서 build 가능
- `make run-fake`로 fake alert 출력 가능
- `sudo ./build/sysguard`로 real eBPF mode 실행 가능
- GUI에서 Start/Stop 동작 가능
- GUI에서 `logs/*.jsonl` session 목록 조회 가능
- 선택한 log를 HTML report로 열람 가능
- `execve` event 수집 가능
- `openat` event 수집 가능
- `pid`, `ppid`, `uid`, `comm`, `argv`, `path` 기록 가능
- target process 또는 AI-agent-like process session summary 생성 가능
- 최소 5개 rule alert 재현 가능
- JSONL report 생성 가능
- Agent Session Report 생성 가능
- demo script로 harmless 시연 가능
- README만 보고 build/run/demo 재현 가능
