# SysGuard

**eBPF/libbpf 기반 AI Agent Boundary Auditor + Commit Safety Monitor**

SysGuard는 Linux kernel의 주요 syscall event를 eBPF로 수집하고, user-space에서 Claude Code, Codex, Gemini CLI 같은 AI 개발 에이전트의 작업 세션을 분석하는 경량 보안 모니터링 도구이다.

SysGuard의 목적은 단순히 syscall log를 보여주는 것이 아니다. Git이 추적하는 레포지토리 내부 변경은 Git이 잘 처리한다. SysGuard는 Git이 보기 어려운 **로컬 시스템 행위**, 즉 AI Agent가 프로젝트 경계를 벗어나 `.env`, SSH key, 시스템 파일, 외부 명령, 파괴적 Git 명령 등에 접근했는지를 판단한다.

핵심 질문은 다음이다.

```text
이 AI Agent 작업은 commit해도 안전한가?
AI Agent가 허용된 개발 작업 범위를 벗어났는가?
Git이 추적하지 못하는 로컬 보안 리스크가 있었는가?
```

공모전 시연에서는 Python GUI를 통해 monitoring을 Start/Stop하고, 선택한 session log를 HTML 기반 **Commit Safety Report**로 확인한다.

---

## 1. 프로젝트 정의

### 기존 Linux syscall monitor와의 차이

일반적인 syscall monitor는 다음 정보를 제공한다.

```text
어떤 프로세스가 어떤 syscall을 호출했는가?
```

SysGuard는 다음 정보를 제공하는 것을 목표로 한다.

```text
AI Agent가 개발 작업 중 허용된 project boundary를 벗어났는가?
민감 파일이나 시스템 자원에 접근했는가?
파괴적 명령이나 위험한 Git 명령을 실행했는가?
현재 작업 결과를 commit해도 안전한가?
```

### 핵심 컨셉

```text
Git:
- 레포지토리 내부 파일 변경 추적
- diff 확인
- branch/commit 기반 복구

SysGuard:
- AI Agent의 syscall event 추적
- project boundary 위반 감지
- protected path 접근 감지
- dangerous command 실행 감지
- Commit Safety Report 생성
```

즉, SysGuard는 Git을 대체하지 않는다. Git이 다루지 않는 로컬 시스템 보안 영역을 보완한다.

---

## 2. 완성품 형태

```text
SysGuard Monitor App
├── Python GUI wrapper
│   ├── Project Path input
│   ├── Target Process input
│   ├── Start Monitoring button
│   ├── Stop button
│   ├── Refresh Logs button
│   ├── Log session list
│   └── Open Commit Safety Report button
│
├── Python analysis/report layer
│   ├── JSONL event reader
│   ├── lightweight target/child process filter
│   ├── project boundary checker
│   ├── protected path policy checker
│   ├── dangerous command detector
│   ├── git status/diff summary collector
│   ├── commit safety evaluator
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

핵심 원칙:

```text
GUI는 eBPF를 직접 다루지 않는다.
GUI는 C/eBPF engine을 실행/종료하고, 생성된 JSONL log를 HTML report로 보여준다.
eBPF는 판단하지 않고 event 수집에 집중한다.
AI Agent 분석, boundary 판단, commit safety 평가는 user-space에서 수행한다.
```

---

## 3. 프로젝트 목표

### 핵심 목표

- Linux process execution event 수집
- Linux file access event 수집
- 특정 process와 child process의 syscall activity를 lightweight하게 추적
- Claude Code / Codex / Gemini CLI 같은 AI Agent session 분석
- project path 내부/외부 접근 분류
- `.env`, `.ssh`, `/etc/shadow` 등 protected path 접근 탐지
- `rm -rf`, `git reset --hard`, `chmod 777` 등 dangerous command 탐지
- Git diff와 syscall event를 함께 요약
- Commit Safety를 `SAFE`, `REVIEW_NEEDED`, `UNSAFE`로 판단
- GUI 기반 Start/Stop 제어
- HTML 기반 Commit Safety Report 생성
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
| 분석 방식 | rule/policy 기반 |
| session 분석 | Python `report.py` 내부 또는 간단한 `session_analyzer.py` |
| log format | JSONL |
| report | HTML |
| 시연 | harmless normal/risky demo script |

---

## 4. 하지 않는 것

5주 MVP에서는 아래 기능을 제외한다.

| 제외 기능 | 제외 이유 |
|---|---|
| 실시간 차단 | eBPF LSM, seccomp, fanotify permission event 설계 필요 |
| 모든 syscall 감시 | event 폭증, false positive 증가 |
| AI Agent 자동 제어 | Claude/Codex interactive terminal 처리 부담 |
| 전체 자동 rollback | Git 작업 손상 가능성, 안전성 문제 |
| `.env` 자동 백업 기본 활성화 | secret 복사본 생성으로 보안 리스크 증가 |
| packet payload 분석 | 개인정보/보안/구현 부담 증가 |
| ML anomaly detection | 데이터셋 부족, 설명 가능성 낮음 |
| 실시간 Web dashboard | GUI와 engine 동기화 부담 증가 |
| YAML rule parser | C parser 구현 부담 증가. MVP는 built-in rule 사용 |
| SQLite 저장 | JSONL로 충분 |

주의:

```text
MVP는 AI Agent를 차단하지 않는다.
MVP는 AI Agent의 행위를 수집, 필터링, 요약, 위험도 평가, report 생성까지만 수행한다.
복구는 Git 명령 안내 수준으로 제한한다.
```

---

## 5. strace/auditd와의 차별점

### strace와의 차이

`strace`는 특정 프로세스의 syscall을 자세히 추적하는 디버깅 도구이다.

```bash
# Example: trace selected syscalls of a process.
strace -f -e trace=execve,openat claude
```

하지만 `strace`는 syscall log를 보여줄 뿐, AI Agent 작업 맥락을 해석하지 않는다.

| 항목 | strace | SysGuard |
|---|---|---|
| 목적 | syscall debugging | AI Agent boundary audit |
| 출력 | low-level syscall log | session summary + safety report |
| AI Agent session grouping | 없음 | 있음 |
| project boundary 판단 | 없음 | 있음 |
| protected path policy | 없음 | 있음 |
| Git diff 연동 | 없음 | 있음 |
| Commit Safety 판단 | 없음 | 있음 |
| GUI/HTML report | 없음 | 있음 |

### auditd와의 차이

`auditd`는 Linux 감사 로그 시스템으로 강력하지만 범용 감사 도구이다.

```bash
# Example: audit access to .env file.
sudo auditctl -w /home/user/project/.env -p rwxa -k env_watch
```

SysGuard는 auditd를 대체하려는 도구가 아니라, AI Agent 개발 workflow에 특화된 해석 계층을 제공한다.

| 항목 | auditd | SysGuard |
|---|---|---|
| 목적 | 시스템 감사/audit | AI Agent 작업 안전성 검토 |
| 설정 | admin 중심 rule | project/agent 중심 policy |
| 출력 | audit log | Commit Safety Report |
| AI Agent process tree 분석 | 수동 | 목표 기능 |
| Git diff와 연결 | 없음 | 있음 |
| `.env`, `.ssh` 접근의 개발 맥락 해석 | 없음 | 있음 |
| 공모전 시연성 | 중간 | 높음 |

핵심 차별점:

```text
strace/auditd:
- low-level event collection

SysGuard:
- AI Agent session interpretation
- project boundary audit
- Git이 추적하지 못하는 로컬 보안 리스크 분석
- commit 전 안전성 판단
```

---

## 6. 전체 아키텍처

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
  CLI alert output
  JSONL output
        |
        | logs/session_*.jsonl
        v
[Python Analysis Layer]
  target process filter
  lightweight process filter
  project boundary checker
  protected path policy checker
  dangerous command detector
  git diff collector
  commit safety evaluator
  JSONL -> HTML report
        |
        v
[Python GUI Wrapper]
  Start / Stop
  Log session list
  Open Commit Safety Report
```

설계상 eBPF program은 특정 AI Agent를 직접 판단하지 않는다. eBPF는 syscall event를 수집하고, user-space에서 `pid`, `ppid`, `comm`, `exe_path`, `argv`, `path`를 이용해 target process와 child process 여부를 판단한다.

---

## 7. 기술 스택

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

## 8. 역할 분담

이번 MVP에서는 B에게 GUI, policy, report, Git 요약이 몰리기 때문에 역할을 재조정한다. 핵심 원칙은 다음이다.

```text
A = syscall evidence를 생성하는 engine 담당
B = evidence를 사용자가 이해할 수 있는 Commit Safety Report로 바꾸는 담당
```

즉, B가 raw event를 보정하거나 JSONL writer를 만들지 않도록 한다. A는 B가 바로 읽을 수 있는 **고정 JSONL schema**를 제공해야 한다.

### 담당자 A: eBPF / Collector / Engine / JSONL Evidence

**역할:** 커널에서 syscall event를 수집하고, user-space C engine에서 정규화된 JSONL evidence를 생성한다.

필수 작업:

- `bpf/sysguard.bpf.c` 작성
- `execve` tracepoint attach
- `openat` tracepoint attach
- BPF ring buffer로 event 전달
- `timestamp_ns`, `pid`, `ppid`, `uid`, `comm` 수집
- `execve`에서 `exe_path`, `argv` 수집
- `openat`에서 `path`, `flags` 수집
- `bpftool gen skeleton` 기반 build 구성
- `src/bpf_collector.c`에서 ring buffer event 수신
- `src/event.h` 작성 및 event schema 고정
- `src/jsonl_writer.c` 작성
- `src/fake_collector.c` 작성
- `--fake`, `--output`, `--agent-mode`, `--target-comm`, `--project-path` CLI 옵션 처리
- normal / risky demo script 작성
- real eBPF mode 안정화

선택 작업:

- `unlinkat` tracepoint 추가
- `renameat` / `fchmodat` / `connect`는 Future Work 또는 추가 구현으로 둔다.

A 완료 기준:

```text
sudo ./build/sysguard \
  --agent-mode \
  --target-comm claude \
  --project-path /home/sumin/SysGuard \
  --output logs/session_claude.jsonl

실행 후 logs/session_claude.jsonl에 execve/openat event가 고정 schema로 기록된다.
```

예시 JSONL:

```json
{"timestamp_ns":123456789,"session_id":"session_20260701_001500","event":"execve","pid":3010,"ppid":3000,"uid":1000,"comm":"git","argv":"git reset --hard","path":"","project_path":"/home/sumin/SysGuard","target_comm":"claude"}
{"timestamp_ns":123456790,"session_id":"session_20260701_001500","event":"openat","pid":3000,"ppid":2500,"uid":1000,"comm":"claude","argv":"","path":"/home/sumin/SysGuard/.env","project_path":"/home/sumin/SysGuard","target_comm":"claude"}
```

A의 핵심 책임은 session 분석이 아니라 **분석 가능한 syscall evidence를 정확히 넘겨주는 것**이다.

### 담당자 B: Policy / Git Summary / Report / GUI Wrapper

**역할:** A가 생성한 JSONL evidence를 읽고, AI Agent 개발 workflow 관점에서 Commit Safety Report를 생성한다.

필수 작업:

- `app/main.py` GUI wrapper 작성
- GUI에서 Start/Stop/Open Report 동작 구현
- `app/report.py`에서 JSONL → HTML report 생성
- `app/policy.py`에서 protected path / dangerous command rule 구현
- `app/git_summary.py`에서 `git status`, `git diff --stat` 요약
- lightweight target/child process filtering
- project boundary 판단
- Commit Safety `SAFE`, `REVIEW_NEEDED`, `UNSAFE` 판단
- sample report 정리

선택 작업:

- 별도 `app/session_analyzer.py` 분리
- report 디자인 개선
- log session 목록에 safety 결과 미리 표시

B 제외 범위:

```text
- eBPF/libbpf 구현
- C JSONL writer 구현
- fake collector 구현
- 실시간 dashboard
- SQLite 저장
- YAML rule parser
- 복구 버튼
- 전체 rollback
- process tree graph
- .env secure backup
```

B 완료 기준:

```text
logs/session_*.jsonl을 읽어서 HTML Commit Safety Report를 생성하고,
GUI에서 해당 report를 열 수 있다.
```

B의 핵심 책임은 **raw syscall log를 제품 관점의 안전성 판단으로 변환하는 것**이다.

### A/B 인터페이스 계약

A와 B 사이의 계약은 JSONL schema다. 이 schema가 고정되면 B는 eBPF 구현 진행 상황과 독립적으로 fake JSONL 기반 개발을 진행할 수 있다.

필수 field:

| Field | 설명 | 담당 |
|---|---|---|
| `timestamp_ns` | event 발생 시간 | A |
| `session_id` | session 식별자 | A |
| `event` | `execve`, `openat` 등 | A |
| `pid` | process id | A |
| `ppid` | parent process id | A |
| `uid` | user id | A |
| `comm` | process name | A |
| `argv` | execve command line | A |
| `path` | openat target path | A |
| `project_path` | GUI/CLI에서 전달한 project root | A |
| `target_comm` | GUI/CLI에서 전달한 target process | A |

B는 위 field만 사용해서 다음을 판단한다.

```text
- target process 관련 event인가?
- project_path 내부 접근인가, 외부 접근인가?
- protected path 접근인가?
- dangerous command 실행인가?
- Commit Safety가 SAFE / REVIEW_NEEDED / UNSAFE 중 무엇인가?
```
---

## 9. 디렉터리 구조

```text
sysguard/
├── src/
│   ├── main.c                 # CLI entry point
│   ├── event.h                # shared event struct
│   ├── alert.h                # alert struct and severity
│   ├── collector.h            # collector-related declarations
│   ├── fake_collector.c       # fake event generator
│   ├── bpf_collector.c        # libbpf skeleton loader + ringbuf reader
│   ├── rules.c                # low-level event rule matching
│   ├── rules.h
│   ├── jsonl_writer.c         # JSONL output writer
│   └── jsonl_writer.h
├── bpf/
│   ├── sysguard.bpf.c         # eBPF program
│   └── vmlinux.h              # kernel type definitions
├── app/
│   ├── main.py                # GUI wrapper app
│   ├── report.py              # JSONL to HTML Commit Safety Report
│   ├── policy.py              # protected path / dangerous command policy
│   ├── git_summary.py         # git status/diff summary helper
│   └── session_analyzer.py    # optional: 분리형 session analysis
├── logs/
│   ├── session_*.jsonl        # monitoring session logs
│   └── session_*.html         # generated reports
├── build/
│   └── generated files and sysguard binary
├── demo/
│   ├── benign_simulator.sh
│   ├── agent_normal_simulator.sh
│   └── agent_boundary_violation_simulator.sh
├── reports/
│   └── sample_report.html
├── docs/
│   ├── architecture.md
│   ├── policy.md
│   └── strace_auditd_comparison.md
├── Makefile
└── README.md
```

---

## 10. Event Interface

`struct sysguard_event`는 eBPF collector와 user-space 분석 계층 사이의 공통 계약이다.

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

    // Optional event types for future extensions.
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
    char old_path[SYSGUARD_MAX_PATH];
    char new_path[SYSGUARD_MAX_PATH];
    int32_t flags;
    int32_t mode;
};

#endif
```

MVP에서 실제로 구현할 필수 field:

```text
execve:
- timestamp_ns
- pid
- ppid
- uid
- comm
- exe_path
- argv

openat:
- timestamp_ns
- pid
- ppid
- uid
- comm
- path
- flags
```

### JSONL Output Schema

A는 B가 바로 사용할 수 있도록 아래 JSONL schema를 고정한다. B는 raw event 보정 없이 이 schema만 읽는다.

```json
{
  "timestamp_ns": 123456789,
  "session_id": "session_20260701_001500",
  "event": "execve",
  "pid": 3010,
  "ppid": 3000,
  "uid": 1000,
  "comm": "git",
  "argv": "git reset --hard",
  "path": "",
  "project_path": "/home/sumin/SysGuard",
  "target_comm": "claude"
}
```

`openat` event 예시:

```json
{
  "timestamp_ns": 123456790,
  "session_id": "session_20260701_001500",
  "event": "openat",
  "pid": 3000,
  "ppid": 2500,
  "uid": 1000,
  "comm": "claude",
  "argv": "",
  "path": "/home/sumin/SysGuard/.env",
  "project_path": "/home/sumin/SysGuard",
  "target_comm": "claude"
}
```

---

## 11. Policy 기준

SysGuard는 레포지토리 내부 파일 수정 자체를 이상 행위로 판단하지 않는다.

### 정상 개발 활동

아래는 일반적으로 정상 활동으로 분류한다.

```text
- src/*.c 수정
- README.md 수정
- Makefile 수정
- test 파일 생성
- git status 실행
- git diff 실행
- make 실행
- python test.py 실행
- npm test 실행
```

### 위험 행위 기준

위험 여부는 다음 기준으로 판단한다.

```text
1. Project boundary violation
   - project_path 바깥의 파일 접근

2. Protected path access
   - .env
   - .env.local
   - config/secrets.json
   - ~/.ssh/
   - ~/.aws/credentials
   - /etc/shadow
   - /etc/sudoers

3. Dangerous command execution
   - rm -rf
   - git reset --hard
   - git clean -fd
   - chmod 777
   - chown root
   - curl / wget / nc / netcat

4. Suspicious sequence
   - .env 접근 후 curl/wget 실행
   - protected path 접근 후 network tool 실행
```

---

## 12. Policy 예시

```json
{
  "project_path": "/home/sumin/SysGuard",
  "target_processes": [
    "claude",
    "codex",
    "gemini",
    "cursor",
    "code"
  ],
  "protected_paths": [
    ".env",
    ".env.local",
    "config/secrets.json",
    "~/.ssh/",
    "~/.aws/credentials",
    "/etc/shadow",
    "/etc/sudoers"
  ],
  "dangerous_commands": [
    "rm -rf",
    "git reset --hard",
    "git clean -fd",
    "chmod 777",
    "chown root",
    "curl",
    "wget",
    "nc",
    "netcat"
  ]
}
```

MVP에서는 JSON parser 없이 Python dictionary 또는 built-in list로 처리해도 된다.

---

## 13. Commit Safety 판단

### SAFE

```text
Commit Safety: SAFE

조건:
- project_path 내부 파일만 접근/수정
- protected path 접근 없음
- dangerous command 실행 없음
- project boundary violation 없음
```

### REVIEW_NEEDED

```text
Commit Safety: REVIEW_NEEDED

조건:
- 많은 파일 수정
- build/config 파일 변경
- 삭제성 명령이 실행됐지만 sandbox/build artifact에 한정됨
- 위험하지는 않지만 사람이 검토해야 하는 작업 존재
```

### UNSAFE

```text
Commit Safety: UNSAFE

조건:
- .env 접근
- ~/.ssh/ 접근
- /etc/shadow, /etc/sudoers 접근
- project_path 외부 접근
- git reset --hard 실행
- rm -rf 실행
- .env 접근 이후 curl/wget/nc 실행
```

---

## 14. Rule 목록

| Rule ID | 기준 | Severity | 설명 |
|---|---|---:|---|
| `project-boundary-access` | `openat` | high | project_path 바깥 파일 접근 |
| `env-file-access` | `openat` | high | `.env` 접근 |
| `ssh-key-access` | `openat` | critical | SSH key 접근 |
| `shadow-access` | `openat` | critical | `/etc/shadow` 접근 |
| `sudoers-access` | `openat` | high | `/etc/sudoers` 접근 |
| `destructive-rm` | `execve` | high | `rm -rf` 실행 |
| `git-reset-hard` | `execve` | high | `git reset --hard` 실행 |
| `git-clean-force` | `execve` | high | `git clean -fd` 실행 |
| `unsafe-chmod` | `execve` 또는 `fchmodat` | medium/high | `chmod 777` 등 위험 권한 변경 |
| `downloader-exec` | `execve` | medium | `curl`, `wget` 실행 |
| `possible-secret-exfiltration` | sequence | critical | `.env` 접근 후 외부 전송 의심 명령 |

---

## 15. Optional syscall 추천

필수는 `execve`, `openat`이다. 시간이 남으면 아래 순서로 추가한다.

| 우선순위 | syscall | 이유 | 담당 |
|---:|---|---|---|
| 1 | `unlinkat` | 실제 파일 삭제 감지 | A |
| 2 | `renameat` / `renameat2` | 파일 rename, ransomware-like behavior 실마리 | A |
| 3 | `fchmodat` / `chmod` | 실제 권한 변경 감지 | A |
| 4 | `exit_group` | session 종료 시점 파악 | A |
| 5 | `connect` | 외부 연결 감지. IPv4/IPv6 decoding 부담 있음 | A |

주의:

```text
write syscall은 MVP에서 비추천한다.
write(fd, buf, count)는 path를 직접 주지 않기 때문에 fd-to-path mapping이 필요하다.
5주 MVP에서는 openat + unlinkat + renameat + chmod 쪽이 더 현실적이다.
```

---

## 16. Build Requirements

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

## 17. Build & Run

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

Agent boundary monitor mode:

```bash
# Start monitoring and later analyze events for claude process.
sudo ./build/sysguard \
  --agent-mode \
  --target-comm claude \
  --project-path /home/sumin/SysGuard \
  --output logs/session_claude.jsonl
```

Generate report:

```bash
# Generate Commit Safety Report.
python3 app/report.py \
  --input logs/session_claude.jsonl \
  --agent claude \
  --project-path /home/sumin/SysGuard \
  --output logs/session_claude.html
```

Open report:

```bash
# Open generated HTML report.
xdg-open logs/session_claude.html
```

GUI mode:

```bash
# MVP에서는 eBPF load 권한 문제를 단순화하기 위해 GUI를 sudo로 실행한다.
sudo python3 app/main.py
```

---

## 18. GUI 동작 방식

### Start Monitoring

```text
Start button 클릭
→ project_path와 target process 읽기
→ logs/session_YYYYMMDD_HHMMSS.jsonl 생성
→ ./build/sysguard --agent-mode --target-comm <target> --project-path <path> 실행
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

### Open Commit Safety Report

```text
선택한 JSONL log 읽기
→ session_analyzer.py 실행
→ project boundary / protected path / dangerous command 분석
→ Git diff/status 요약
→ HTML report 생성
→ browser로 열기
```

---

## 19. GUI 화면 MVP

```text
+------------------------------------------------------+
| SysGuard - AI Agent Boundary Auditor                 |
+------------------------------------------------------+
| Project Path:   /home/sumin/SysGuard                 |
| Target Process: claude                               |
|                                                      |
| [ Start Monitoring ] [ Stop ]                        |
+------------------------------------------------------+
| Status: Stopped                                      |
+------------------------------------------------------+
| Log Sessions                                         |
|------------------------------------------------------|
| session_claude_20260701_142100.jsonl | UNSAFE        |
| session_claude_20260701_143500.jsonl | SAFE          |
| session_claude_20260701_151000.jsonl | REVIEW        |
+------------------------------------------------------+
| [ Open Commit Safety Report ]                        |
+------------------------------------------------------+
```

---

## 20. HTML Report 구성

HTML report는 선택한 JSONL session을 사람이 보기 쉽게 요약한다.

포함 항목:

```text
1. Session metadata
2. Target process / project path
3. Commit Safety result
4. Normal development activity summary
5. Boundary violation summary
6. Protected path access summary
7. Dangerous command summary
8. Git status/diff summary
9. Recent event table
10. Recommended actions
```

예시:

```text
SysGuard Commit Safety Report

Target Agent: claude
Project Path: /home/sumin/SysGuard
Commit Safety: UNSAFE
Risk Level: HIGH

Normal Development Activity:
- README.md opened
- src/main.c modified
- make executed

Boundary Violations:
- /home/sumin/.ssh/config accessed
- .env accessed

Dangerous Commands:
- git reset --hard
- rm -rf build/

Recommended Actions:
- Review git diff before commit.
- Check whether .env content was exposed.
- Rotate API keys if exposure is suspected.
- Avoid committing until boundary violations are reviewed.
```

---

## 21. `.env` 처리 정책

`.env`는 보통 Git이 추적하지 않는 로컬 secret file이다. 따라서 Git만으로는 수정/삭제 복구가 어렵다.

MVP 정책:

```text
- .env 접근 여부를 HIGH alert로 표시한다.
- .env 내용은 JSONL이나 HTML report에 절대 저장하지 않는다.
- .env가 접근되면 Commit Safety를 UNSAFE로 표시한다.
- 복구보다 secret exposure 대응을 안내한다.
```

권장 대응:

```text
1. .env에 어떤 secret이 있었는지 확인한다.
2. AI Agent transcript 또는 command output에 secret이 노출됐는지 확인한다.
3. 노출 가능성이 있으면 API key/token/password를 rotate한다.
4. .env는 .gitignore에 유지한다.
5. .env.example에는 key 이름만 보관한다.
```

Optional future work:

```text
Secure Backup Mode:
- 사용자가 명시적으로 켠 경우에만 .env를 .sysguard/snapshots/... 에 600 권한으로 백업한다.
- 기본값은 OFF로 둔다.
- HTML report에는 secret 내용을 절대 출력하지 않는다.
```

---

## 22. Makefile 예시

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

.PHONY: all clean run-fake run-real run-gui run-agent

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

# Run agent boundary monitor mode.
run-agent: $(BIN)
	mkdir -p logs
	sudo ./$(BIN) --agent-mode --target-comm claude --project-path $$(pwd) --output logs/session_claude.jsonl

# Run GUI wrapper.
run-gui: $(BIN)
	mkdir -p logs
	sudo python3 app/main.py

clean:
	rm -rf build
```

---

## 23. Demo Script

### 정상 개발 활동 demo

`demo/agent_normal_simulator.sh`

```bash
#!/usr/bin/env bash
# This script simulates normal AI agent development activity.
# It only reads or modifies safe project-local demo files.

set -euo pipefail

PROJECT_DIR="$(pwd)"
SANDBOX_DIR="$PROJECT_DIR/demo/sandbox_normal"

mkdir -p "$SANDBOX_DIR"

echo "[demo] Simulate reading project files"
cat README.md >/dev/null || true

echo "[demo] Simulate modifying a project-local file"
echo "normal update" >> "$SANDBOX_DIR/notes.txt"

echo "[demo] Simulate normal development commands"
git status >/dev/null || true
make --version >/dev/null || true
python3 --version >/dev/null || true

echo "[demo] Done"
```

Expected report:

```text
Commit Safety: SAFE or REVIEW_NEEDED
Reason:
- Only project-local development activity was observed.
- No protected path access detected.
- No dangerous command detected.
```

### Boundary violation demo

`demo/agent_boundary_violation_simulator.sh`

```bash
#!/usr/bin/env bash
# This script simulates risky AI agent behavior in a controlled way.
# It must not exploit, persist, exfiltrate, or damage the system.

set -euo pipefail

PROJECT_DIR="$(pwd)"
SANDBOX_DIR="$PROJECT_DIR/demo/sandbox_risky"

mkdir -p "$SANDBOX_DIR/build"
echo "SECRET_KEY=dummy_value" > "$SANDBOX_DIR/.env"
echo "echo test" > "$SANDBOX_DIR/test.sh"

echo "[demo] Simulate sensitive file access inside project sandbox"
cat "$SANDBOX_DIR/.env" >/dev/null

echo "[demo] Simulate unsafe permission command"
chmod 777 "$SANDBOX_DIR/test.sh"

echo "[demo] Simulate recursive delete inside sandbox only"
rm -rf "$SANDBOX_DIR/build"

echo "[demo] Simulate destructive Git command pattern without executing it"
bash -c 'echo "git reset --hard" >/dev/null'

echo "[demo] Done"
```

Expected report:

```text
Commit Safety: UNSAFE or REVIEW_NEEDED
Reason:
- .env-like file accessed.
- chmod 777 detected.
- rm -rf detected inside sandbox.
```

주의: 실제 demo에서는 `/etc/shadow`, real SSH key, real API key를 사용하지 않는다.

---

## 24. 5주 개발 계획

작업량 균형을 위해 Week 1부터 JSONL schema와 fake log를 먼저 고정한다. 실제 eBPF가 늦어져도 B는 fake JSONL로 report/GUI 개발을 진행할 수 있어야 한다.

| 주차 | 담당자 A | 담당자 B | 완료 기준 |
|---|---|---|---|
| Week 1 | `event.h`, fake collector, JSONL writer, CLI option skeleton | fake JSONL 기반 HTML report mockup, policy rule 초안 | `make run-fake`로 JSONL 생성, B가 report 생성 |
| Week 2 | `execve` tracepoint PoC, `pid/ppid/uid/comm/argv` 기록 | GUI skeleton, Start/Stop/Open Report 버튼 | fake mode에서 GUI로 report 열기 |
| Week 3 | `openat` tracepoint PoC, path/flags 수집, real JSONL 안정화 | protected path rule, dangerous command rule, project boundary rule | real exec/open event가 report에 반영 |
| Week 4 | `--target-comm`, `--project-path`, demo script 안정화, optional `unlinkat` 시도 | Git diff/status summary, Commit Safety 판단 완성 | SAFE/REVIEW/UNSAFE report 생성 |
| Week 5 | Ubuntu VM 재현성, Makefile 정리, eBPF 시연 안정화 | sample report, GUI polish, README/발표자료 정리 | GUI에서 Start→Stop→Report 시연 가능 |

### 작업량 조정 원칙

```text
A가 반드시 제공해야 하는 것:
- execve/openat evidence
- 고정 JSONL schema
- fake mode
- demo script

B가 반드시 제공해야 하는 것:
- JSONL parser
- policy rule
- Git summary
- HTML Commit Safety Report
- GUI wrapper

이번 MVP에서 제외하는 것:
- 실시간 dashboard
- 복구 버튼
- SQLite
- YAML parser
- process tree graph
- .env secure backup
```
---

## 25. 개발 순서

개발 순서는 B가 A의 real eBPF 구현을 기다리지 않도록 구성한다.

```text
1. JSONL schema 확정
2. event.h 작성
3. fake_collector.c 작성
4. jsonl_writer.c 작성
5. main.c에서 --fake, --output, --agent-mode, --target-comm, --project-path option 처리
6. fake JSONL sample 생성
7. app/policy.py 작성
8. app/report.py 기본 HTML 생성
9. app/git_summary.py 작성
10. app/main.py GUI skeleton 작성
11. execve eBPF collector 구현
12. openat eBPF collector 구현
13. GUI Start/Stop과 real engine 연결
14. Commit Safety Report 완성
15. optional: unlinkat 추가
16. clean VM에서 README 기준 재현성 테스트
```

최종 완료 흐름:

```text
GUI에서 Project Path / Target Process 입력
→ Start Monitoring
→ Claude Code 또는 demo script 실행
→ Stop
→ log session 선택
→ Open Commit Safety Report
```
---

## 26. 안전 기준

공모전 demo는 실제 공격 도구처럼 동작하면 안 된다.

금지:

```text
reverse shell 실행
exploit 자동화
권한 상승 시도
persistence 생성
외부 서버로 데이터 전송
실제 secret 출력
실제 SSH key 접근
실제 시스템 파일 변경
사용자 파일 삭제/암호화/변조
```

허용:

```text
project-local sandbox 내부 파일 접근
fake .env 파일 접근
chmod 777 demo/sandbox/test.sh
rm -rf demo/sandbox/build
bash -c 'echo hello'
git status
make --version
python3 --version
curl --version
```

---

## 27. 발표 포인트

### 시스템 관점

- eBPF program이 syscall tracepoint에 attach된다.
- kernel space에서는 event 수집만 수행한다.
- ring buffer를 통해 user-space C engine으로 event를 전달한다.
- user-space 분석 계층이 target process와 child process를 session으로 묶는다.
- Python GUI는 privileged engine을 제어하고 report를 시각화한다.

### 보안 관점

- 레포지토리 내부 파일 수정은 정상 개발 활동으로 분류한다.
- 이상 행위는 악성 확정이 아니라 **검토해야 할 boundary violation**으로 정의한다.
- `.env`, `.ssh`, `/etc/shadow` 등 Git이 추적하지 않는 로컬 리스크를 감시한다.
- 각 finding은 `severity`, `reason`, `recommendation`을 포함한다.

### 제품 관점

- 사용자는 GUI에서 AI Agent monitoring session을 시작/중지할 수 있다.
- 각 session은 JSONL log로 저장된다.
- 저장된 session log는 Commit Safety Report로 열람할 수 있다.
- Report는 syscall log가 아니라 commit 전 검토 가능한 요약 정보를 제공한다.

### 차별점 관점

```text
strace/auditd는 event를 수집한다.
SysGuard는 AI Agent 작업 맥락에서 event를 해석한다.

Git은 레포지토리 내부 변경을 추적한다.
SysGuard는 Git이 못 보는 로컬 시스템 경계 위반을 감시한다.
```

---

## 28. Future Work

```text
kernel-side PID filtering using BPF map
connect syscall 기반 outbound network monitoring
unlinkat/renameat 기반 삭제/rename 정확도 향상
git worktree 기반 safe workspace 생성
allowlist/denylist config
YAML policy parser
real-time GUI alert table
systemd service packaging
privileged backend + unprivileged GUI 분리
eBPF LSM 또는 fanotify 기반 차단 기능
optional secure backup mode for protected local files
```

---

## 29. 최종 완료 기준

- clean Ubuntu VM에서 build 가능
- `make run-fake`로 fake JSONL 생성 가능
- `sudo ./build/sysguard`로 real eBPF mode 실행 가능
- GUI에서 Start/Stop 동작 가능
- GUI에서 `logs/*.jsonl` session 목록 조회 가능
- 선택한 log를 HTML report로 열람 가능
- `execve` event 수집 가능
- `openat` event 수집 가능
- 고정 JSONL schema 출력 가능
- target process 기준 lightweight session filtering 가능
- project boundary 판단 가능
- protected path 접근 탐지 가능
- dangerous command 탐지 가능
- Commit Safety `SAFE/REVIEW_NEEDED/UNSAFE` 판단 가능
- demo script로 harmless 시연 가능
- README만 보고 build/run/demo 재현 가능
