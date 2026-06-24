# SysGuard

**eBPF/libbpf 기반 Linux Process/File Access 이상행위 탐지 시스템 + GUI Report Viewer**

SysGuard는 Linux kernel의 `execve`, `openat` syscall event를 eBPF로 수집하고, user-space C engine에서 rule 기반으로 의심 행위를 탐지하는 경량 runtime security monitor이다.

공모전 시연에서는 사용자가 직접 조작할 수 있는 GUI를 제공한다. GUI에서 monitoring을 Start/Stop하고, 수집된 log session 목록을 확인하며, 선택한 log를 HTML report로 열람할 수 있다.

---

## 1. 완성품 형태

SysGuard는 내부적으로 두 부분으로 나뉜다.

```text
SysGuard Monitor App
├── Python GUI wrapper
│   ├── Start Monitoring button
│   ├── Stop button
│   ├── Refresh Logs button
│   ├── Log session list
│   └── Open HTML Report button
│
└── C/eBPF monitoring engine
    ├── eBPF syscall collector
    ├── libbpf loader
    ├── ring buffer reader
    ├── rule engine
    ├── CLI alert output
    └── JSONL log writer
```

핵심 원칙은 다음과 같다.

```text
GUI는 eBPF를 직접 다루지 않는다.
GUI는 C/eBPF engine을 실행/종료하고, 생성된 JSONL log를 HTML report로 보여준다.
```

---

## 2. 프로젝트 목표

### 핵심 목표

- Linux process execution event 수집
- Linux file access event 수집
- 의심 명령 실행 탐지
- 민감 파일 접근 탐지
- CLI alert 출력
- JSONL session log 생성
- GUI 기반 Start/Stop 제어
- GUI 기반 log session 목록 조회
- 선택한 log를 HTML report로 변환 및 표시
- harmless demo script 기반 재현 가능한 시연

### MVP 범위

| 구분 | 내용 |
|---|---|
| 감시 대상 syscall | `execve`, `openat` |
| 수집 방식 | eBPF tracepoint |
| engine | C + libbpf |
| GUI | Python wrapper app |
| event 전달 | BPF ring buffer |
| 탐지 방식 | built-in rule 기반 |
| log format | JSONL |
| report | HTML |
| 시연 | harmless command 기반 demo script |

---

## 3. 하지 않는 것

5주 MVP에서는 아래 기능을 제외한다.

| 제외 기능 | 제외 이유 |
|---|---|
| `connect` syscall 탐지 | IPv4/IPv6 decoding과 테스트 부담 증가 |
| 실시간 Web dashboard | GUI와 engine 동기화 부담 증가 |
| C 기반 GUI | GTK/Qt C API 학습 부담 증가 |
| YAML rule parser | C에서 parser 구현 부담 증가 |
| SQLite 저장 | JSONL로 충분 |
| ML anomaly detection | 데이터셋 부족, 설명 가능성 낮음 |
| 차단 기능 | LSM eBPF, seccomp, fanotify permission event 등 별도 설계 필요 |
| 모든 syscall 감시 | event 폭증 및 false positive 증가 |

---

## 4. 전체 아키텍처

```text
[Other Processes]
  bash, curl, cat, python, etc.
        |
        | execve(), openat()
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
[Python GUI Wrapper]
  Start / Stop
  Log session list
  JSONL -> HTML report
  Open report
```

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
- `bpftool gen skeleton` 기반 build 구성
- `src/bpf_collector.c`에서 ring buffer event 수신
- real eBPF mode 안정화

완료 기준:

```text
sudo ./build/sysguard --output logs/session_test.jsonl
실행 후 bash, curl, cat /etc/passwd 같은 실제 행위가 event 또는 alert로 출력된다.
```

### 담당자 B: Rule Engine / Report / GUI

**역할:** 수집된 event를 보안적으로 해석하고 사용자에게 alert/report로 보여준다.

주요 작업:

- `src/event.h` 작성
- `src/alert.h` 작성
- `src/fake_collector.c` 작성
- `src/rules.c` 작성
- CLI alert 출력
- JSONL writer 구현
- `app/main.py` GUI 작성
- `app/report.py` JSONL to HTML report 구현
- demo script 작성
- README 및 발표용 sample report 정리

완료 기준:

```text
./build/sysguard --fake --output logs/session_fake.jsonl
실행 후 fake event 기반 alert가 출력되고,
GUI에서 해당 log를 선택해 HTML report로 볼 수 있다.
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
│   ├── report.py              # JSONL to HTML report generator
│   └── README.md              # GUI usage note
├── logs/
│   ├── session_*.jsonl        # monitoring session logs
│   └── session_*.html         # generated reports
├── build/
│   └── generated files and sysguard binary
├── demo/
│   └── benign_simulator.sh
├── reports/
│   └── sample_alerts.jsonl
├── docs/
│   ├── architecture.md
│   └── rules.md
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
};

// Normalized event consumed by the rule engine.
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

    // Open event fields.
    char path[SYSGUARD_MAX_PATH];
    int32_t flags;
};

#endif
```

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

## 10. 이상행위 기준

SysGuard에서 이상행위는 악성행위의 확정 판정이 아니다.

본 프로젝트에서는 이상행위를 다음과 같이 정의한다.

> Linux 환경에서 침해 사고, 권한 상승, 정보 탈취, 컨테이너 오남용과 연관될 가능성이 높은 syscall event 또는 event sequence

### 기준 1: 민감 자원 접근

```text
/etc/shadow
/etc/sudoers
/var/run/docker.sock
/home/*/.ssh/id_rsa
```

### 기준 2: 위험 command 실행

```text
bash, sh, zsh
nc, netcat, ncat
curl, wget
python, perl, ruby
```

### 기준 3: 정책 위반

```text
일반 사용자 프로세스가 /etc/shadow 접근
non-allowlisted process가 Docker socket 접근
학생 실습 VM에서 netcat 실행
```

### 기준 4: event sequence

MVP에서는 optional이다.

```text
curl 실행 → shell 실행
shell 실행 → 민감 파일 접근
```

---

## 11. MVP Rule 목록

| Rule ID | Event | Severity | 설명 |
|---|---|---|---|
| `shell-exec` | `execve` | medium | shell process 실행 |
| `suspicious-netcat` | `execve` | high | netcat 계열 command 실행 |
| `downloader-exec` | `execve` | medium | `curl`, `wget` 실행 |
| `sensitive-shadow-access` | `openat` | critical | `/etc/shadow` 접근 |
| `sudoers-access` | `openat` | high | `/etc/sudoers` 접근 |
| `docker-sock-access` | `openat` | high | Docker socket 접근 |
| `ssh-key-access` | `openat` | high | SSH private key 접근 |

Optional rule:

| Rule ID | Event | Severity | 설명 |
|---|---|---|---|
| `download-and-shell` | sequence | high | downloader 실행 후 shell 실행 |

---

## 12. Build Requirements

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

## 13. Build & Run

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

GUI mode:

```bash
# Run GUI wrapper.
sudo python3 app/main.py
```

공모전 demo에서는 eBPF load 권한 문제를 단순화하기 위해 GUI를 `sudo`로 실행한다. 실서비스 수준에서는 GUI와 privileged backend를 분리하는 구조가 필요하다.

---

## 14. GUI 동작 방식

### Start Monitoring

```text
Start button 클릭
→ logs/session_YYYYMMDD_HHMMSS.jsonl 생성
→ ./build/sysguard --output logs/session_YYYYMMDD_HHMMSS.jsonl 실행
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
→ file name, modified time, alert count, critical/high count 표시
```

### Open HTML Report

```text
선택한 JSONL log 읽기
→ HTML report 생성
→ logs/session_YYYYMMDD_HHMMSS.html 저장
→ browser 또는 GUI WebView로 열기
```

---

## 15. GUI 화면 MVP

```text
+------------------------------------------------------+
| SysGuard Monitor                                    |
| eBPF Linux Runtime Security Monitor                 |
+------------------------------------------------------+
| [ Start Monitoring ] [ Stop ] [ Refresh Logs ]      |
| Status: Stopped                                     |
+------------------------------------------------------+
| Log Sessions                                        |
|------------------------------------------------------|
| session_20260624_142100.jsonl | 12 alerts | 2 crit  |
| session_20260624_143500.jsonl |  8 alerts | 1 crit  |
| session_20260624_151000.jsonl | 15 alerts | 3 crit  |
+------------------------------------------------------+
| [ Open HTML Report ]                                |
+------------------------------------------------------+
```

---

## 16. HTML Report 구성

HTML report는 선택한 JSONL session을 사람이 보기 쉽게 요약한다.

포함 항목:

```text
1. Session file name
2. Total alert count
3. Severity summary
4. Rule별 발생 횟수
5. Recent alert table
6. Reason
7. Recommendation
```

예시:

```text
SysGuard Report

Total alerts: 12
Critical: 2
High: 4
Medium: 6

Recent Alerts
- [critical] sensitive-shadow-access pid=18345 comm=cat
- [high] docker-sock-access pid=18350 comm=python
- [medium] downloader-exec pid=18331 comm=curl
```

---

## 17. Makefile 예시

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

.PHONY: all clean run-fake run-real run-gui

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

# Run GUI wrapper.
run-gui: $(BIN)
	mkdir -p logs
	sudo python3 app/main.py

clean:
	rm -rf build
```

---

## 18. Demo Script

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

GUI 시연 순서:

```text
1. sudo python3 app/main.py
2. Start Monitoring 클릭
3. demo/benign_simulator.sh 실행
4. Stop 클릭
5. Refresh Logs 클릭
6. 생성된 session log 선택
7. Open HTML Report 클릭
```

---

## 19. 5주 개발 계획

| 주차 | 담당자 A | 담당자 B | 완료 기준 |
|---|---|---|---|
| Week 1 | libbpf-bootstrap 구조 파악, skeleton build 실험 | C fake collector, event/alert/rule engine | `make run-fake`로 alert 출력 |
| Week 2 | `execve` tracepoint PoC | CLI 출력, JSONL writer, GUI skeleton | fake mode에서 JSONL 생성, GUI 실행 |
| Week 3 | ring buffer event decode, 실제 `execve` 통합 | log 목록, HTML report generator | 실제 `bash`, `curl` alert, report 생성 |
| Week 4 | `openat` tracepoint, path 수집 | sensitive file rule, GUI Start/Stop 안정화 | `/etc/shadow`, Docker socket alert |
| Week 5 | Ubuntu VM 재현성, Makefile 정리 | README, sample report, 발표자료, demo flow | GUI에서 Start→Stop→Report 시연 가능 |

---

## 20. 개발 순서

```text
1. event.h 작성
2. alert.h 작성
3. fake_collector.c 작성
4. rules.c 작성
5. main.c에서 --fake mode 실행
6. JSONL writer 추가
7. app/report.py 작성
8. app/main.py GUI skeleton 작성
9. demo script 작성
10. execve eBPF collector 구현
11. openat eBPF collector 구현
12. GUI Start/Stop과 real engine 연결
13. README 기준으로 clean VM 재현성 테스트
```

최종 완료 흐름:

```text
GUI에서 Start Monitoring
→ demo script 실행
→ Stop
→ log session 선택
→ Open HTML Report
```

---

## 21. 안전 기준

공모전 demo는 실제 공격 도구처럼 동작하면 안 된다.

금지:

```text
reverse shell 실행
exploit 자동화
권한 상승 시도
persistence 생성
외부 서버로 데이터 전송
파일 삭제/암호화/변조
```

허용:

```text
bash -c 'echo hello'
cat /etc/passwd >/dev/null
curl --version
ls -l /var/run/docker.sock
```

---

## 22. 발표 포인트

### 시스템 관점

- eBPF program이 syscall tracepoint에 attach된다.
- kernel space에서는 event 수집만 수행한다.
- ring buffer를 통해 user-space C engine으로 event를 전달한다.
- C engine이 rule engine을 통해 alert를 생성한다.
- Python GUI는 privileged engine을 제어하고 report를 시각화한다.

### 보안 관점

- 이상행위는 악성 확정이 아니라 조사할 가치가 있는 suspicious behavior로 정의한다.
- `execve` 기반으로 의심 command 실행을 탐지한다.
- `openat` 기반으로 민감 파일 접근을 탐지한다.
- 각 alert는 `severity`, `reason`, `recommendation`을 제공한다.

### 제품 관점

- 사용자는 GUI에서 monitoring session을 시작/중지할 수 있다.
- 각 session은 JSONL log로 저장된다.
- 저장된 session log는 HTML report로 열람할 수 있다.
- CLI와 GUI를 모두 지원하므로 개발/시연/디버깅이 분리된다.

---

## 23. Future Work

```text
connect syscall 기반 outbound network monitoring
download-and-shell sequence rule
process tree correlation
allowlist/denylist config
YAML rule parser
real-time GUI alert table
systemd service packaging
privileged backend + unprivileged GUI 분리
eBPF LSM 기반 차단 기능
```

---

## 24. 최종 완료 기준

- clean Ubuntu VM에서 build 가능
- `make run-fake`로 fake alert 출력 가능
- `sudo ./build/sysguard`로 real eBPF mode 실행 가능
- GUI에서 Start/Stop 동작 가능
- GUI에서 `logs/*.jsonl` session 목록 조회 가능
- 선택한 log를 HTML report로 열람 가능
- `execve` event 수집 가능
- `openat` event 수집 가능
- 최소 5개 rule alert 재현 가능
- JSONL report 생성 가능
- demo script로 harmless 시연 가능
- README만 보고 build/run/demo 재현 가능
