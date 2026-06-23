# SysGuard

**eBPF/libbpf 기반 Linux Process/File Access 이상행위 탐지 시스템**

SysGuard는 Linux kernel의 `execve`, `openat` syscall event를 eBPF로 수집하고, user-space C daemon에서 rule 기반으로 의심 행위를 탐지하는 경량 runtime security monitor이다.

본 프로젝트는 차단형 보안 솔루션이 아니라, **실행 행위와 민감 파일 접근을 실시간으로 관찰하고 alert/report를 제공하는 탐지형 보안 모니터**를 목표로 한다.

---

## 1. 프로젝트 목표

공모전 목표에 맞춰 실생활 Linux 환경에서 적용 가능한 보안 모니터링 소프트웨어를 설계하고 구현한다.

### 핵심 목표

- Linux process execution event 수집
- Linux file access event 수집
- 의심 명령 실행 탐지
- 민감 파일 접근 탐지
- CLI alert 출력
- JSONL report 생성
- harmless demo script 기반 재현 가능한 시연

### MVP 범위

| 구분 | 내용 |
|---|---|
| 감시 대상 syscall | `execve`, `openat` |
| 수집 방식 | eBPF tracepoint |
| user-space | C + libbpf |
| event 전달 | BPF ring buffer |
| 탐지 방식 | built-in rule 기반 |
| 출력 | CLI, JSONL |
| 시연 | harmless command 기반 demo script |

---

## 2. 프로젝트에서 하지 않는 것

5주 MVP에서는 아래 기능을 제외한다.

| 제외 기능 | 제외 이유 |
|---|---|
| `connect` syscall 탐지 | IPv4/IPv6 decoding, endian 처리, 테스트 부담 증가 |
| TUI/Web dashboard | 핵심 기능보다 UI에 시간이 많이 소요됨 |
| YAML rule parser | C에서 parser 구현 부담 증가 |
| SQLite 저장 | JSONL로 충분 |
| ML anomaly detection | 데이터셋 부족, 설명 가능성 낮음 |
| 차단 기능 | LSM eBPF, seccomp, fanotify permission event 등 별도 설계 필요 |
| 모든 syscall 감시 | event 폭증 및 false positive 증가 |

---

## 3. 전체 아키텍처

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
[User-space SysGuard Daemon]
  libbpf loader
  ring buffer reader
  event decoder
  rule engine
  alert manager
  CLI / JSONL output
```

### 핵심 개념

- eBPF program은 kernel space에서 syscall event를 관찰한다.
- SysGuard daemon은 user space에서 event를 받아 rule을 평가한다.
- eBPF는 판단 로직을 최소화하고, 보안 판단은 user-space rule engine이 수행한다.

---

## 4. 기술 스택

| 영역 | 기술 |
|---|---|
| eBPF program | C |
| user-space daemon | C |
| eBPF loader | libbpf |
| skeleton 생성 | bpftool gen skeleton |
| compiler | clang |
| build | Makefile |
| output | CLI, JSONL |
| demo | Bash script |

---

## 5. 역할 분담

### 담당자 A: eBPF / Collector

**역할:** 커널에서 syscall event를 수집해 user-space로 전달한다.

주요 작업:

- `bpf/sysguard.bpf.c` 작성
- `execve` tracepoint attach
- `openat` tracepoint attach
- BPF ring buffer로 event 전달
- `bpftool gen skeleton` 기반 build 구성
- `src/bpf_collector.c`에서 ring buffer event 수신
- kernel event를 `struct sysguard_event`로 전달

완료 기준:

```text
sudo ./build/sysguard
실행 후 bash, curl, cat /etc/shadow 같은 실제 행위가 event로 출력된다.
```

### 담당자 B: Rule Engine / Alert / Report

**역할:** 수집된 event를 보안적으로 해석하고 사용자에게 alert로 보여준다.

주요 작업:

- `src/event.h` 작성
- `src/alert.h` 작성
- `src/fake_collector.c` 작성
- `src/rules.c` 작성
- CLI alert 출력
- JSONL writer 구현
- demo script 작성
- README 및 발표용 sample report 정리

완료 기준:

```text
./build/sysguard --fake
실행 후 fake event 기반 alert가 출력되고 JSONL report가 생성된다.
```

---

## 6. 디렉터리 구조

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
├── build/
│   └── generated files
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

## 7. Event Interface

`struct sysguard_event`는 담당자 A와 B 사이의 공통 계약이다.

담당자 A는 이 구조체를 생산하고, 담당자 B는 이 구조체를 소비한다.

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
// The eBPF collector produces this structure.
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

## 8. Alert Interface

`struct sysguard_alert`는 rule engine이 생성하는 최종 보안 결과이다.

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
// This is the final product-level result shown to users.
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

## 9. 이상행위 기준

SysGuard에서 이상행위는 악성행위의 확정 판정이 아니다.

본 프로젝트에서는 이상행위를 다음과 같이 정의한다.

> Linux 환경에서 침해 사고, 권한 상승, 정보 탈취, 컨테이너 오남용과 연관될 가능성이 높은 syscall event 또는 event sequence

### 기준 1: 민감 자원 접근

예시:

```text
/etc/shadow
/etc/sudoers
/var/run/docker.sock
/home/*/.ssh/id_rsa
```

### 기준 2: 위험 command 실행

예시:

```text
bash, sh, zsh
nc, netcat, ncat
curl, wget
python, perl, ruby
```

### 기준 3: 정책 위반

예시:

```text
일반 사용자 프로세스가 /etc/shadow 접근
non-allowlisted process가 Docker socket 접근
학생 실습 VM에서 netcat 실행
```

### 기준 4: event sequence

MVP에서는 optional이다.

예시:

```text
curl 실행 → shell 실행
shell 실행 → 민감 파일 접근
```

---

## 10. MVP Rule 목록

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

## 11. Build Requirements

Ubuntu VM 기준으로 개발한다.

필수 도구:

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
  linux-headers-$(uname -r)
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

## 12. Build

```bash
# Build SysGuard.
make
```

Fake mode 실행:

```bash
# Run without eBPF.
./build/sysguard --fake
```

Real eBPF mode 실행:

```bash
# Run real eBPF collector.
sudo ./build/sysguard
```

JSONL report 생성:

```bash
# Save alerts to a JSONL file.
sudo ./build/sysguard --output reports/alerts.jsonl
```

---

## 13. Makefile 예시

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

.PHONY: all clean run-fake run-real

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
	./$(BIN) --fake

# Run real eBPF collector.
run-real: $(BIN)
	sudo ./$(BIN)

clean:
	rm -rf build
```

---

## 14. Demo Script

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

실행:

```bash
# Terminal 1
sudo ./build/sysguard --output reports/demo_alerts.jsonl

# Terminal 2
chmod +x demo/benign_simulator.sh
./demo/benign_simulator.sh
```

---

## 15. 사용 예시

```text
[medium] shell-exec pid=18320 uid=1000 comm=bash
  reason: Shell process was executed.
  recommendation: Verify whether this shell execution is expected.

[medium] downloader-exec pid=18331 uid=1000 comm=curl
  reason: Downloader command was executed.
  recommendation: Check whether this download activity is expected.

[critical] sensitive-shadow-access pid=18345 uid=0 comm=cat
  reason: Process accessed /etc/shadow, which contains password hash data.
  recommendation: Verify the process identity and whether this access is expected.
```

JSONL 예시:

```json
{"severity":"medium","rule_id":"shell-exec","pid":18320,"uid":1000,"comm":"bash","reason":"Shell process was executed.","recommendation":"Verify whether this shell execution is expected."}
{"severity":"critical","rule_id":"sensitive-shadow-access","pid":18345,"uid":0,"comm":"cat","reason":"Process accessed /etc/shadow, which contains password hash data.","recommendation":"Verify the process identity and whether this access is expected."}
```

---

## 16. 5주 개발 계획

| 주차 | 담당자 A | 담당자 B | 완료 기준 |
|---|---|---|---|
| Week 1 | libbpf-bootstrap 구조 파악, skeleton build 실험 | C fake collector, event/alert/rule engine | `make run-fake`로 alert 출력 |
| Week 2 | `execve` tracepoint PoC | CLI 출력, JSONL writer | fake mode에서 JSONL 생성 |
| Week 3 | ring buffer event decode, 실제 `execve` 통합 | exec rule 정리, demo script 1차 | 실제 `bash`, `curl` alert |
| Week 4 | `openat` tracepoint, path 수집 | sensitive file rule 구현 | `/etc/shadow`, Docker socket alert |
| Week 5 | Ubuntu VM 재현성, Makefile 정리 | README, sample report, 발표자료 | README만 보고 demo 재현 |

---

## 17. 개발 순서

처음부터 eBPF를 완성하려고 하지 않는다.

권장 순서:

```text
1. event.h 작성
2. alert.h 작성
3. fake_collector.c 작성
4. rules.c 작성
5. main.c에서 --fake mode 실행
6. JSONL writer 추가
7. demo script 작성
8. execve eBPF collector 구현
9. openat eBPF collector 구현
10. README 기준으로 clean VM 재현성 테스트
```

첫 번째 완료 목표:

```bash
make run-fake
```

두 번째 완료 목표:

```bash
sudo ./build/sysguard
```

---

## 18. 안전 기준

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

SysGuard는 실제 악성행위 실행을 요구하지 않고, harmless command로도 탐지 rule을 재현할 수 있어야 한다.

---

## 19. 발표 포인트

### 시스템 관점

- eBPF program이 syscall tracepoint에 attach된다.
- kernel space에서는 event 수집만 수행한다.
- ring buffer를 통해 user-space로 event를 전달한다.
- user-space daemon이 rule engine을 통해 alert를 생성한다.

### 보안 관점

- 이상행위는 악성 확정이 아니라 조사할 가치가 있는 suspicious behavior로 정의한다.
- `execve` 기반으로 의심 command 실행을 탐지한다.
- `openat` 기반으로 민감 파일 접근을 탐지한다.
- 각 alert는 `severity`, `reason`, `recommendation`을 제공한다.

### 공모전 관점

- 2인 역할 분담이 명확하다.
- 5주 안에 구현 가능한 MVP로 범위를 제한했다.
- CLI/JSONL/demo script로 재현 가능한 시연이 가능하다.
- 향후 `connect`, sequence correlation, TUI, 차단 기능으로 확장할 수 있다.

---

## 20. Future Work

5주 MVP 이후 확장 가능한 기능:

```text
connect syscall 기반 outbound network monitoring
download-and-shell sequence rule
process tree correlation
allowlist/denylist config
YAML rule parser
TUI dashboard
systemd service packaging
eBPF LSM 기반 차단 기능
```

---

## 21. 최종 완료 기준

프로젝트는 아래 조건을 만족하면 완료로 본다.

- clean Ubuntu VM에서 build 가능
- `make run-fake`로 fake alert 출력 가능
- `sudo ./build/sysguard`로 real eBPF mode 실행 가능
- `execve` event 수집 가능
- `openat` event 수집 가능
- 최소 5개 rule alert 재현 가능
- JSONL report 생성 가능
- demo script로 harmless 시연 가능
- README만 보고 build/run/demo 재현 가능
