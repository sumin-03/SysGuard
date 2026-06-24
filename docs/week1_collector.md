# Week 1 — Collector / eBPF (담당자 A)

## 목표
1주차 A의 목표는 탐지 로직 완성이 아니라 **eBPF 빌드 파이프라인을 뚫어놓는 것**이다:
libbpf 구조 이해 → skeleton build 실험 → ring buffer로 event 1건 전달 PoC.

## 환경 준비

### 필수 도구 설치
```bash
sudo apt update
sudo apt install -y clang llvm bpftool libbpf-dev \
  linux-headers-$(uname -r) make gcc
```
> WSL2에서는 `linux-headers-$(uname -r)`가 apt에 없을 수 있다. CO-RE는
> `/sys/kernel/btf/vmlinux`(BTF)만 있으면 동작하므로 headers 설치 실패는 무시 가능.

### BTF 확인 (CO-RE 전제)
```bash
ls -l /sys/kernel/btf/vmlinux   # 현재 환경: 존재함 ✅
```

### vmlinux.h 생성
Makefile이 자동 생성하지만 수동으로도 가능:
```bash
make vmlinux            # == bpftool btf dump file /sys/kernel/btf/vmlinux format c > bpf/vmlinux.h
```
`bpf/vmlinux.h`는 머신별로 다르고 크므로 git에 커밋하지 않는다(.gitignore 처리됨).

## libbpf / skeleton 동작 흐름

```
bpf/sysguard.bpf.c
   │  clang -target bpf -c          (eBPF 바이트코드로 컴파일)
   ▼
build/sysguard.bpf.o
   │  bpftool gen skeleton
   ▼
build/sysguard.skel.h               (open/load/attach/destroy + map 핸들 코드 생성)
   │  #include 후 유저스페이스에서 링크
   ▼
유저스페이스 (src/bpf_collector.c)
   sysguard_bpf__open_and_load()    # 프로그램/맵을 커널에 로드
   sysguard_bpf__attach()           # tracepoint에 attach
   ring_buffer__new(... maps.events)# ring buffer consumer 생성
   ring_buffer__poll()              # event 수신 → 콜백
   sysguard_bpf__destroy()
```

- **kernel space**: tracepoint(`sys_enter_execve`)에서 `sysguard_event`를 채워
  `bpf_ringbuf_reserve/submit`으로 ring buffer에 적재 (수집만, 판정 없음).
- **user space**: ring buffer를 poll해서 event를 받아 콜백으로 넘김.
  2주차부터 이 콜백 자리에 B의 rule engine / JSONL writer가 들어간다.
- skeleton 구조체/함수 이름(`sysguard_bpf`, `sysguard_bpf__open_and_load` 등)은
  BPF 오브젝트 파일명(`sysguard.bpf.o`)에서 자동 파생된다.

## 빌드 / 실행

```bash
make           # eBPF 컴파일 + skeleton 생성  (1주차 핵심 산출물)
make poc       # 독립 collector PoC 바이너리 빌드 (build/sysguard_poc)
make run-poc   # sudo로 PoC 실행 → 다른 셸에서 명령 실행 시 EXEC event 출력
```

`make run-poc` 후 다른 터미널에서 `ls`, `cat /etc/passwd` 등을 실행하면:
```
[EXEC] pid=12345 ppid=6789 uid=1000 comm=ls exe=/usr/bin/ls
```
형태로 출력되면 수집 경로가 끝까지 동작하는 것이다. Ctrl-C로 종료.

## 1주차 완료 체크리스트
- [ ] clang / bpftool 설치 및 동작 확인
- [ ] `make vmlinux`로 bpf/vmlinux.h 생성
- [ ] `make`가 skeleton 생성 단계까지 무에러 통과
- [ ] `make run-poc`로 execve event가 ring buffer를 통해 출력됨
- [ ] `struct sysguard_event` 인터페이스를 B와 확정 (src/event.h)

## 알려진 리스크 / 메모
- **WSL2**: tracepoint attach가 환경에 따라 제한될 수 있음. 막히면 최종 시연
  재현성을 위해 clean Ubuntu VM을 별도 확보(README 24장 요구사항).
- 2주차: argv 수집 정교화 + JSONL writer(B)와 콜백 연동.
- 4주차: `openat` tracepoint 추가(`SYSGUARD_EVENT_OPEN`, `path`/`flags` 채움).
