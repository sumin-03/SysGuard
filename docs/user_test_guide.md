# SysGuard 사용자 테스트 가이드

실제 사용자(= AI Agent에게 개발 작업을 시키는 개발자) 시점에서 SysGuard가
제대로 동작하는지 확인하는 가이드다. 시나리오 1부터 순서대로 진행한다.

사용자 스토리:

```text
개발자가 Claude Code에게 작업을 시킨다.
→ SysGuard로 그 세션을 감시한다.
→ 커밋 전에 Commit Safety Report를 열어 SAFE/REVIEW_NEEDED/UNSAFE를 확인한다.
```

---

## 0. 사전 준비 (약 2분)

```bash
cd ~/sumin/SysGuard
make sysguard        # 주의: `make`만 치면 skeleton까지만 빌드됨
ls build/sysguard    # 바이너리 존재 확인
```

체크리스트:

- [ ] `build/sysguard` 파일이 존재한다
- [ ] 빌드 에러가 없다 (경고 1건은 무해)

---

## 1. 시나리오 1 — GUI 기본 흐름 (fake mode, root 불필요, 약 3분)

**목적:** eBPF 없이 GUI의 Start → Stop → Report 흐름만 먼저 확인한다.

```bash
python3 app/main.py
```

1. **"Use fake collector" 체크박스가 켜져 있는지 확인** (기본값 ON)
2. Target Process는 기본값 `claude` 그대로 둔다
3. **▶ Start Monitoring** 클릭 → 상태줄에 `Monitoring... PID=...` 표시
4. 몇 초 뒤 fake collector가 스스로 종료됨 → 상태가 `Stopped`로 바뀜
5. 로그 목록에 `session_claude_YYYYMMDD_HHMMSS.jsonl`이 생겼는지 확인
   (안 보이면 **🔄 Refresh** 클릭)
6. 목록에서 그 세션을 클릭 선택 → **📄 Open Report** 클릭
7. 브라우저에 Commit Safety Report가 열린다

체크리스트:

- [ ] Start/Stop 시 상태줄이 바뀐다
- [ ] 세션 로그가 목록에 나타난다
- [ ] 리포트가 브라우저에 열린다
- [ ] 리포트에 **Commit Safety: UNSAFE** 배지가 보인다
      (fake 데이터에 AWS credential 접근 등이 섞여 있으므로 UNSAFE가 정답)

---

## 2. 시나리오 2 — 정상 개발 활동 감시 (real eBPF, 약 5분)

**목적:** 정상적인 개발 활동만 있으면 **SAFE** 판정이 나오는지 확인한다.

real eBPF 모드는 root가 필요하므로 GUI를 sudo로 실행한다:

```bash
sudo python3 app/main.py
```

1. **"Use fake collector" 체크 해제**
2. Target Process에 `bash` 입력 (demo 스크립트가 bash로 돌기 때문)
3. Project Path가 `/home/sumin/sumin/SysGuard`인지 확인
4. **▶ Start Monitoring** 클릭
5. **이미 열려 있는** 다른 터미널에서 실행
   (⚠️ 새 터미널을 열면 그 bash의 시작 과정까지 감시에 잡힌다):

   ```bash
   cd ~/sumin/SysGuard
   bash demo/agent_normal_simulator.sh
   ```

6. `[demo] Done` 이 출력되면 GUI에서 **■ Stop** 클릭
7. 새 세션 선택 → **📄 Open Report**

체크리스트:

- [ ] 리포트에 **Commit Safety: SAFE** 가 표시된다
- [ ] Normal Development Activity에 `cat`, `git status`, `make --version` 등이 보인다
- [ ] Boundary Violation / Protected Path / Dangerous Command 섹션이 비어 있다

> sudo GUI에서 브라우저가 안 열리면: 일반 사용자 터미널에서
> `xdg-open logs/session_bash_*.html` 로 직접 연다.

---

## 3. 시나리오 3 — 위험 행위 감시 (real eBPF, 약 5분)

**목적:** 경계 위반 행위가 있으면 **UNSAFE** 판정이 나오는지 확인한다.

시나리오 2와 같은 방법으로 Start한 뒤, 터미널에서:

```bash
cd ~/sumin/SysGuard
bash demo/agent_boundary_violation_simulator.sh
```

Stop → 세션 선택 → Open Report.

체크리스트:

- [ ] 리포트에 **Commit Safety: UNSAFE** 가 표시된다
- [ ] Protected Path 섹션에 `demo/sandbox_risky/.env` 접근이 보인다
- [ ] Dangerous Command 섹션에 `chmod 777`, `rm -rf` 가 보인다
- [ ] Recommended Actions에 `.env`/API key 관련 안내가 보인다

---

## 4. 시나리오 4 — 실제 Claude Code 감시 (핵심 시나리오, 약 10분)

**목적:** 진짜 AI Agent를 감시하는 본래 목적대로 동작하는지 확인한다.

1. `sudo python3 app/main.py` 실행
2. "Use fake collector" 체크 해제, Target Process에 `claude` 입력
3. **▶ Start Monitoring** 클릭
4. **이미 열려 있는** 터미널에서 Claude Code를 실행하고 아무 작업이나 시킨다:

   ```bash
   cd ~/sumin/SysGuard
   claude
   # 예: "README.md를 읽고 요약해줘" 또는 "src/ 코드 구조를 설명해줘"
   ```

5. 작업이 끝나면 Claude Code 종료 → GUI에서 **■ Stop**
6. 세션 선택 → **📄 Open Report**

체크리스트:

- [ ] Claude가 실행한 명령(execve)과 열어본 파일(openat)이 리포트에 나온다
- [ ] 읽기 전용 작업만 시켰다면 SAFE, 프로젝트 밖 파일을 건드렸으면
      UNSAFE/REVIEW_NEEDED로 판정이 바뀐다
- [ ] (심화) Claude에게 일부러 `cat ~/.bashrc` 같은 프로젝트 밖 작업을 시키면
      Boundary Violation으로 잡히는지 확인

---

## 5. 자주 걸리는 문제

| 증상 | 원인 / 해결 |
|---|---|
| fake 체크 해제 후 Start 누르면 바로 종료됨 (0 byte 로그) | GUI를 sudo 없이 실행함. real eBPF 모드는 `sudo python3 app/main.py` 필요 |
| GUI 로그 목록에 세션이 안 보임 | 목록은 `logs/session_*.jsonl` 패턴만 표시. Refresh 클릭 |
| real mode인데 이벤트가 0건 | Target Process 이름 오타, 또는 target 프로세스를 모니터링 시작 **전에** 이미 실행해 둔 경우 (시작 후 실행해야 잡힘) |
| SAFE여야 하는데 boundary violation이 잡힘 | 모니터링 중 새 터미널을 열어 `.bashrc` 읽기가 잡힌 것. 기존 터미널 사용 |
| sudo GUI에서 리포트가 브라우저에 안 열림 | 일반 사용자로 `xdg-open logs/<세션>.html` 직접 실행 |
| 리포트 생성 에러 | 모니터가 아직 실행 중인 상태에서 열었을 수 있음. Stop 먼저 확인 (`pgrep sysguard`) |
| Stop을 잊고 계속 켜둠 | 이후의 모든 셸 활동이 로그에 섞임. `pgrep sysguard`로 확인 후 종료 |

---

## 6. 성공 기준 요약

```text
시나리오 1: GUI 흐름 동작 + fake 리포트 UNSAFE
시나리오 2: 정상 demo → SAFE
시나리오 3: 위험 demo → UNSAFE (.env / chmod 777 / rm -rf 탐지)
시나리오 4: 실제 Claude Code 세션이 리포트로 요약됨
```

네 가지가 모두 통과하면 README 29장의 최종 완료 기준 중
사용자 시나리오 부분이 충족된 것이다.
