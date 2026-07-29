# SysGuard 시연 시나리오

발표용 진행 대본. **총 8분**(질의응답 별도) 기준이며, 시간이 부족하면 Act 3까지만 해도 이야기가 완결된다.

핵심 메시지 한 줄:

> **Git은 저장소 안에서 무엇이 바뀌었는지 보여준다. SysGuard는 그 과정에서 AI 에이전트가 무엇을 했는지 보여준다.**

---

## 0. 사전 준비 (발표 30분 전)

```bash
cd ~/SysGuard
make clean && make                      # 무경고 빌드 확인
make test-c                             # C rule tests: all passed
python3 -m unittest discover -s tests -t .   # OK (실패 0건)
```

- [ ] **오래된 로그 정리** — `logs/` 에 큰 세션이 남아 있으면 GUI 첫 스캔이 느려진다
  ```bash
  mkdir -p logs/archive && mv logs/session_*.jsonl logs/session_*.html logs/archive/ 2>/dev/null
  ```
- [ ] **라이브 eBPF 동작 확인** (필수 — 이게 안 되면 Act 2·3을 fake로 대체해야 한다)
  ```bash
  sudo ./build/sysguard --fake --project-path "$(pwd)" --output /tmp/preflight.jsonl >/dev/null && echo OK
  sudo ./build/sysguard --target-comm bash --project-path "$(pwd)" --output /tmp/live.jsonl &
  sleep 2; touch /tmp/sg_probe && kill %1; grep -c . /tmp/live.jsonl   # 0보다 커야 한다
  ```
- [ ] **터미널 2개 + 브라우저** 배치. 왼쪽=수집기, 오른쪽=에이전트/시뮬레이터
- [ ] 글꼴 크게 (터미널 16pt 이상), 브라우저 확대 125%
- [ ] **백업 산출물** — 라이브가 실패할 때 즉시 열 수 있도록 미리 생성한 리포트를 준비해 둔다

---

## Act 1 — 문제 제기 (1분, 말로만)

터미널에 이것만 띄워놓고 시작한다.

```bash
git status --short
```

> "AI 에이전트에게 작업을 시키고 나면 우리는 `git status`로 확인합니다. 그런데 **여기 안 나오는 일**들이 있습니다.
> 에이전트가 저장소 밖 파일을 읽었는지, 만들었다 지운 파일이 있었는지, 쉘 시작 파일에 뭔가 심었는지 —
> Git은 알려주지 않습니다. SysGuard는 커널에서 syscall을 잡아서 그걸 봅니다."

---

## Act 2 — 정상 세션은 조용하다 (2분)

> "먼저 보여드릴 건 **오탐이 없다**는 겁니다. 보안 도구가 매번 경고하면 아무도 안 봅니다."

**왼쪽 터미널** — 수집 시작:
```bash
sudo ./build/sysguard --agent-mode --target-comm claude \
  --project-path "$(pwd)" --output logs/demo_normal.jsonl
```

**오른쪽 터미널** — 에이전트에게 읽기 작업만 시킨다:
```bash
claude
```
> 프롬프트: `read README.md`

작업이 끝나면 왼쪽에서 `Ctrl-C`, 리포트 생성:
```bash
python3 app/report.py logs/demo_normal.jsonl
xdg-open logs/demo_normal.html
```

**보여줄 것 — 리포트 첫 화면** (숫자는 실행마다 다르며 아래는 실제 측정 예시):
```
Commit Safety: SAFE
[0 Protected] [0 Persistence] [0 Dangerous] [0 Outside writes] [0 Deletions] [1,591 Outside reads] [35 Runtime noise]
Why this verdict: no policy findings; outside-project reads and runtime bookkeeping are informational.
```

> "이벤트 3천 개가 넘게 잡혔고, 프로젝트 **밖** 읽기가 1,500건이 넘습니다. 에이전트는 자기 런타임, 캐시,
> 인증서, node_modules를 계속 읽거든요.
> 초기 버전은 이걸 전부 '경계 위반'으로 잡아서 **모든 세션이 UNSAFE**로 나왔습니다. 리포트가 1.8 MB였습니다.
> 지금은 정보성으로 요약하고 **판정은 SAFE**입니다."

---

## Act 3 — Git이 못 보는 것 (2분)

**같은 방식으로 수집 시작** (`--output logs/demo_delete.jsonl`), 에이전트에게:

> 프롬프트: `docs/hello.c 에 hello world 출력하는 C 파일 만들고, 컴파일해서 실행한 다음 파일 지워줘`

**보여줄 것 — 두 화면을 나란히:**

```bash
git status --short          # 아무것도 없음 (깨끗)
```
```
Commit Safety: REVIEW_NEEDED
Why this verdict: file deletion ×1
   File deletion requested: /home/vboxuser/SysGuard/docs/hello.c
```

> "**Git은 깨끗하다고 합니다.** 파일이 커밋된 적이 없으니 지워져도 흔적이 없거든요.
> SysGuard는 '에이전트가 방금 만들어준 소스를 지웠다'고 파일명까지 알려줍니다. 이게 이 도구의 핵심입니다."

**이어서 정확도를 짚는다:**

> "그런데 파일 **생성**은 경고하지 않았습니다. 프로젝트 안이니까요. Git이 추적하는 영역이고 정상 작업입니다.
> 그리고 컴파일 중 gcc가 `/tmp`에 만든 임시 파일은 medium으로 따로 표시됩니다 —
> 사실이지만 위험은 아니라는 뜻입니다."

---

## Act 4 — 정말 위험한 것 (2분, 하이라이트)

> "그럼 AI 에이전트한테 **진짜 위험한 공격**은 뭘까요? 프롬프트 인젝션을 당한 에이전트가
> **자기가 다음에도 실행될 방법을 심는 것**입니다."

**실제 홈 디렉터리는 건드리지 않는다.** 샌드박스 HOME으로 수집:
```bash
sudo ./build/sysguard --agent-mode --target-comm bash \
  --project-path "$(pwd)" \
  --home-path "$(pwd)/demo/sandbox_home" \
  --output logs/demo_persistence.jsonl
```

> `--target-comm bash`는 모든 bash를 대상으로 잡으므로, 시연 중에는 **다른 터미널 작업을 멈춰두는 것**이 깔끔하다.

**오른쪽 터미널:**
```bash
bash demo/agent_persistence_simulator.sh
```

**왼쪽 터미널에 실시간으로 뜨는 것:**
```
  [critical] persistence-sensitive-write - Write to persistence/activation target: .../.bashrc
  [critical] persistence-sensitive-write - Write to persistence/activation target: .../.ssh/authorized_keys
  [critical] persistence-sensitive-write - Write to persistence/activation target: .../.claude/settings.json
```

> "세 건 다 CRITICAL입니다. 쉘 시작 파일, SSH 인증키, 그리고 **에이전트 자신의 설정 파일**입니다.
> 마지막 게 특히 중요합니다 — Claude Code 설정에는 hook을 정의할 수 있어서, 여기 한 줄 심으면
> **다음 세션부터 임의 명령이 자동 실행**됩니다."

**그리고 결정적인 대비를 보여준다:**

> "여기서 눈여겨보실 건 **1번과 3번이 같은 파일**이라는 겁니다.
> `.bashrc`를 **읽은** 1번은 아무 경고도 없었습니다. 쉘은 원래 매번 읽으니까요.
> **쓴** 3번만 CRITICAL입니다.
> 저희는 위험도를 '어디에 접근했나'가 아니라 **'무슨 효과를 내는가'**로 판정합니다."

리포트를 열어 **Persistence-Sensitive Writes** 섹션과 `Commit Safety: UNSAFE`를 보여준다.

---

## Act 5 — 마무리 (1분)

GUI를 띄워 세 세션을 한 화면에 보여준다:
```bash
sudo -E python3 app/main.py
```

| Session | Time | Size | Verdict |
|---|---|---|---|
| demo_persistence | … | … | **UNSAFE** (빨강) |
| demo_delete | … | … | **REVIEW_NEEDED** (주황) |
| demo_normal | … | … | **SAFE** (초록) |

> "같은 에이전트, 다른 작업. 판정이 셋으로 갈립니다.
> **읽기만 하면 SAFE, 흔적 없이 지우면 REVIEW, 자기를 심으면 UNSAFE.**
> 커밋 전에 이 화면만 보면 됩니다."

---

## 예상 질문과 답변

**Q. eBPF를 왜 썼나? `inotify`나 감사 로그로 안 되나?**
> `inotify`는 파일 변경만 보고 **누가 어떤 의도로** 했는지는 못 봅니다. auditd는 프로세스 계보 추적이 약합니다.
> 저희는 `execve`를 관측해 에이전트 프로세스를 뿌리로 잡고, `ppid`로 자식을 동적으로 추가해서
> **에이전트가 띄운 쉘·컴파일러·git까지 한 세션**으로 묶습니다.

**Q. 에이전트가 우회할 수 있지 않나?**
> 일부는 가능하고, 문서에 적어뒀습니다. 두 엔진 모두 경로를 **lexical**하게 매칭하므로
> 심볼릭 링크로 우회할 여지가 있습니다. 근본 해결은 수집기가 이벤트 시점에 resolve된 경로를
> 기록하는 것이고 `TASK-A-014`로 등록해 뒀습니다.
> 다만 **차단 도구가 아니라 감사 도구**라는 점이 전제입니다 — 막는 게 아니라 커밋 전에 보여주는 겁니다.

**Q. 빌드하면 `/tmp`에 쓰는 게 왜 경고로 뜨나? 오탐 아닌가?**
> 사실 그대로의 보고입니다. 컴파일러가 프로젝트 밖에 쓴 게 맞으니까요. 그래서 **medium**입니다.
> 파일명 패턴(`/tmp/cc*`)으로 면제하지 **않은** 이유는, 공격자가 `/tmp/ccevil.o`라고 이름 짓기만 하면
> 통과하기 때문입니다. 대신 `--tool-tmp`으로 **사전에 합의한 디렉터리**를 지정하면 그 안은 정보성으로 빠집니다.
> 이름이 아니라 위치를 믿는 방식입니다.

**Q. 네트워크 연결이 수십 건인데 왜 SAFE인가?**
> 단독 네트워크 관찰은 **증거**이지 위반이 아닙니다. `.env` 접근 **후** 전송 도구 실행이라는
> 순서가 관측될 때 `possible-secret-exfiltration`으로 critical 승격됩니다.

**Q. 오탐을 어떻게 줄였나?**
> 실제 세션 로그로 반복 측정했습니다. 초기엔 이벤트의 50%가 경고였고 그중 98%가 읽기였습니다.
> 읽기/쓰기 구분 → 런타임 bookkeeping 분류 → 효과 기반 재분류를 거쳐,
> 지금은 순수 읽기 세션이 **위반 0건**으로 나옵니다.

**Q. 현재 한계는?**
> 세 가지를 문서화해 뒀습니다. ① 심볼릭 링크 우회(A-014) ② `~/.claude/session-env`와 `plugins/cache`를
> 경로만으로 면제한 trade-off ③ 수집이 syscall **진입** 시점이라 성공 여부는 모른다는 점 —
> 그래서 리포트도 "requested/attempted"라고 표기합니다.

---

## 실패 대비 (플랜 B)

| 상황 | 대응 |
|---|---|
| eBPF 로드 실패 (커널/BTF 문제) | `--fake` 모드로 전환 — 13개 규칙 전부 발화하는 결정적 시나리오가 들어 있다. "수집 계층 대신 규칙 엔진을 보여드립니다"라고 명시 |
| `claude` 실행이 느리거나 멈춤 | Act 2·3을 `demo/agent_normal_simulator.sh` / `agent_boundary_violation_simulator.sh`로 대체 |
| 리포트가 안 열림 | `logs/*.html`을 미리 브라우저 탭에 열어두고 전환 |
| 시간 초과 | Act 4까지만. Act 5(GUI)는 생략 가능 |

**fake 모드 한 줄:**
```bash
./build/sysguard --fake --project-path "$(pwd)" --home-path "$(pwd)/demo/sandbox_home" \
  --output logs/demo_fake.jsonl && python3 app/report.py logs/demo_fake.jsonl
```

---

## 정리 (발표 후)

```bash
rm -rf demo/sandbox_home demo/sandbox_normal demo/sandbox_risky
git status --short          # 작업 트리가 깨끗한지 확인
```
