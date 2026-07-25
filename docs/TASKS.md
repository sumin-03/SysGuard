# SysGuard — Task Board

This board tracks work derived from the gap between `README.md` (the
authoritative top-level spec) and the current implementation.

**Owner A** (김수민): eBPF collector, C engine, JSONL evidence pipeline —
`TASK-A-*`.
**Owner B** (이현창): Python policy, git summary, HTML report, Tkinter GUI —
`TASK-B-*`. As of 2026-07-25 both domains are implemented by the same person;
the A/B split is kept for traceability against the README's team roles.

**Workflow**: `README.md` is the spec. Codex acts as project director and
reviewer; Claude implements. Each task is planned by the director, implemented,
built/tested, diff-reviewed, and only then marked `DONE` here.

**Status legend**: `READY` (unblocked, can start) · `BLOCKED` (needs a
prerequisite) · `DEPENDS-ON:<id>` · `IN PROGRESS` · `DONE`.

---

## Backlog

| ID | Priority | Status | Goal |
|----|----------|--------|------|
| TASK-A-001 | P1 | **DONE** | Add ABI-ready `unlinkat`, `renameat2`, `fchmodat`, `exit_group` collection and carry those events through JSONL, rules, fake mode, and PoC output. |
| TASK-A-002 | P1 | BLOCKED | Define the CONNECT wire representation, then implement `sys_enter_connect` + `outbound-connect`. *Blocked*: README requires a destination address but `event.h` reserves no address-family/address/port fields. |
| TASK-A-003 | P1 | **DONE** | Align `src/rules.c` with the README's 13-rule set — remove/disable the five undocumented rules (`unsafe-chown`, `shell-exec`, `suspicious-netcat`, `docker-sock-access`, `aws-cred-access`) and correct executable matching to use `exe_path`/`argv` semantics. |
| TASK-A-004 | P1 | **DONE** | Add `project-boundary-access` using normalized paths + the configured project root (needs an explicit rule context instead of the event-only `rules_evaluate` API). |
| TASK-A-005 | P1 | DEFERRED | C-engine stateful `possible-secret-exfiltration`. *Deferred by director:* the Python detector (TASK-B-002) is the MVP authority for this sequence (it owns the user-visible verdict/report and already has the full ordered session); a second C-side state machine with PID/subtree lifecycle is not warranted until a real-time-alert requirement appears. Revisit only then. |
| TASK-A-006 | P1 | READY | Complete additive JSONL serialization for every supported payload (rename paths, flags, mode, CONNECT once designed, consistent alert/non-alert records). *Partially delivered by TASK-A-001 for the current event set.* |
| TASK-A-007 | P1 | READY | Expand `fake_collector` into deterministic coverage of all README event types and all 13 specified rules, including ordered sequence scenarios. |
| TASK-A-008 | P2 | READY | Add non-root C tests for rule predicates, sequence state, event-name mapping, JSON escaping, payload serialization, and fake-mode schema compatibility. |
| TASK-A-009 | P2 | READY | Generalize path normalization to UNLINK, CHMOD, and both RENAME paths; document/handle non-AT_FDCWD dirfd-relative paths. *Path-field generalization delivered by TASK-A-001; dirfd handling still open.* |
| TASK-A-010 | P2 | READY | Reconcile Makefile behavior with README "Build": `make` should produce `build/sysguard.bpf.o`, `build/sysguard.skel.h`, and `build/sysguard`, while preserving focused targets. |
| TASK-A-011 | P2 | READY | Use EXIT events to retire tracked PIDs safely and prevent stale PID membership in long-running target-subtree sessions. *Unblocked by TASK-A-001 (EXIT is now emitted).* |
| TASK-A-012 | P3 | READY | Update collector comments / stale "optional/MVP-only" wording after the seven-event contract is implemented. *Partially done for the four events added in TASK-A-001.* |
| TASK-A-013 | P3 | READY | Add build-time ABI assertions and a documented event-contract versioning policy for future shared-struct changes. |
| TASK-B-001 | P1 | **DONE** | Align the Python analysis + report layer with `unlinkat`/`renameat2`/`fchmodat`/`exit_group` and the additive `old_path`/`new_path`/`flags`/`mode` contract (repairs the live A→B contract break). |
| TASK-B-002 | P1 | **DONE** | Add session-scoped `possible-secret-exfiltration` detection (`.env` access followed by `curl`/`wget`) in the Python policy. |
| TASK-B-003 | P1 | **DONE** | Implement README-conformant `REVIEW_NEEDED` decisions (high-volume changes, build/config edits, sandbox-only deletions). |
| TASK-B-004 | P2 | **DONE** | Reconcile Python `DANGEROUS_COMMANDS` with the canonical README/C rules — drop `chown root`/`nc`/`netcat`/`ncat`; treat standalone `curl`/`wget` as downloader evidence, not an UNSAFE command. |
| TASK-B-005 | P2 | DEPENDS-ON:TASK-B-001 | Complete report conformance: add "Recent Events", correct the 10-section order, render every event payload meaningfully. |
| TASK-B-006 | P1 | **DONE** | Add a non-sudo Python test suite (policy, sequence ordering, event-contract compatibility, safety verdicts, HTML escaping, report sections). Independent of TASK-A-008. |
| TASK-B-007 | P2 | DEPENDS-ON:TASK-B-003 | Add the README-promised per-session safety-result preview to the GUI session list/panel. |
| TASK-B-008 | P3 | READY | Make git-summary failure behavior match the README's safe-empty contract; test timeout/error paths. |
| TASK-B-009 | P3 | READY | Surface malformed JSONL-line counts instead of silently discarding corrupt evidence. |

**Next up (highest-priority READY):** TASK-A-007 (fake coverage — small: git-clean-force scenario) / TASK-B-005 (report Recent Events + section order — unblocked by B-001) / TASK-B-007 (GUI safety preview — now unblocked by B-003).

---

## Completed

### TASK-B-003 — README section-7 REVIEW_NEEDED heuristics
*Completed 2026-07-25.*

Activated the previously-vestigial middle verdict tier. `evaluate_commit_safety`
now consults the git change summary (already collected per README §8) to surface
REVIEW_NEEDED situations that are not clear violations.

**Signals (only when no UNSAFE condition exists):**
- **High-volume changes** — ≥ 20 distinct paths in `git status --short`
  (`HIGH_VOLUME_CHANGE_THRESHOLD`, a documented project choice; README gives no number).
- **Build/config edits** — an explicit allowlist (`Makefile`, `pyproject.toml`,
  `package.json`, `Cargo.toml`, `go.mod`, `Dockerfile`, … + `requirements*.txt`,
  `*.lock`, `build.gradle*`, `docker-compose*.yml/.yaml`), matched by basename +
  fnmatch (no broad `*.json`/`config/` globs).
- **Deletions** — a git `D` status entry, or an in-project `unlinkat` event.

**Verdict precedence (never downgrades):** UNSAFE (protected/boundary/dangerous/
world-writable chmod/critical alert/`.env`→curl sequence) → REVIEW_NEEDED
(deletions or the git signals) → SAFE. Review signals can never mask an UNSAFE
verdict, and a SAFE session with no git signal stays SAFE.

**Files changed (5):**
- `app/policy.py` — `HIGH_VOLUME_CHANGE_THRESHOLD` + `BUILD_CONFIG_BASENAMES`/
  `BUILD_CONFIG_PATTERNS`; `is_build_config_path`, `parse_git_status` (defensive
  porcelain parse: tolerates the `.strip()` leading-space loss, spaces in
  filenames, rename `old -> new` → destination, and non-string/empty/`(...)`
  placeholders as *unavailable evidence* — never raises), `detect_review_signals`;
  `evaluate_commit_safety(events, project_path="", git_summary=None)` —
  backward-compatible, adds the `review_findings` key + recommendations, only
  emits the "safe to commit" line on a SAFE verdict.
- `app/report.py` — fetch `get_git_summary` before evaluating and pass it in; new
  escaped "Review Needed" section.
- `tests/helpers.py` — `fake_git_summary(status=, diff_stat=)` (default unchanged).
- `tests/test_policy.py` + `tests/test_report.py` — +12 tests (threshold 19/20,
  build-config incl. nested / `requirements-dev.txt` / `*.lock`, rename→dest,
  git-deletion, in-project unlink, unavailable/malformed/**non-string** git inert,
  unsafe-never-downgraded across every UNSAFE category, no safe-message on
  REVIEW_NEEDED, backward-compatible 2-arg call).

**Do-not-touch honored:** no C/BPF/JSONL change; `app/main.py`,
`app/session_analyzer.py`, `app/git_summary.py` unchanged; no content/secret
inspection; git failure-text contract fix deferred to TASK-B-008.

**Verification (all non-sudo):** `py_compile` OK; full suite **54 tests** (was 42,
+12) green; smoke: 20 paths→REVIEW_NEEDED, `pyproject.toml`→REVIEW_NEEDED, single
src edit→SAFE, `git reset --hard` + 20-path git→UNSAFE, 2-arg call→SAFE; fake-mode
report still generates; prior verdicts unchanged without a git signal.

**Director review:** Codex reviewed the 5-file diff — one SHOULD-FIX (non-string
`status` value raised in `parse_git_status`; fixed with an `isinstance` guard +
regression cases), re-verified — APPROVED.



### TASK-B-006 — Non-sudo Python test suite
*Completed 2026-07-25.*

Added a stdlib-`unittest` suite (zero pip dependencies — runs on the target
Ubuntu 24.04 VM as-is) that locks in the accumulated, approved Python behavior
so future changes can't silently regress it.

**Process note:** the Codex rescue agent authored the suite directly rather than
returning a plan only (a deviation from the plan-only request and the
implementer/reviewer role split). Handled by inverting review for this one task:
Claude independently read all six files line-by-line, traced the filter logic,
ran the suite from two working directories, and checked bootstrap/gitignore
hygiene — this constitutes the independent verification in place of a Codex
self-review.

**Files added (6, all under `tests/`):** `__init__.py` (adds `app/` to
`sys.path` via `__file__`, so imports work from any cwd), `helpers.py`
(`make_event`/`write_jsonl`/`fake_git_summary`/`read_text`), `test_policy.py`,
`test_session_analyzer.py`, `test_report.py`, `test_git_summary.py`. No
production file (`app/`, `src/`, `bpf/`, `Makefile`, `README`) modified — only
`tests/` is new.

**Coverage (42 tests, locking in approved behavior only):**
- policy predicates (system/protected/boundary/env-file/inside-project),
  `external_transfer_tool` exact/argv-fallback/null-safe.
- dangerous-command canonical 7-list (B-004); standalone curl/wget not dangerous.
- sequence detection: ordered `.env`→curl/wget CRITICAL, reversed/standalone
  none, dedup, PID-independent, call-local, no secret-content leak (B-002).
- safety verdicts: unlink→REVIEW_NEEDED, chmod777→UNSAFE, chmod644→SAFE,
  rename+exit→SAFE, standalone downloader→SAFE, MEDIUM C alert doesn't force
  UNSAFE (B-001/B-004).
- session summary recognizes all 6 event names + mutation/lifecycle shapes +
  preserved prior keys (B-001); load/skip-blank/skip-invalid; target-subtree filter.
- report: event-detail formatting for all types; deletion/permission/exit/
  sequence sections render; C alert details render; **all hostile fields
  HTML-escaped** (XSS regression guard); git_summary mocked (hermetic).
- git_summary: exact subprocess calls + 10s timeout; failure paths return
  strings without raising (loosely asserted — TASK-B-008 may change the text).

**Deliberately NOT tested (unimplemented — would be premature):** B-003
REVIEW_NEEDED heuristics, B-005 Recent Events section, A-002 connect. GUI
(`app/main.py`) excluded (needs a display).

**Run command (non-sudo, from repo root):**
`python3 -m unittest discover -s tests -t .` → `Ran 42 tests … OK`. No Makefile
target added (Makefile reconciliation is TASK-A-010 — avoided the collision).

**Verification:** suite green from repo root AND from a foreign cwd (robust
bootstrap); `python3 -m compileall -q app tests` OK; `__pycache__`/`*.pyc`
already gitignored; no bytecode leaks into `git status`.



### TASK-B-004 — Reconcile Python dangerous-command policy with canonical rules
*Completed 2026-07-25.*

Reduced `app/policy.py`'s `DANGEROUS_COMMANDS` to the seven canonical destructive
strings so the Python verdict matches the README/C rule set and README §7's
UNSAFE conditions. A standalone downloader is no longer UNSAFE on its own.

**File changed (1):** `app/policy.py` — `DANGEROUS_COMMANDS` is now exactly
`rm -rf`, `rm -r`, `git reset --hard`, `git clean -fd`, `git clean -f`,
`chmod 777`, `chmod a+rwx` (+ a rationale comment). Removed: `curl`/`wget`
(→ `downloader-exec` MEDIUM; escalate only via the B-002 `.env`-then-transfer
sequence), `chown root` and `nc`/`netcat`/`ncat` (non-canonical, dropped from the
C engine in A-003). `is_dangerous_command`/`classify_event`/
`evaluate_commit_safety` logic and the B-002 helpers are unchanged;
`app/report.py` unchanged (the C `downloader-exec` MEDIUM alert already shows in
Alert Details without forcing UNSAFE, since `has_critical` checks only
`severity=="critical"`).

**Verification (all non-sudo):**
- `DANGEROUS_COMMANDS` == the exact 7-list; each retained pattern →
  `dangerous_command` HIGH → UNSAFE.
- `chown root` / `nc` / `netcat` / `ncat` → no finding.
- Standalone `curl`/`wget` → no finding, verdict SAFE; a JSONL `downloader-exec`
  MEDIUM alert renders SAFE with the alert still visible in Alert Details.
- `.env`→curl and `.env`→wget still → 1 CRITICAL → UNSAFE (B-002); reversed → none.
- B-001 verdicts intact; `py_compile` OK; no C/BPF/JSONL/GUI/git-summary/report change.

**Director review:** Codex reviewed the `app/policy.py` diff — APPROVED, no issues.



### TASK-B-002 — possible-secret-exfiltration sequence detection (Python)
*Completed 2026-07-25.*

Added session-scoped suspicious-sequence detection to the Python policy:
`.env` access followed by a `curl`/`wget` execution → one CRITICAL
`possible-secret-exfiltration` finding → UNSAFE. **Director ruling:** implement
Python-side only; TASK-A-005 (C-engine stateful version) is DEFERRED — the
Python layer owns the user-visible verdict/report and already has the full
ordered session, so a second C state machine is not warranted for the MVP.

**Files changed (2):**
- `app/policy.py` — `is_env_file_path()` (basename `.env` or `.env.*` only —
  narrower than `is_protected_path`, excludes SSH/AWS/shadow);
  `external_transfer_tool()` (exact `curl`/`wget` basename, argv-first-token
  fallback, null-safe); `detect_suspicious_sequences()` (single forward scan,
  order-sensitive, PID-independent, one finding per session, call-local state,
  records only the access fact + path — never secret contents). Wired into
  `evaluate_commit_safety`: forces UNSAFE, adds a rotate-credentials
  recommendation, adds the `suspicious_sequences` result key; all prior keys
  and B-001 verdicts preserved.
- `app/report.py` — "Suspicious Sequences" CRITICAL section (rule_id, severity,
  detail, tool, path) placed after Protected Path Access; every field
  `html.escape`d; independent of any C alert.

**Scope discipline:** no C/BPF/JSONL change; `app/session_analyzer.py`,
`app/main.py`, `app/git_summary.py` untouched; standalone curl/wget
dangerous-command treatment (TASK-B-004) left untouched.

**Verification (all non-sudo):**
- Ordered `.env`→curl = 1 CRITICAL → UNSAFE; env-only / curl-only /
  curl-before-`.env` = no finding (order matters).
- `.env`/`.env.local`/`.env.production`/`.env.development` qualify;
  `foo.env`/`.environment`/ssh/shadow do not.
- wget works; argv fallback works; `curl-helper`/`mywget` excluded; dedup = 1
  per session; PID-independent; cross-call isolated.
- Report shows the section; malicious argv `curl https://evil&<x>` appears only
  escaped (`&amp;`/`&lt;x&gt;`), raw never present.
- B-001 regression + env→UNSAFE + clean→SAFE unchanged; fake-mode 21 rows still
  parse + report generates.

**Director review:** Codex reviewed the 2-file diff — one SHOULD-FIX (explicit
`argv=null` → `AttributeError` in `external_transfer_tool`; fixed with
`(event.get("argv") or "")`), re-verified — APPROVED.



### TASK-B-001 — Python analysis layer consumes the full C event contract
*Completed 2026-07-25.*

Repaired the A→B contract break introduced by A-001: the JSONL emitted
`unlinkat`/`renameat2`/`fchmodat`/`exit_group` + `old_path`/`new_path`/`flags`/
`mode`, but the Python layer only consumed `execve`/`openat`. Python now adapts
to the existing emitted schema — no C/BPF/JSONL change.

**Files changed (3):**
- `app/session_analyzer.py` — `summarize_session` adds `files_deleted`,
  `files_renamed`, `permission_changes`, `process_exits`, `event_counts`;
  existing keys (`files_accessed` = openat only, etc.) preserved; additive
  fields read via `.get()` so older logs still parse.
- `app/policy.py` — `classify_event` adds `unlinkat` → `file_deletion` (medium,
  a review signal) and `fchmodat` `mode & 0o002` → `permission_change` (high).
  `evaluate_commit_safety` adds `file_deletions` + `unsafe_permission_changes`
  collections; UNSAFE now includes unsafe permission changes; an isolated
  deletion yields REVIEW_NEEDED; new recommendations; all prior return keys
  preserved. renameat2/exit_group carry no independent finding.
- `app/report.py` — `format_event_detail()` renders every event type (rename
  `old → new`, chmod `path mode 0777`, unlink `delete: path`, exit context);
  metadata counts; non-alert mutation subsections; new "Unsafe Permission
  Changes" + "File Deletions" sections; alert table uses the formatter so no
  mutation cell is blank; all event-derived strings `html.escape`d.

**Director decisions applied:** standalone curl/wget is downloader evidence, not
an UNSAFE dangerous command (B-002 combines it); rename/exit never independently
unsafe; unsafe fchmodat is a `permission_change` type (not `dangerous_command`).

**Verification (all non-sudo):**
- Build clean; fake JSONL 21 rows all parse; `summarize_session` →
  `files_deleted=[…/stale.o]`, `files_renamed=[draft.md → final.md]`,
  `permission_changes` modes 511 & 420, `process_exits=[claude]`.
- Verdicts: isolated unlink → REVIEW_NEEDED; chmod 0777 → UNSAFE; chmod 0644 →
  SAFE; rename+exit → SAFE.
- Report HTML contains File Deletions / Permission Changes / Process Exits /
  draft.md / final.md / deploy.sh / 0777.
- Escaping: `old_path="<old>"` → `&lt;old&gt;`, `new_path="new&name"` →
  `new&amp;name`.
- Regression: openat protected/boundary + execve dangerous + env→UNSAFE +
  clean→SAFE unchanged; `py_compile` OK. `app/main.py` / `app/git_summary.py`
  untouched.

**Director review:** Codex reviewed the 3-file diff — APPROVED, no issues.



### TASK-A-004 — project-boundary-access rule + explicit rule context
*Completed 2026-07-23.*

Added the README `project-boundary-access` rule (openat, HIGH) and the explicit
rule-evaluation context it needs. No ABI, BPF, JSONL-writer, target_filter, or
owner-B changes.

**Design decisions (ruled by the director):**
- API: new `struct sysguard_rule_ctx { const char *project_path; }` in
  `rules.h`; `rules_evaluate(ev, const ctx*, out)`. `ctx`/`project_path`
  NULL/empty/non-absolute disables ONLY the boundary rule.
- Allowlist: C mirrors `app/policy.py`'s `SYSTEM_PATH_PREFIXES` +
  `USER_CONFIG_SUFFIXES` so routine `/usr`,`/lib`,`/proc`,tool-config opens are
  not flagged. Boundary rule runs LAST in the OPEN branch, so protected rules
  (shadow/sudoers/ssh/env) win by first-match.
- Predicate: lexical, component-aware containment (exact match or `root + "/"`);
  one trailing slash ignored; root `/` contains all; no `realpath` in C
  (Python remains the symlink-authoritative second layer).
- Fake: project-local fixtures use a `{PROJECT}/` sentinel expanded to the
  runtime `--project-path`; the standalone `.aws/credentials` scenario was
  removed (its C rule was dropped in A-003; owner B's policy.py still catches it
  from raw JSONL); one dedicated outside-project OPEN
  (`/home/user/outside-project/report.txt`) demonstrates the rule.
- Reconciliation: no double-count — Python computes its own boundary verdict
  independently of the C `rule_id`.

**Files changed (4):** `src/rules.h`, `src/rules.c`, `src/bpf_collector.c`,
`src/fake_collector.c`.

**Verification (all non-sudo):**
- `make clean && make && make sysguard && make poc` — clean, zero warnings.
- `project-boundary-access` exists only in the C impl; fake-mode 21 events all parse.
- With `--project-path /tmp/sysguard-a004-project`: exactly ONE boundary alert (HIGH) on the outside file; 4 project-local opens not flagged; shadow/sudoers/ssh/env retain their specific alerts; A-001 `file-unlink`(medium) + `unsafe-chmod` fchmodat(high) + A-003 `downloader-exec`(path=/usr/bin/curl) intact.
- Edge cases (CLI): trailing-slash root behaves identically; root `.` and no `--project-path` disable the rule (0 alerts); `root=/home/user/outside-project` contains `report.txt` (0); `root=/home/user/outside` does NOT swallow `/home/user/outside-project` (1) — component boundary correct.

**Director review:** Codex reviewed the 4-file diff — APPROVED, no blocker/should-fix/nit.



### TASK-A-003 — Align the C rule engine with the README's rule set
*Completed 2026-07-22.*

Removed the five rules absent from the README's 13-rule table and corrected the
`downloader-exec` executable-matching semantics per the `event.h` FIELD
SEMANTICS contract. No ABI, BPF, JSONL-writer, or owner-B changes.

**Files changed (2):**
- `src/rules.c` — removed `unsafe-chown`, `shell-exec`, `suspicious-netcat`
  (EXEC) and `docker-sock-access`, `aws-cred-access` (OPEN). `downloader-exec`
  now matches `exe_path`/`argv` (never `comm`) and names `exe_path` in its
  reason — at execve entry `comm` is the caller (shell), not the downloader.
  The 10 retained canonical rules keep their IDs/event-types/severities; the
  `match_any` helper stays (still used by `downloader-exec`); no retained EXEC
  predicate uses `comm` for executable identity.
- `src/fake_collector.c` — minimal semantic fixes: curl scenario now
  `comm=bash`, `exe_path=/usr/bin/curl` (proves the downloader rule ignores
  `comm`); the shell scenario (`comm=sh`, `exe_path=/usr/bin/bash`) is a
  negative regression that must not fire the removed `shell-exec`; the
  `.aws/credentials` OPEN scenario is retained as non-alert evidence. A-001
  UNLINK/RENAME/CHMOD/EXIT scenarios untouched.

**Not implemented here (separate tasks):** `project-boundary-access`
(TASK-A-004), `outbound-connect` (TASK-A-002, BLOCKED), and
`possible-secret-exfiltration` (TASK-A-005).

**Verification (all non-sudo):**
- `make clean && make && make sysguard` — clean, zero warnings.
- The 5 removed rule IDs are absent from `src/rules.c`; all 10 canonical IDs remain; the 3 deferred IDs were not added.
- Fake-mode 21 events all parse; observed alert set is a subset of the 10 canonical with no forbidden IDs.
- `downloader-exec` record: `comm=bash`, `path=/usr/bin/curl`, `argv` starts with `curl `, reason `Downloader executed: /usr/bin/curl` (no `comm` mislabel).
- Shell exec and `.aws/credentials` scenarios are non-alert; A-001 `file-unlink` (medium) and `unsafe-chmod` fchmodat (high) still fire.

**Director review:** Codex reviewed the `rules.c` + `fake_collector.c` diff — APPROVED, no blocker/should-fix/nit.

### TASK-A-001 — File-mutation + exit tracepoints through the pipeline
*Completed 2026-07-22.*

Added four of the five missing README tracepoints (CONNECT deferred to
TASK-A-002 because its destination-address ABI is undefined). Uses the enum
values and struct fields already reserved in `event.h`; no wire-contract
renumbering or reordering.

**Files changed (8):**
- `bpf/sysguard.bpf.c` — `handle_unlinkat` (path), `handle_renameat2`
  (old_path=args[1], new_path=args[3], flags=args[4]), `handle_fchmodat`
  (path + mode=args[2]), `handle_exit_group` (context-only marker). Each
  reserves from the ring buffer, fills context, clears payload, does bounded
  user reads, submits. argv verifier pattern and the 256 KB ring buffer are
  untouched.
- `src/event.h` — doc-only: values 1–7 documented as the README contract (not
  "optional"); `flags` clarified as OPEN/RENAME; enum values and field order
  unchanged.
- `src/jsonl_writer.c` — additive `old_path`/`new_path`/`flags`/`mode` fields in
  both writers; `renameat` → `renameat2` event name; alert writer now uses the
  same event-dependent `argv`/`path` selection as the non-alert writer.
- `src/rules.c` — `file-unlink` (UNLINK, medium) and `unsafe-chmod` (CHMOD,
  `mode & 0002` → high, octal reason). Existing rules undisturbed.
- `src/fake_collector.c` — UNLINK / RENAME / CHMOD(0777 & 0644) / EXIT
  deterministic scenarios; scenario struct extended.
- `src/poc_main.c` — per-type PoC output (path / old→new+flags / path+octal
  mode / context-only).
- `src/target_filter.c` — path normalization generalized to `path`,
  `old_path`, `new_path` per event type.
- `src/bpf_collector.c` — stale openat-only normalization comment updated.

**Verification (all non-sudo):**
- `make clean && make && make sysguard` — clean, zero warnings.
- Skeleton exposes all 6 programs (`handle_execve/openat/unlinkat/renameat2/fchmodat/exit_group`).
- Fake-mode run: 21 events across `{execve, openat, unlinkat, renameat2, fchmodat, exit_group}`; every JSONL line parses with `json`.
- `file-unlink` = medium and `unsafe-chmod` = high (`mode` = 511 / 0777) alerts fire; RENAME carries `old_path`/`new_path` and is non-alert; EXIT is context-only; safe chmod 0644 is non-alert.
- EXEC argv behavior unchanged; EXEC alerts now carry `exe_path` in `path` and keep `argv` (consistent with non-alert records).

**Live eBPF (sudo, run manually by the user — not a completion prerequisite):**
```bash
sudo ./build/sysguard --agent-mode --target-comm bash \
  --project-path "$(pwd)" --output logs/task_a_001_live.jsonl
# In another shell, inside a disposable sandbox:
#   touch a && mv a b && chmod 777 b && rm b
```

**Director review:** Codex reviewed the diff — no blockers; one SHOULD-FIX
(alert-writer `argv`/`path` selection inconsistency) applied and re-verified.
