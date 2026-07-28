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
| TASK-A-002 | P1 | **DONE** | Define the CONNECT wire representation, then implement `sys_enter_connect` + `outbound-connect`. (ABI: appended `addr_family`/`dest_addr[16]`/`dest_port`.) |
| TASK-A-003 | P1 | **DONE** | Align `src/rules.c` with the README's 13-rule set — remove/disable the five undocumented rules (`unsafe-chown`, `shell-exec`, `suspicious-netcat`, `docker-sock-access`, `aws-cred-access`) and correct executable matching to use `exe_path`/`argv` semantics. |
| TASK-A-004 | P1 | **DONE** | Add `project-boundary-access` using normalized paths + the configured project root (needs an explicit rule context instead of the event-only `rules_evaluate` API). |
| TASK-A-005 | P1 | DEFERRED | C-engine stateful `possible-secret-exfiltration`. *Deferred by director:* the Python detector (TASK-B-002) is the MVP authority for this sequence (it owns the user-visible verdict/report and already has the full ordered session); a second C-side state machine with PID/subtree lifecycle is not warranted until a real-time-alert requirement appears. Revisit only then. |
| TASK-A-006 | P1 | **DONE** | Complete additive JSONL serialization for every supported payload (rename paths, flags, mode, CONNECT, consistent alert/non-alert records). *Delivered by TASK-A-001 (mutation fields) + TASK-A-002 (connect fields).* |
| TASK-A-007 | P1 | **DONE** | Expand `fake_collector` into deterministic coverage of all README event types and all 13 specified rules, including ordered sequence scenarios. |
| TASK-A-008 | P2 | READY | Add non-root C tests for rule predicates, sequence state, event-name mapping, JSON escaping, payload serialization, and fake-mode schema compatibility. |
| TASK-A-009 | P2 | READY | Generalize path normalization to UNLINK, CHMOD, and both RENAME paths; document/handle non-AT_FDCWD dirfd-relative paths. *Path-field generalization delivered by TASK-A-001; dirfd handling still open.* |
| TASK-A-010 | P2 | **DONE** | Reconcile Makefile behavior with README "Build": `make` should produce `build/sysguard.bpf.o`, `build/sysguard.skel.h`, and `build/sysguard`, while preserving focused targets. |
| TASK-A-011 | P2 | READY | Use EXIT events to retire tracked PIDs safely and prevent stale PID membership in long-running target-subtree sessions. *Unblocked by TASK-A-001 (EXIT is now emitted).* |
| TASK-A-012 | P3 | READY | Update collector comments / stale "optional/MVP-only" wording after the seven-event contract is implemented. *Partially done for the four events added in TASK-A-001.* |
| TASK-A-013 | P3 | READY | Add build-time ABI assertions and a documented event-contract versioning policy for future shared-struct changes. |
| TASK-B-001 | P1 | **DONE** | Align the Python analysis + report layer with `unlinkat`/`renameat2`/`fchmodat`/`exit_group` and the additive `old_path`/`new_path`/`flags`/`mode` contract (repairs the live A→B contract break). |
| TASK-B-002 | P1 | **DONE** | Add session-scoped `possible-secret-exfiltration` detection (`.env` access followed by `curl`/`wget`) in the Python policy. |
| TASK-B-003 | P1 | **DONE** | Implement README-conformant `REVIEW_NEEDED` decisions (high-volume changes, build/config edits, sandbox-only deletions). |
| TASK-B-004 | P2 | **DONE** | Reconcile Python `DANGEROUS_COMMANDS` with the canonical README/C rules — drop `chown root`/`nc`/`netcat`/`ncat`; treat standalone `curl`/`wget` as downloader evidence, not an UNSAFE command. |
| TASK-B-005 | P2 | **DONE** | Complete report conformance: add "Recent Events", correct the 10-section order, render every event payload meaningfully. |
| TASK-B-006 | P1 | **DONE** | Add a non-sudo Python test suite (policy, sequence ordering, event-contract compatibility, safety verdicts, HTML escaping, report sections). Independent of TASK-A-008. |
| TASK-B-007 | P2 | **DONE** | Add the README-promised per-session safety-result preview to the GUI session list/panel. |
| TASK-B-008 | P3 | READY | Make git-summary failure behavior match the README's safe-empty contract; test timeout/error paths. |
| TASK-B-009 | P3 | READY | Surface malformed JSONL-line counts instead of silently discarding corrupt evidence. |
| TASK-B-010 | P2 | **DONE** | Report-layer aggregation of repeated rows (user-reported: repeated commands/opens bloat the report). Collapse identical alert/normal rows into one `×N` row; display-only, verdict + raw JSONL unchanged. |
| TASK-A-014 | P2 | READY | Record collector-resolved (symlink-resolved) target paths at event time. Both engines match paths lexically today — C cannot `realpath` in the real-time hot path and Python runs after the session, so a symlink created and removed during the run can make an exempt-looking path (`/tmp/claude-<uid>/x`, `~/.claude/projects/x`, ...) resolve to a persistence target and be classified as runtime noise. Resolving in the collector is the sound fix; the Python `realpath` cross-check is only defence in depth. *Raised by the director during the TASK-B-013 review.* |
| TASK-A-015 | P1 | READY | Attach `sys_enter_rename` and `sys_enter_renameat`. Only `renameat2` is traced today, but glibc `rename()` issues the `rename` syscall (82) — measured: a 5,143-event real session recorded **zero** rename events. The whole rename-destination policy (protected / persistence / outside, `RENAME_EXCHANGE`) is therefore dead code in production, and the atomic-replace bypass it was built to stop would go undetected. Blocks project-local agent-config detection. |
| TASK-B-015 | P1 | **DONE** | Trusted per-session toolchain temp root (`--tool-tmp`): compiler intermediates are classified by an exact pre-agreed root handed to the agent as `TMPDIR`, never by forgeable `/tmp/cc*` filenames. |
| TASK-B-014 | P1 | **DONE** | Deletion and rename classified with the same precedence as opens (protected → persistence → disposable-runtime → review), using a **narrower** deletion-safe set than the write allowlist; `renameat2` also classifies ordinary outside destinations and both paths under `RENAME_EXCHANGE`. Compiler temp files are deliberately NOT exempted (documented). |
| TASK-B-013 | P2 | **DONE** | Extend the runtime-noise set (`~/.claude/shell-snapshots/`, `~/.claude/file-history/`, agent `/tmp` scratch) after real sessions (`"read readme.md"`, 3,788 events) still graded REVIEW_NEEDED on 21 agent bookkeeping writes: `~/.claude/shell-snapshots/` (19) plus agent `/tmp` scratch (2). Adds those to the noise set while keeping `~/.claude/settings*.json` and `~/.claude.json` persistence-sensitive. |
| TASK-B-012 | P1 | **DONE** | Effect-aware write policy (user-reported: a `"read README.md"` session still graded REVIEW_NEEDED on 35 agent/toolchain bookkeeping writes). Split outside writes into runtime-noise (informational) / ordinary (`REVIEW_NEEDED`) / persistence-activation (`persistence-sensitive-write`, UNSAFE); trusted monitored-home with fail-closed; fixed the protected-verdict leak (AWS creds, sudoers). |
| TASK-B-011 | P1 | **DONE** | Operation-aware boundary policy redesign (user-reported false-positive storm: a README-only Claude session graded UNSAFE with 1,653 boundary alerts, ~98% read-only). Rename `project-boundary-access` → `outside-project-write`; outside-project **reads** become informational, only **writes/creates** are a boundary violation; verdict drops generic boundary from UNSAFE → REVIEW_NEEDED. C + Python parity, plus a non-sudo C rule harness (`make test-c`). |

**All 13 README canonical rules are implemented (13/13).** Remaining is P2/P3 polish/infra only: TASK-A-008 (C tests), TASK-A-009 (dirfd paths), TASK-A-011 (EXIT-based PID retirement), TASK-A-012 (comments), TASK-A-013 (ABI version policy — partly seeded by A-002's `_Static_assert`s), TASK-B-008 (git safe-empty), TASK-B-009 (malformed-JSONL counts). DONE beyond the README gap: TASK-B-010 (report aggregation). *(A-010, B-007 already DONE.)*

---

## Completed

### TASK-B-015 — Trusted toolchain temp root (`--tool-tmp`)
*Completed 2026-07-28.*

**Problem (user-reported):** a session that wrote, compiled and ran a
hello-world C file graded REVIEW_NEEDED with the **7 GCC intermediates as the
sole driver** (`/tmp/ccXXXXXX.s|.o|.res|.cdtor.*`). Unlike the previous session
there was no deletion to justify the verdict independently, so a completely
benign build produced a report consisting entirely of compiler internals.

**Approach (per the director's design):** do not recognize forgeable compiler
filenames — `comm` is attacker-controllable, a real `gcc`/`as`/`ld` writes
wherever its caller says, and file events carry no verified executable identity.
Instead agree on the *location* in advance: the user hands the agent a private
`TMPDIR` and tells SysGuard about it with `--tool-tmp`, and only paths **beneath
that exact root** are runtime noise. `gcc -o /tmp/payload` stays reported.

**Validation (fail-closed, all refusals warn and leave temps reportable):**
absolute · not `/` · no trailing `/` · no `.`/`..` component · fully canonical
(`realpath(dir) == dir`, so no symlink in ANY component) · a real directory ·
owned by the monitored user · mode `0700` · fits the session buffer (never
stored truncated). The root is recorded in the JSONL `tool_tmp` field so the
report classifies exactly as the live engine did, and an empty recorded value is
authoritative.

**Files changed (10):** `src/rules.{c,h}` (`tool_tmp_path` in the rule ctx,
`path_in_tool_tmp`, used by both the write and deletion classifiers),
`src/main.c` (`--tool-tmp` + `tool_tmp_is_trusted`), `src/collector.h`,
`src/jsonl_writer.{c,h}` (additive `tool_tmp` field), `src/bpf_collector.c`,
`src/fake_collector.c`, `app/policy.py` (`path_in_tool_tmp`, threaded through
`classify_event`/`evaluate_commit_safety`), `README.md`, tests.

**Verification:** clean zero-warning build; `make test-c` all passed; **139
Python tests OK**. Live CLI checks: a valid root is accepted and recorded, while
mode 0755, foreign ownership, a relative path, a missing directory, `/`, a
trailing-slash symlink, a symlinked parent component and a 317-byte path are all
refused with warnings.

**Director review:** five passes, every finding applied — (1) out-of-bounds
suffix read for paths shorter than 3 bytes; (2) `/` as a root stripped to `""`
and matched every absolute path (Python); (3) a trailing slash made the kernel
resolve a final symlink before `lstat`, defeating the symlink check; (4) `lstat`
only inspects the final component, so a symlinked **parent** still passed —
fixed by requiring a fully canonical path; (5) an over-long root was silently
truncated, widening the exemption to sibling paths. Final pass: no issues.
Residual TOCTOU (the directory could be replaced after startup validation) is
documented; the Python verdict layer re-resolves each candidate path.

### TASK-B-014 — Deletion/rename precedence; compiler noise accepted
*Completed 2026-07-28.*

**Problem (user-reported):** a session that wrote a hello-world C file, compiled
and ran it graded REVIEW_NEEDED on 9 drivers — 7 GCC intermediates under `/tmp`
(`ccXXXXXX.s|.o|.res|.cdtor.*`, written by `gcc`/`cc1`/`as`/`collect2`) and 2
deletions (`docs/hello.c` and the compiled binary inside the agent's own,
already write-exempt, `/tmp` scratch). The user asked whether REVIEW_NEEDED is
defensible here.

**Director verdict:** the verdict is right but the explanation is noisy — "eight
of its nine drivers should not be presented as reasons for review".

**Decisions taken:**
- **Compiler temps stay reportable.** Exempting `/tmp/cc*` by filename shape, or
  by shape plus `comm`, was rejected: `comm` is attacker-controllable, a real
  `gcc`/`as`/`ld` writes wherever its caller says, and file events carry no
  verified executable identity (`exe_path` exists only on `execve`). The sound
  fix is a private per-session `TMPDIR` handed to the agent — impossible here
  because SysGuard *observes* an independently launched agent rather than
  starting it. The false positive is therefore accepted and documented: the
  build genuinely did write outside the project.
- **Deletion gets open-style precedence** — protected → `UNSAFE`, persistence /
  activation → `UNSAFE` (a deleted `authorized_keys` or shell rc also changes
  what runs next session), disposable runtime → informational, else review.
- **The write allowlist is NOT reused wholesale for deletion** (director's
  correction to my proposal): deleting `~/.claude/history.jsonl`, `backups/` or
  `file-history/` is destructive and unlinking `/dev/null` is not bookkeeping.
  Only the agent's own uid-scoped scratch, cwd markers, `.claude.json.tmp.*` and
  recreatable caches/logs are deletion-exempt.
- **In-project source deletion stays REVIEW_NEEDED**, and git trackedness must
  not downgrade it: create → compile → delete leaves no git evidence at all,
  which is exactly where syscall history beats `git diff`.
- **`renameat2` gap closed**: ordinary outside destinations are now classified
  too, so staging in an exempt location and renaming to `/tmp/payload` no longer
  bypasses the boundary signal.

**Verification:** clean zero-warning build; `make test-c` all passed; **131
Python tests OK**. The reported session keeps `REVIEW_NEEDED` but its review
drivers reduce to the `docs/hello.c` deletion plus the (documented) compiler
temps; the scratch-binary deletion moved to the informational bucket.

**Director review:** four passes, every finding applied — (1) `RENAME_EXCHANGE`
swaps both paths, so both are destinations and both must be classified;
(2) the C engine returns a single alert, so exchange targets must be scanned
severity-major (protected across both, then persistence, then boundary) or an
ordinary outside path could mask a critical one; (3) the new informational
deletion bucket was not rendered, breaking the promise that exempted activity
always stays visible in the report. Final pass: no regressions.

### TASK-B-013 — Runtime-noise set extended (shell snapshots, agent /tmp scratch)
*Completed 2026-07-28.*

**Problem (user-reported):** a second real session (`"read readme.md"`, 3,788
events) still graded **REVIEW_NEEDED** on 21 outside writes — 19× the same
`~/.claude/shell-snapshots/snapshot-bash-*.sh` (Claude Code snapshots the shell
environment on every bash invocation), 1× `/tmp/claude-<uid>/.../tasks/*.output`
(background-task output), 1× `/tmp/claude-<hex>-cwd` (cwd marker). All agent
bookkeeping that TASK-B-012's table did not yet cover.

**User's question:** *"should any write inside `~/.claude` count as safe?"*
**Answer taken:** bookkeeping yes, **configuration no**. `~/.claude/settings.json`,
`settings.local.json` and `~/.claude.json` define **hooks and MCP servers**, so a
write there executes arbitrary commands on the next run — a prompt-injected agent
backdooring its own config is precisely what this tool must catch. Those three
stay `persistence-sensitive-write` (`UNSAFE`); a regression test pins it.

**Changes:** `.claude/shell-snapshots/` added to the home-relative noise
prefixes, plus agent `/tmp` scratch (`/tmp/claude-<uid>/`, `/tmp/claude-<hex>-cwd`)
— never all of `/tmp`. Mirrored in `src/rules.c` and `app/policy.py` with the
shared parity fixture extended in both harnesses.

**Verification:** clean zero-warning build; `make test-c` all passed; **121
Python tests OK**; both real sessions now grade **SAFE** (32.2 KB and 36.5 KB
reports) with 0 review-worthy writes and 75 / 35 informational noise writes.

**Director review:** six passes; every finding applied —
(1) `/tmp/claude-<N>/` accepted any number → the component must equal the
writing process's uid; (2) C's unsigned parse could wrap so a huge number
matched → 10-digit bound plus 64-bit accumulation, mirrored by an identical
bound in Python (which has bignums); (3) zero-padded spellings
(`/tmp/claude-00001000/`) still matched → canonical spelling only; (4) the
`-cwd` marker token was unauthenticated → narrowed to 4–16 lowercase hex;
(5) symlinked scratch paths could redirect an exempt path onto a persistence
target → a `realpath` cross-check refuses live redirections, **and** the residual
gap is documented rather than overclaimed: post-hoc analysis cannot prove
event-time link state, this affects every lexical exemption (not just `/tmp`),
and the sound fix is filed as **TASK-A-014** (collector-resolved targets).

### TASK-B-012 — Effect-aware write policy (runtime noise vs. persistence)
*Completed 2026-07-28.*

**Problem (user-reported):** after TASK-B-011, a real Claude session whose only
prompt was `"read README.md"` still graded **REVIEW_NEEDED** — driven solely by
35 outside-project writes (protected 0, dangerous 0, deletions 0). All 35 were
agent/toolchain bookkeeping: 17× `~/.claude/` session state, 6× `/dev/null`,
4× `~/.claude.json.tmp.<pid>.<hex>` atomic staging, 3× `~/.npm` cache/logs,
2× `~/.cache/claude-cli-nodejs/`, 2× `~/.config/Code/logs/`, 1× kernel
`trace_marker`. B-011's "reads = noise, writes = signal" had a blind spot: the
agent's OWN runtime writes are noise too.

**Director consultation:** Codex rejected a blanket write allowlist and
prescribed classification by **effect**, with the guardrail that "cache",
"agent-owned", and "pseudo-filesystem" must never become synonyms for "safe".

**Approach — five buckets, one precedence, both engines:**
1. protected/credential access (read or write) → `UNSAFE`
2. persistence/activation **mutation** → `persistence-sensitive-write` → `UNSAFE`
   (reads stay ordinary — a shell reads `.bashrc` on every invocation)
3. inside the project → no finding
4. operation-unknown outside open → `REVIEW_NEEDED`, never exempted
5. proven outside mutation → runtime-noise match ? informational : `REVIEW_NEEDED`

Matching is exact / prefix / component-aware only (no `"/.cache/"` substrings).
Home-relative rules use the **monitored** user's home — `SUDO_UID`-aware in C,
the recorded `home_path` JSONL field in Python — and fail closed when it is
absent, malformed, or root.

**Files changed (13):** `app/policy.py` (bucket tables, `resolve_monitored_home`,
`is_runtime_noise_write`, `is_persistence_sensitive`, rename-by-destination,
verdict rewrite), `src/rules.c` (mirrored tables, `persistence-sensitive-write`,
rename branch, lexical normalizer, `path_protected_rule`), `src/rules.h`,
`src/collector.h`, `src/main.c` (`--home-path` + sudo-aware resolution),
`src/jsonl_writer.{c,h}` (additive `home_path` field), `src/bpf_collector.c`,
`src/fake_collector.c` (`{HOME}` sentinel + persistence/noise demo scenarios),
`README.md`, `docs/TASKS.md`, `tests/test_{policy,report,rules}.py|c`.

**Fixed along the way:** the Python verdict only promoted `.env`/`.ssh`/
`/etc/shadow`, so **AWS credentials and sudoers leaked through as
REVIEW_NEEDED**; it now uses `bool(protected_accesses)`.

**Verification (all non-sudo):** clean zero-warning build; `make test-c` all
passed (parity matrix: 14 noise rows, 10 near-miss rows, 23 persistence rows,
precedence, traversal, fail-closed home, rename destinations); **117 Python
tests OK**; fake demo shows `~/.bashrc` **write** = critical while the **read**
of the same file is silent. **The reported session now grades `SAFE` with a
37 KB report** (was REVIEW_NEEDED; the original B-011-era report was 1.8 MB).

**Director review:** five passes. Four findings raised and all applied —
(1) traversal (`.claude/projects/../../.bashrc`) defeated the lexical exemption
→ dot-segment paths are refused an exemption and normalized before persistence
matching, in both engines; (2) `SUDO_UID=0`/malformed accepted root's `/root`
→ full numeric validation + non-zero requirement; (3) the collector's home was
not serialized, so the report could re-derive a different one → additive
`home_path` JSONL field, and an **empty** recorded value is authoritative
(fail-closed) rather than re-derived; (4) a staging file renamed onto a
protected path (`.env`, `~/.aws/credentials`, `/etc/sudoers`) bypassed all
alerts → protected precedence now applies to rename destinations (this added
the `aws-credentials-access` / `secrets-file-access` rule IDs to the C engine
for parity with Python's `PROTECTED_PATHS`; documented in README §5). Final
pass: no actionable regressions.

**Known limitation (accepted, documented in README §6):**
`~/.claude/session-env/` (sourceable scripts) and `~/.claude/plugins/cache/`
(executable plugin content) are exempted by path alone — a cache-poisoning /
session-script false-negative tradeoff taken to keep routine sessions readable.
A hardened profile would require session-created runtime roots plus integrity
verification. Exempted writes still always appear in the report with counts and
representative paths.

### TASK-B-011 — Operation-aware boundary policy (outside-project-write)
*Completed 2026-07-28.*

**Problem (user-reported):** running a real Claude Code session that only read
`README.md` produced an **UNSAFE** verdict and a ~1.8 MB report. Quantified on
the captured session (`logs/session_claude_20260727_214104.jsonl`, 3,430
events): 1,710 alerts (~50% of events), 1,653 of them `project-boundary-access`,
~98% read-only, and effectively 100% routine runtime paths (agent runtime,
language toolchain, caches, cert stores, `node_modules`). Root cause: the
"outside project root = violation" rule mislabels an AI agent's normal
read-mostly runtime access as a boundary breach, so every real session grades
UNSAFE and the report is unreadable.

**Director consultation:** Codex recommended a *sensitivity-first,
operation-aware* model (chosen over allowlist expansion, which is
environment-specific and would dangerously normalize runtime writes): classify
protected/sensitive paths first, then split outside-project opens into
read-only (informational) vs. mutation-capable (write/create/truncate/append →
violation). Both the C real-time engine and the Python verdict engine must move
together to keep parity.

**Approach:** shared open-flag matrix — a mutation is
`(flags & O_ACCMODE) ∈ {O_WRONLY, O_RDWR}` **or** any of
`O_CREAT | O_TRUNC | O_APPEND | O_TMPFILE` (so `O_RDONLY|O_CREAT`, which still
creates, counts). Protected-path classification runs first and is unchanged, so
`/etc/shadow`, `.env`, SSH keys, etc. still fire regardless of read/write.

**Files changed (10):**
- `app/policy.py` — added `open_flags_may_mutate`, `is_outside_project`,
  `is_boundary_violation(path, project, flags)` helpers. `classify_event`
  now emits a `boundary_violation` finding only for mutation-capable outside
  opens; `evaluate_commit_safety` counts non-sensitive outside **reads** as
  informational (`outside_project_reads` / `_read_paths`, bounded), separates
  `outside_project_unknown_opens` (legacy flag-less records), and removes
  generic boundary from UNSAFE — it now flows to `REVIEW_NEEDED`.
- `src/rules.c` — `#define _GNU_SOURCE` + `<fcntl.h>`; `open_flags_may_mutate`
  helper; boundary rule now requires a mutation flag; rule_id
  `project-boundary-access` → `outside-project-write`; reason/recommendation
  reworded (write/create framing).
- `src/rules.h` — ctx doc comment updated to `outside-project-write`.
- `app/report.py` — section 4 "Boundary Violations" → "Outside-Project Writes"
  (aggregated, `×N`); added an informational line + sampled paths for
  non-sensitive outside reads.
- `src/fake_collector.c` — outside scenarios split into a read (unflagged) and
  a write (`out.log`, `O_WRONLY|O_CREAT` → fires); **bug fix:** the OPEN case
  now copies `scenarios[i].flags` into `ev.flags` (previously only RENAME did,
  so open flags were always 0).
- `tests/test_rules.c` **(new)** + `Makefile` `test-c` target — non-sudo C rule
  harness driving `rules_evaluate()`: inside read / outside read (no alert),
  outside write + `O_CREAT`/`O_TRUNC`/`O_APPEND` (→ `outside-project-write`),
  protected-before-boundary precedence, system-allowlisted write. Seeds
  TASK-A-008.
- `tests/helpers.py`, `tests/test_policy.py`, `tests/test_report.py` — `flags`
  default; `OperationAwareBoundaryTests` + predicate tests; report section
  rename/read-info assertions.
- `README.md` — §5 rule table (`outside-project-write`), §5 read/write rationale
  note, §6 policy categories + allowlist rationale, §7 verdict table (SAFE
  allows non-sensitive outside reads; REVIEW_NEEDED owns outside writes; generic
  boundary removed from UNSAFE), §9 report layout, Validation row.

**Verification (all non-sudo):**
- `make clean && make` — clean, zero-warning build; `make test-c` — "C rule
  tests: all passed".
- Fake mode with `--project-path`: outside **read** (`report.txt`) is a plain
  non-alert event; outside **write** (`out.log`) fires `outside-project-write`
  (flags 0x41); protected paths still fire; no `project-boundary-access`
  anywhere.
- Python suite: **100 tests, OK**.
- Re-evaluating the reported real session: **UNSAFE → REVIEW_NEEDED**, 39
  outside writes surfaced, 1,621 outside reads summarized as informational.

**Director review:** Codex reviewed the diff and raised two findings, both
applied and re-verified:
- **[P1]** the system-path allowlist was exempting *writes* to `/usr`, `/etc`,
  `/opt`, ... in both engines — removed from the mutation decision (C:
  `outside-project-write` rule; Python: `is_boundary_violation` no longer
  routes through `is_outside_project`). The allowlist now suppresses only
  informational reads. This surfaced ~10 additional real-session writes.
- **[P2]** operation-unknown outside opens (flag-less legacy records) were
  ignored by the verdict, so an unknown-only session graded SAFE — now they
  contribute to `REVIEW_NEEDED` (matching the policy table), with a matching
  recommendation. The dead C read-allowlist function/tables were removed to
  keep the zero-warning build.

A second review pass then caught a third finding, also applied:
- **[P1] O_TMPFILE bit overlap** — Python folded `O_TMPFILE` into the OR-mask,
  but on Linux `O_TMPFILE == (__O_TMPFILE | O_DIRECTORY)`, so a routine
  read-only directory scan (`O_RDONLY | O_DIRECTORY`) matched the mask and was
  misread as a mutation (the C engine already used whole-pattern equality).
  Python now mirrors C: `(f & O_TMPFILE) == O_TMPFILE`, checked separately from
  the create/trunc/append bits. Impact on the real session was large — outside
  "writes" dropped 185 → 39 as 372 directory scans were reclassified as reads.

A third pass caught a fourth finding, also applied:
- **[P1] allowlist ordering for unknown ops** — the informational counting loop
  applied the system/tool-config read-noise allowlist *before* the operation was
  known, so a flag-less (unknown) open of `/etc/passwd`, `/usr/...`, or
  `~/.gitconfig` was neither counted nor reviewed even though it could be a
  write. The loop now establishes "outside the project" by location, classifies
  the operation, and only drops system paths that are *proven reads*. The
  now-unused `is_outside_project` helper was removed.

A fourth review pass reported **no actionable regressions** — the diff is
consistent across the C engine, Python policy, report, fake collector, and
tests. Final state: 100 Python tests + `make test-c` green, zero-warning build.

### TASK-B-010 — Report-layer aggregation of repeated rows
*Completed 2026-07-27. (User-reported UX issue, outside the original README-gap backlog.)*

A single logical action produces many syscalls, and repeated commands/opens
produced many near-identical rows, cluttering the HTML report. B-010 collapses
repeated **display** rows into one row + a `×N` occurrence count — a
**display-only** change that never touches collection, the raw JSONL evidence,
or the Commit Safety verdict.

**Files changed (1 + tests):** `app/report.py` (+ `tests/test_report.py`).
- Pure helper `aggregate_for_display(items, key_fn) -> [(first_item, count)]`
  (first-seen order, no mutation/escape/HTML/timestamp/policy) + `_count_suffix`.
- **Alert Details:** identical rows collapse; new "Occurrences" column (`×N`,
  `—` for 1). Key = `(severity, rule_id, pid, comm, format_event_detail, reason)`
  so different-importance / different-process alerts never merge.
- **Normal Activity** (commands/files/deletions/renames/chmods/exits): aggregate
  FIRST, then cap at 20 unique rows (repeated early activity can't hide later
  distinct activity), each with a `×N` suffix.
- **Recent Events** and the policy finding subsections stay **unaggregated**
  (raw tail / small policy-derived lists).
- Metadata `Total Events` / `Alerts` still show raw counts.

**Design guardrails:** aggregation runs only at render time, after
`evaluate_commit_safety` over the full event list — so the verdict/badge is
unchanged (a test asserts the badge HTML is byte-identical with vs without
aggregation). All values escaped at the render boundary; the `×N` markup is
static. No monotonic `timestamp_ns` is rendered.

**Verification (non-sudo):** full suite **88 tests** (was 77, +11); a live
report over a crafted 30×-duplicate-alert session collapses to one `×30` row +
raw metadata (31/31), and the input JSONL sha256 is unchanged before/after
report generation.

**Director review:** Codex (which planned it) reviewed the diff — APPROVED, no
blocker/should-fix; three nits (per-field distinct-alert test, escaped-once
scoping, docstring wording) applied.

### TASK-A-010 — Default `make` builds the full engine
*Completed 2026-07-26.*

Reconciled the Makefile default target with the README "Build" contract (and the
GUI's "run make first" guidance): plain `make` now produces
`build/sysguard.bpf.o` + `build/sysguard.skel.h` + the executable
`build/sysguard`, not just the skeleton.

**File changed (1):** `Makefile` — `all: $(BPF_SKEL)` → `all: $(BIN)` (the
`$(BIN)` rule already depends on `$(BPF_SKEL)` → `$(BPF_OBJ)`, so all three
artifacts build through the existing chain — no duplicated prerequisites, no
recipe on `all`). Refreshed the stale "Week-1 skeleton experiment" header /
USER_SRC comments. No source/flag/library/artifact-name change; `sysguard`,
`poc`, `vmlinux`, `run`, `run-poc`, `clean` unchanged.

**Verification (non-sudo):** `make clean && make` builds all three artifacts
(executable `build/sysguard`); a second `make` is a no-op (`make -q` clean);
`make sysguard`/`make poc` still work; `make -n run`/`run-poc` still emit their
sudo commands; fake-mode JSONL parses; full 77-test Python suite green.

**Director review:** Codex reviewed the Makefile diff — APPROVED, no findings.

### TASK-B-007 — GUI per-session safety preview
*Completed 2026-07-26.*

Filled the README section-10 GUI gap ("session별 safety 결과 미리보기"): each
session-list row now shows its Commit Safety verdict inline with the README
badge colors.

**Testability boundary (director design):** the verdict logic lives in a pure,
Tkinter-free, git-free helper so it is fully unit-tested headless; only the
widget wiring is a manual step (this box has no `python3-tk`/display).

**Files:**
- NEW `app/safety_preview.py` — `compute_session_safety(jsonl_path, target_comm,
  project_path)`: reuses `load_events` → `filter_target_events` →
  `evaluate_commit_safety(git_summary=None)`; returns SAFE/REVIEW_NEEDED/UNSAFE
  or `"UNKNOWN"` on any missing/empty/malformed input or error; **never raises,
  never calls git, imports only policy + session_analyzer**.
- `app/main.py` — `refresh_logs` renders `<file>  (N bytes)  [VERDICT]` per row
  with `itemconfig` badge colors (SAFE green / REVIEW_NEEDED orange / UNSAFE red
  / UNKNOWN gray), isolated per file so one bad session can't abort the refresh;
  `open_report` uses `split("  ", 1)[0]` so filename recovery is unaffected by
  the suffix. Start/Stop/Refresh/Open Report/`fix_ownership`/`open_in_browser`/
  sudo-env restoration unchanged.
- NEW `tests/test_safety_preview.py` — 10 tests.

**Documented behavior:** the preview passes `git_summary=None`, so it can show
SAFE where the full report shows REVIEW_NEEDED (git-only heuristics are absent);
Open Report remains the authoritative, git-aware verdict.

**Verification (non-sudo):** `py_compile` OK for `safety_preview.py` +
`main.py`; the 10 helper tests pass (SAFE/REVIEW_NEEDED/UNSAFE, missing/empty/
malformed → UNKNOWN, project_path + target_comm derivation, git never invoked);
full suite **77 tests** (was 67); an AST check confirms the helper imports only
policy + session_analyzer. **The Tkinter rendering + colors are a manual step on
the target VM (python3-tk + display).**

**Director review:** Codex reviewed the diff — APPROVED (no blocker/should-fix);
one nit (add a target_comm-derivation test) applied.

### TASK-A-002 — connect tracepoint + outbound-connect rule (rules 13/13)
*Completed 2026-07-26.*

Implemented the 7th README tracepoint and completed canonical rule coverage. The
**first change to the shared wire ABI**: appended
`addr_family` / `dest_addr[16]` / `dest_port` to `struct sysguard_event`
(tail-only), guarded by compile-time `_Static_assert`s on the offsets (1320/
1328/1332/1348), field widths (4/16/2), and total size (1352) so an accidental
reorder/resize is caught in BOTH the BPF and user-space builds. This satisfies
**TASK-A-006** (additive JSONL for every payload) as well.

**Design decisions (director-approved):** binary family-agnostic address
storage (not text); the C JSONL layer renders it via `inet_ntop` so Python stays
simple; `outbound-connect` is MEDIUM and excludes loopback/link-local/
unspecified but NOT RFC1918/ULA (a private-LAN host is still outbound); no Python
policy rule (a standalone MEDIUM connect stays SAFE, like a downloader).

**Files changed (11 + board):**
- `src/event.h` — `SYSGUARD_CONNECT_ADDR_LEN` + 3 appended fields + 6 ABI asserts.
- `bpf/sysguard.bpf.c` — `handle_connect`: read `sa_family` first, then
  constant-size, `addrlen`-gated reads of a fixed stack `sockaddr_in`/`_in6`,
  `bpf_ntohs` for the port; `clear_payload` zeroes the binary fields;
  collection-only (attempt, not success).
- `src/jsonl_writer.c` — `"connect"` name; `render_dest_addr` (`inet_ntop`);
  additive `addr_family`/`dest_addr`/`dest_port` in both writers, escaped,
  back-compatible.
- `src/rules.c` — `connect_is_local` (binary loopback/link-local/unspecified
  checks) + `format_connect_endpoint`; MEDIUM `outbound-connect` first-match
  branch; other 12 rules undisturbed.
- `src/fake_collector.c` — separate `connect_scenarios[]` table + shared
  `fake_emit` helper (existing 22 rows untouched): external IPv4/IPv6 fire, IPv4
  `127.0.0.1` + IPv6 `::1` stay silent.
- `src/poc_main.c` — CONNECT print (`ip:port` / `[ipv6]:port`).
- `src/target_filter.c` — comment.
- `app/report.py` — `format_event_detail` CONNECT rendering.
- `tests/` — +6 (standalone MEDIUM connect → SAFE; connect counted;
  IPv4/IPv6 render; missing-addr; alert endpoint in HTML; legacy JSONL without
  the new keys still renders).

**Verification (all non-sudo):** clean warning-free build (all 6 `_Static_assert`s
hold); skeleton exposes `handle_connect`; fake mode emits 4 connect events —
`203.0.113.10:443` and `[2001:db8::1]:443` fire `outbound-connect` MEDIUM,
`127.0.0.1` and `::1` are silent; every row carries the 3 keys, non-connect rows
have them zeroed; the HTML report renders both endpoints; full Python suite **67
tests** (was 61). **Live eBPF load/verifier acceptance is a sudo-only manual step
for the user.**

**Director review:** Codex (which designed the ABI) reviewed the 11-file diff —
APPROVED with one should-fix (tighten the ABI asserts to lock field order +
widths) and one nit (PoC IPv6 `[ip]:port`), both applied and re-approved.

### TASK-A-006 — additive JSONL serialization for every payload
*Completed 2026-07-26 (with TASK-A-002).* Delivered incrementally: TASK-A-001
added `old_path`/`new_path`/`flags`/`mode`; TASK-A-002 added
`addr_family`/`dest_addr`/`dest_port`. Both writers emit every payload
consistently for alert and non-alert records; all fields are additive and
back-compatible. CONNECT was the last piece, so this closes with A-002.



### TASK-B-005 — HTML report README section-9 conformance
*Completed 2026-07-25.*

Brought the report to the exact 10-section order README section 9 specifies and
added the missing "Recent Events" section.

**File changed (1 + tests):** `app/report.py` (+ `tests/test_report.py`).
- **Canonical order** (1) Session Metadata → (2) Commit Safety badge → (3) Normal
  Development Activity → (4) Boundary Violations → (5) Protected Path Access →
  (6) Dangerous Commands → (7) Git Status/Diff Summary → (8) Alert Details →
  (9) Recent Events → (10) Recommended Actions. Metadata now precedes the badge
  (was reversed) and carries a heading for stable order assertions.
- **Stable layout:** Boundary Violations / Protected Path Access / Dangerous
  Commands / Alert Details always render, with concise empty-state text, so the
  ten-section structure does not vary by session.
- **Findings as subsections:** the B-002 Suspicious Sequences, B-001 Unsafe
  Permission Changes + File Deletions, and B-003 Review Needed displays moved to
  `<h3>` subsections under Alert Details (kept their evidence + headings) instead
  of interrupting README's ten top-level sections. Alert Details renders even
  with no C alert (Python findings can carry the verdict).
- **Recent Events:** the last 50 filtered events, newest-first
  (`events[-50:][::-1]`), each rendered through `format_event_detail` so all six
  event types show meaningful payloads; the cap/count are labeled.
- Every event-derived value (event type, comm, pid via `str()`, detail, finding
  text, git status/diff) is `html.escape`d — the XSS invariant is preserved.

**Do-not-touch honored:** no C/BPF/JSONL change; `app/main.py`,
`app/policy.py`, `app/session_analyzer.py`, `app/git_summary.py` unchanged; no
verdict/classification change; no new analyzer aggregation.

**Verification (all non-sudo):** `py_compile` OK; full suite **61 tests** (was
54, +7: order, metadata-before-badge, empty states, Recent Events renders every
event type, 50-cap newest-first, findings-as-subsections, hostile escaping); a
live fake-mode report renders all 10 sections in the canonical order with the
finding subsections between Alert Details and Recent Events.

**Director review:** Codex reviewed the 2-file diff — APPROVED, no findings.



### TASK-A-007 — Fake-collector rule coverage (git-clean-force)
*Completed 2026-07-25.*

Closed the last achievable fake-coverage gap by adding a single deterministic
`git-clean-force` EXEC scenario. The fake session now exercises every
implemented C rule and all six emitted event types.

**File changed (1):** `src/fake_collector.c` — one new `scenarios[]` row
(`comm="bash"` caller, `exe_path="/usr/bin/git"`, `argv="git clean -fd"`,
pid 3023 / ppid 3000, HIGH via the git-clean-force rule), plus a clarifying
comment on the caller-vs-target convention for the dangerous-command group.

**Coverage after A-007:** the fake session emits 22 events across all 6
implemented event types and fires all 11 implemented canonical C rules
(destructive-rm, downloader-exec, env-file-access, file-unlink, git-reset-hard,
**git-clean-force**, project-boundary-access, shadow-access, ssh-key-access,
sudoers-access, unsafe-chmod). Combined with the Python `possible-secret-
exfiltration` sequence (the `.env`-OPEN-before-`curl`-EXEC ordering is
preserved), that is 12 of the README's 13 canonical rules. Only
`outbound-connect` remains unavailable — it needs the connect syscall +
destination-address ABI (TASK-A-002, BLOCKED).

**Do-not-touch honored:** no change to `rules.c/rules.h`, `bpf/`, `event.h`,
`jsonl_writer.c`, `target_filter.c`, any `app/*.py`, the existing
A-001/A-003/A-004 scenario rows, or the `{PROJECT}` sentinel.

**Verification (all non-sudo):** build warning-free; fake session = 22 events,
6 event types; `git-clean-force` fires HIGH with `comm="bash"`,
`path="/usr/bin/git"`, `argv="git clean -fd"`; all 11 rule_ids present,
`outbound-connect` absent; Python sequence still fires → UNSAFE; all JSONL
parses; full 54-test Python suite still green.

**Director review:** Codex reviewed the `src/fake_collector.c` diff — the change
passes all checks (APPROVED). The only note was that `docs/TASKS.md` is also
modified; that is the intended task-board update, committed together here.



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
