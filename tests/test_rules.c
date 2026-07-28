/* Non-sudo C unit tests for src/rules.c (TASK-A-008 seed; TASK-B-011 parity).
 *
 * Constructs synthetic sysguard_event / sysguard_rule_ctx values and drives
 * rules_evaluate() directly — no BPF program, kernel, or root needed. Mirrors
 * the flag matrix in tests/test_policy.py so the C rule engine and the Python
 * policy agree on read-vs-write and protected-before-boundary precedence.
 *
 *   Build + run:  make test-c
 */
#include <stdio.h>
#include <string.h>
#include <fcntl.h>

#include "rules.h"

static int failures;

#define CHECK(cond) do { \
    if (!(cond)) { printf("  FAIL (line %d): %s\n", __LINE__, #cond); failures++; } \
} while (0)

static struct sysguard_event mk_open(const char *path, int flags)
{
    struct sysguard_event e;
    memset(&e, 0, sizeof(e));
    e.type = SYSGUARD_EVENT_OPEN;
    e.pid = 100;
    e.ppid = 1;
    e.uid = 1000;
    strncpy(e.comm, "claude", sizeof(e.comm) - 1);
    strncpy(e.path, path, sizeof(e.path) - 1);
    e.flags = flags;
    return e;
}

/* Monitored home used by the home-relative parity rows (mirrors test_policy.py). */
#define HOME "/home/u"

/* Return the rule_id fired for an event under project root P, or NULL. */
static const char *rule_of(struct sysguard_event *e, const char *project)
{
    static struct sysguard_alert a;
    struct sysguard_rule_ctx ctx = { project, HOME };
    if (rules_evaluate(e, &ctx, &a))
        return a.rule_id;
    return NULL;
}

/* Same, but with an untrusted/absent home: every home-relative match must be
 * disabled (fail-closed), so noise writes fall back to outside-project-write. */
static const char *rule_of_nohome(struct sysguard_event *e, const char *project)
{
    static struct sysguard_alert a;
    struct sysguard_rule_ctx ctx = { project, NULL };
    if (rules_evaluate(e, &ctx, &a))
        return a.rule_id;
    return NULL;
}

static struct sysguard_event mk_rename(const char *old_path, const char *new_path)
{
    struct sysguard_event e;
    memset(&e, 0, sizeof(e));
    e.type = SYSGUARD_EVENT_RENAME;
    e.pid = 100;
    e.ppid = 1;
    e.uid = 1000;
    strncpy(e.comm, "claude", sizeof(e.comm) - 1);
    strncpy(e.old_path, old_path, sizeof(e.old_path) - 1);
    strncpy(e.new_path, new_path, sizeof(e.new_path) - 1);
    return e;
}

static struct sysguard_event mk_unlink(const char *path, uint32_t uid)
{
    struct sysguard_event e;
    memset(&e, 0, sizeof(e));
    e.type = SYSGUARD_EVENT_UNLINK;
    e.pid = 100;
    e.ppid = 1;
    e.uid = uid;
    strncpy(e.comm, "rm", sizeof(e.comm) - 1);
    strncpy(e.path, path, sizeof(e.path) - 1);
    return e;
}

static int is(const char *got, const char *want)
{
    return got && strcmp(got, want) == 0;
}

int main(void)
{
    const char *P = "/project";
    struct sysguard_event e;

    /* inside-project read -> no alert */
    e = mk_open("/project/src/a.c", O_RDONLY);
    CHECK(rule_of(&e, P) == NULL);

    /* outside-project READ -> no alert (routine runtime access; informational) */
    e = mk_open("/home/u/.cache/node/x.js", O_RDONLY);
    CHECK(rule_of(&e, P) == NULL);
    e = mk_open("/etc/ssl/certs/ca.pem", O_RDONLY);   /* certs were false positives */
    CHECK(rule_of(&e, P) == NULL);

    /* outside-project WRITE -> outside-project-write */
    e = mk_open("/home/u/.claude/plugins/p", O_WRONLY);
    CHECK(is(rule_of(&e, P), "outside-project-write"));

    /* O_RDONLY|O_CREAT still CREATES -> outside-project-write */
    e = mk_open("/tmp/other/new", O_RDONLY | O_CREAT);
    CHECK(is(rule_of(&e, P), "outside-project-write"));

    /* O_RDONLY|O_TRUNC and O_APPEND also mutate */
    e = mk_open("/tmp/other/t", O_RDONLY | O_TRUNC);
    CHECK(is(rule_of(&e, P), "outside-project-write"));
    e = mk_open("/tmp/other/a", O_WRONLY | O_APPEND);
    CHECK(is(rule_of(&e, P), "outside-project-write"));

    /* protected paths win over boundary regardless of read/write */
    e = mk_open("/project/.env", O_RDONLY);
    CHECK(is(rule_of(&e, P), "env-file-access"));
    e = mk_open("/home/u/.ssh/id_rsa", O_WRONLY);      /* outside + write, but protected */
    CHECK(is(rule_of(&e, P), "ssh-key-access"));

    /* system-path READ is allowlisted (routine) -> no alert */
    e = mk_open("/usr/lib/x.so", O_RDONLY);
    CHECK(rule_of(&e, P) == NULL);

    /* but a system-path WRITE is a persistence/tampering signal: the allowlist
     * must NOT suppress mutations -> outside-project-write fires */
    e = mk_open("/usr/lib/x.so", O_WRONLY);
    CHECK(is(rule_of(&e, P), "outside-project-write"));
    e = mk_open("/etc/passwd", O_WRONLY);   /* not protected, but a write to /etc */
    CHECK(is(rule_of(&e, P), "outside-project-write"));

    /* ---- TASK-B-012 parity matrix (mirrors tests/test_policy.py) ---------- */

    /* Runtime bookkeeping WRITES -> informational, no alert. */
    const char *noise[] = {
        HOME "/.claude/projects/s.jsonl", HOME "/.claude/sessions/1.json",
        HOME "/.claude/backups/b", HOME "/.claude/history.jsonl",
        HOME "/.claude/file-history/uuid/6ccb9ea1740990e8@v2",
        HOME "/.claude/session-env/x/hook.sh", HOME "/.claude/plugins/cache/p",
        HOME "/.npm/_cacache/x", HOME "/.npm/_logs/x.log",
        HOME "/.cache/claude-cli-nodejs/x.jsonl", HOME "/.config/Code/logs/x/cli.log",
        HOME "/.claude.json.tmp.426628.ba9822eb",
        HOME "/.claude/shell-snapshots/snapshot-bash-123-abc.sh",
        "/dev/null", "/dev/tty", "/sys/kernel/debug/tracing/trace_marker",
        "/tmp/claude-1000/-home-u-proj/tasks/x.output", "/tmp/claude-c8bd-cwd",
    };
    for (size_t i = 0; i < sizeof(noise) / sizeof(noise[0]); i++) {
        e = mk_open(noise[i], O_WRONLY | O_CREAT);
        if (rule_of(&e, P) != NULL)
            printf("  FAIL: expected no alert for %s\n", noise[i]), failures++;
    }

    /* Near misses must NOT be exempted -> outside-project-write. */
    const char *near_miss[] = {
        HOME "/.npmrc", HOME "/.cache/other/x", HOME "/evil.tmp",
        HOME "/.claude/plugins/evil", HOME "/.claude/x",
        HOME "/.claude.json.tmp.notapid.zz",     /* malformed staging name */
        "/dev/sda", "/proc/sys/kernel/x", "/sys/class/net/x", "/tmp/x",
        "/tmp/claude-evil/x",        /* not numeric -> no exemption */
        "/tmp/claude-9999/payload",  /* wrong uid (writer is 1000) -> no exemption */
        "/tmp/claude-18446744073709552616/x",  /* overflow must not wrap to 1000 */
        "/tmp/claude-00000000001000/x",        /* over-long padding -> rejected */
        "/tmp/claude-01000/x",                 /* zero-padded spelling -> rejected */
        "/tmp/claude-1000",          /* no trailing component -> no exemption */
        "/tmp/claude-x-cwd/sub",     /* cwd marker is exact-only */
        "/tmp/claude-evil-cwd",      /* non-hex token -> not the marker shape */
        "/tmp/claude-abc-cwd",       /* too short (<4 hex) -> not the shape */
        HOME "/.claude/shell-snapshots",   /* the dir itself, not a file under it */
    };
    for (size_t i = 0; i < sizeof(near_miss) / sizeof(near_miss[0]); i++) {
        e = mk_open(near_miss[i], O_WRONLY | O_CREAT);
        if (!is(rule_of(&e, P), "outside-project-write"))
            printf("  FAIL: expected outside-project-write for %s\n", near_miss[i]), failures++;
    }

    /* Persistence/activation WRITES -> persistence-sensitive-write (critical). */
    const char *persist[] = {
        HOME "/.bashrc", HOME "/.zshrc", HOME "/.profile", HOME "/.zshenv",
        HOME "/.gitconfig", HOME "/.config/git/config",
        HOME "/.claude.json", HOME "/.claude/settings.json",
        HOME "/.claude/settings.local.json",
        HOME "/.ssh/authorized_keys",
        HOME "/.config/autostart/x.desktop", HOME "/.config/systemd/user/x.service",
        HOME "/.local/share/systemd/user/x.service", HOME "/.config/environment.d/x.conf",
        "/etc/crontab", "/etc/cron.d/x", "/var/spool/cron/crontabs/u",
        "/etc/systemd/system/x.service", "/etc/profile", "/etc/profile.d/x.sh",
        "/etc/ld.so.preload", "/etc/ld.so.conf.d/x.conf",
        "/project/.git/hooks/pre-commit",   /* inside the project, still persistence */
    };
    for (size_t i = 0; i < sizeof(persist) / sizeof(persist[0]); i++) {
        e = mk_open(persist[i], O_WRONLY);
        if (!is(rule_of(&e, P), "persistence-sensitive-write"))
            printf("  FAIL: expected persistence-sensitive-write for %s\n", persist[i]), failures++;
    }

    /* READS of persistence targets are ordinary (a shell reads .bashrc always). */
    e = mk_open(HOME "/.bashrc", O_RDONLY);
    CHECK(rule_of(&e, P) == NULL);
    e = mk_open(HOME "/.claude.json", O_RDONLY);
    CHECK(rule_of(&e, P) == NULL);

    /* Precedence: protected beats persistence and noise. */
    e = mk_open(HOME "/.ssh/id_rsa", O_WRONLY);
    CHECK(is(rule_of(&e, P), "ssh-key-access"));

    /* Atomic replace: rename ONTO a persistence target is critical, and the
     * destination — not the exempt staging source — decides. */
    e = mk_rename(HOME "/.claude.json.tmp.426628.ab", HOME "/.claude.json");
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));
    e = mk_rename(HOME "/.claude/projects/a", HOME "/.claude/projects/b");
    CHECK(rule_of(&e, P) == NULL);

    /* A rename onto a PROTECTED destination keeps protected precedence, so a
     * file staged in an exempt runtime dir cannot replace credentials silently. */
    e = mk_rename(HOME "/.claude/projects/stage", HOME "/.aws/credentials");
    CHECK(is(rule_of(&e, P), "aws-credentials-access"));
    e = mk_rename(HOME "/.claude/projects/stage", "/project/.env");
    CHECK(is(rule_of(&e, P), "env-file-access"));
    e = mk_rename(HOME "/.claude/projects/stage", "/etc/sudoers");
    CHECK(is(rule_of(&e, P), "sudoers-access"));
    e = mk_rename(HOME "/.claude/projects/stage", HOME "/.ssh/id_rsa");
    CHECK(is(rule_of(&e, P), "ssh-key-access"));

    /* Path traversal must not defeat the exemption or the persistence rule:
     * a noise prefix followed by ".." resolves elsewhere, so the exemption is
     * refused (fail closed) and the resolved persistence target still fires. */
    e = mk_open(HOME "/.claude/projects/../../.bashrc", O_WRONLY);
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));
    e = mk_open(HOME "/.claude/projects/../evil", O_WRONLY | O_CREAT);
    CHECK(is(rule_of(&e, P), "outside-project-write"));
    e = mk_open(HOME "/.npm/_logs/../../.ssh/authorized_keys", O_WRONLY);
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));

    /* Fail-closed: without a trusted home, home-relative exemptions are OFF, so
     * a bookkeeping write is reported rather than silently dropped. */
    e = mk_open(HOME "/.claude/projects/s.jsonl", O_WRONLY | O_CREAT);
    CHECK(is(rule_of_nohome(&e, P), "outside-project-write"));
    /* ...and home-relative persistence is likewise not claimed (still reported). */
    e = mk_open(HOME "/.bashrc", O_WRONLY);
    CHECK(is(rule_of_nohome(&e, P), "outside-project-write"));
    /* Absolute persistence paths do not depend on home. */
    e = mk_open("/etc/cron.d/x", O_WRONLY);
    CHECK(is(rule_of_nohome(&e, P), "persistence-sensitive-write"));
    /* Absolute no-op sinks likewise stay exempt without a home. */
    e = mk_open("/dev/null", O_WRONLY);
    CHECK(rule_of_nohome(&e, P) == NULL);

    /* ---- TASK-B-014: deletion precedence (mirrors tests/test_policy.py) ---- */

    /* Compiler intermediates under /tmp are NOT exempt: recognizing forgeable
     * gcc temp filenames would be an attacker-controllable allowlist. */
    e = mk_open("/tmp/ccQ3Au8q.s", O_WRONLY | O_CREAT);
    strncpy(e.comm, "cc1", sizeof(e.comm) - 1);
    CHECK(is(rule_of(&e, P), "outside-project-write"));

    /* Deleting the agent's OWN uid-scoped scratch is disposable -> no alert. */
    e = mk_unlink("/tmp/claude-1000/-home-u-proj/uuid/scratchpad/hello", 1000);
    CHECK(rule_of(&e, P) == NULL);
    /* ...but another uid's directory is not the writer's own scratch. */
    e = mk_unlink("/tmp/claude-9999/-home-u-proj/uuid/scratchpad/hello", 1000);
    CHECK(is(rule_of(&e, P), "file-unlink"));

    /* Protected and persistence precedence applies to deletions too. */
    e = mk_unlink("/project/.env", 1000);
    CHECK(is(rule_of(&e, P), "env-file-access"));
    e = mk_unlink(HOME "/.bashrc", 1000);
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));
    e = mk_unlink(HOME "/.ssh/authorized_keys", 1000);
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));

    /* The WRITE allowlist is not reused wholesale: deleting history/backups is
     * destructive and stays reviewable. */
    e = mk_unlink(HOME "/.claude/history.jsonl", 1000);
    CHECK(is(rule_of(&e, P), "file-unlink"));
    e = mk_unlink(HOME "/.claude/backups/b", 1000);
    CHECK(is(rule_of(&e, P), "file-unlink"));
    e = mk_unlink("/dev/null", 1000);
    CHECK(is(rule_of(&e, P), "file-unlink"));
    /* Caches/logs the agent recreates freely are disposable. */
    e = mk_unlink(HOME "/.npm/_logs/x.log", 1000);
    CHECK(rule_of(&e, P) == NULL);

    /* In-project source deletion stays reviewable. */
    e = mk_unlink("/project/docs/hello.c", 1000);
    CHECK(is(rule_of(&e, P), "file-unlink"));

    /* RENAME_EXCHANGE swaps both files, so old_path is a destination too: an
     * exchange must not hide a sensitive target behind a benign new_path. */
    e = mk_rename(HOME "/.bashrc", "/project/benign.txt");
    e.flags = (1 << 1);   /* RENAME_EXCHANGE */
    e.uid = 1000;
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));
    e = mk_rename("/project/.env", "/project/benign.txt");
    e.flags = (1 << 1);
    e.uid = 1000;
    CHECK(is(rule_of(&e, P), "env-file-access"));
    /* Severity must win over target order: an ordinary outside new_path must
     * not mask a critical old_path on the other side of the exchange. */
    e = mk_rename(HOME "/.bashrc", "/tmp/ordinary-outside");
    e.flags = (1 << 1);
    e.uid = 1000;
    CHECK(is(rule_of(&e, P), "persistence-sensitive-write"));
    e = mk_rename("/project/.env", "/tmp/ordinary-outside");
    e.flags = (1 << 1);
    e.uid = 1000;
    CHECK(is(rule_of(&e, P), "env-file-access"));

    /* Without the flag, only the destination matters (plain rename). */
    e = mk_rename(HOME "/.bashrc", "/project/benign.txt");
    e.uid = 1000;
    CHECK(rule_of(&e, P) == NULL);

    /* Rename to an ordinary outside destination is an outside write. */
    e = mk_rename("/tmp/claude-1000/stage", "/tmp/payload");
    e.uid = 1000;
    CHECK(is(rule_of(&e, P), "outside-project-write"));

    if (failures == 0) {
        printf("C rule tests: all passed\n");
        return 0;
    }
    printf("C rule tests: %d check(s) FAILED\n", failures);
    return 1;
}
