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

/* Return the rule_id fired for an event under project root P, or NULL. */
static const char *rule_of(struct sysguard_event *e, const char *project)
{
    static struct sysguard_alert a;
    struct sysguard_rule_ctx ctx = { project };
    if (rules_evaluate(e, &ctx, &a))
        return a.rule_id;
    return NULL;
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

    if (failures == 0) {
        printf("C rule tests: all passed\n");
        return 0;
    }
    printf("C rule tests: %d check(s) FAILED\n", failures);
    return 1;
}
