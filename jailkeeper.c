/*
 * Seccomp jailkeeper.
 *
 * Copyright (c) 2014 Olli Vanhoja
 * Copyright (c) 2012 The Chromium OS Authors <chromium-os-dev@chromium.org>
 * Author: Will Drewry <wad@chromium.org>
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using prctl(PR_SET_SECCOMP, 2, ...).
 *
 * When run, returns the specified errno for the specified
 * system call number against the given architecture.
 *
 * Run this one as root as PR_SET_NO_NEW_PRIVS is not called.
 */

#include <errno.h>
#include <linux/filter.h>
#include <linux/seccomp.h>
#include <linux/unistd.h>
#include <stdio.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/prctl.h>
#include <sys/reg.h>
#include <sys/types.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <signal.h>
#include "jailkeeper.h"

#ifndef PR_SET_NO_NEW_PRIVS
#define PR_SET_NO_NEW_PRIVS 38
#endif

char * prog_path;

int jk_install_filter(struct sock_fprog * prog)
{
    if (prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0)) {
        perror("prctl(NO_NEW_PRIVS)");
        return 1;
    }

    if (prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, prog)) {
        perror("prctl(SECCOMP)");
        return 1;
    }

#ifdef DEBUG
    fprintf(stderr, "OK\n");
#endif

    return 0;
}

void jk_set_syscall_nr(pid_t child, unsigned long new_syscall)
{
    ptrace(PTRACE_POKEUSER, child, sizeof(long)*ORIG_RAX, new_syscall);
}

char * jk_read_string(pid_t child, unsigned long addr)
{
    char * val;
    int allocated = 4096, rd = 0;
    unsigned long tmp;

    val = malloc(allocated);
    if (!val)
        return NULL;

    while (1) {
        if (rd + sizeof(tmp) > allocated) {
            allocated *= 2;
            val = realloc(val, allocated);
            if (!val)
                return NULL;
        }

        errno = 0;
        tmp = ptrace(PTRACE_PEEKDATA, child, addr + rd);
        if (errno) {
#ifdef DEBUG
            char buf[80];

            snprintf(buf, sizeof(buf), "ptrace(PTRACE_PEEKDATA, %d, 0x%016lx)",
                     child, addr + rd);
            perror(buf);
#endif
            free(val);
            return NULL;
        }

        memcpy(val + rd, &tmp, sizeof(tmp));
        if (memchr(&tmp, 0, sizeof(tmp)) != NULL)
            break;
        rd += sizeof(tmp);
    }

    return val;
}

static void monitor(pid_t child)
{
    int status, syscall, new_syscall;
    long retcode;
    long arg1, arg2, arg3, arg4, arg5, arg6;
    rule_checker fn;

    waitpid(child, &status, 0);
    if (!WSTOPSIG(status))
        return;

    ptrace(PTRACE_SETOPTIONS, child, 0, PTRACE_O_TRACESECCOMP);

    while (1) {
        ptrace(PTRACE_CONT, child, NULL, NULL);
        waitpid(child, &status, 0);
        if (WIFEXITED(status)) {
            fprintf(stderr, "\nChild exit with status %d\n", WEXITSTATUS(status));
            break;
        }
        if (WIFSIGNALED(status)) {
            fprintf(stderr, "\nChild terminated to signal %d\n", WTERMSIG(status));
            break;
        }

        syscall = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*ORIG_RAX);
        retcode = ptrace(PTRACE_PEEKUSER, child, sizeof(long)*RAX);

        /*
         * retcode is set to -ENOSYS if this is a syscall entry.
         */
        if (retcode != -ENOSYS)
            continue;

#ifdef DEBUG
        fprintf(stderr, "syscall(%d)\n", syscall);
#endif

        if (syscall == -1) {
            kill(child, SIGKILL);
            break;
        }

        /*
         * Set syscall nr to -1 so child can't execute that syscall even if
         * the jailkeeper will segfault.
         */
        jk_set_syscall_nr(child, -1);
        new_syscall = -1;

        arg1 = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RDI);
        arg2 = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RSI);
        arg3 = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RDX);
        arg4 = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * RCX);
        arg5 = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * R8);
        arg6 = ptrace(PTRACE_PEEKUSER, child, sizeof(long) * R9);

        fn = jk_get_checker(syscall);

#ifdef DEBUG
        fprintf(stderr,
                "chk[%p](%d, %d, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx, 0x%lx)\n",
                fn, child, syscall, arg1, arg2, arg3, arg4, arg5, arg6);
#endif
        if (fn && !fn(child, syscall, arg1, arg2, arg3, arg4, arg5, arg6)) {
            /* Restore syscall, permission granted. */
            new_syscall = syscall;
        }

        jk_set_syscall_nr(child, new_syscall);
        if (new_syscall == -1) {
            fprintf(stderr, "\nSyscall denied (%d)\n", syscall);
            kill(child, SIGKILL);
            break;
        }
    }
}

int main(int argc, char **argv)
{
    pid_t child;

    if (argc < 2) {
        fprintf(stderr,
            "Usage:\n"
            "%s <prog> [<args>]\n\n",
            argv[0]);
        return 1;
    }
    prog_path = argv[1];

    child = fork();
    if(child == 0) {
        ptrace(PTRACE_TRACEME, 0, NULL, NULL);
        kill(getpid(), SIGSTOP);

#ifdef DEBUG
        fprintf(stderr, "Dropping privileges...");
#endif
        if (apply_rules())
            return 1;

#ifdef DEBUG
        fprintf(stderr, "execvp((%p)\"%s\" ...)\n", prog_path, prog_path);
#endif
        execvp(prog_path, &argv[1]);
        perror("Failed to execv");

        return 255;
    } else if (child < 0) {
        return 255;
    }

    monitor(child);

    return 0;
}
