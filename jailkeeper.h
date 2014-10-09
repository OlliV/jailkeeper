/*
 * Seccomp jailkeeper.
 *
 * Copyright (c) 2014 Olli Vanhoja
 *
 * The code may be used by anyone for any purpose,
 * and can serve as a starting point for developing
 * applications using prctl(PR_ATTACH_SECCOMP_FILTER).
 */

#ifndef JAILKEEPER_H
#define JAILKEEPER_H

#include <stddef.h>
#include <stdint.h>
#include <unistd.h>
#include "bpf-helper.h"

#ifndef num_elem
#define num_elem(x) (sizeof(x) / sizeof(*(x)))
#endif

#define RULE_CHECKER_ARGS pid_t child, int nr_syscall, \
                          intptr_t arg1, intptr_t arg2, intptr_t arg3, \
                          intptr_t arg4, intptr_t arg5, intptr_t arg6

/**
 * @return 0 if OK; 1 if NOK
 */
typedef int (*rule_checker)(RULE_CHECKER_ARGS);

#define RULE_CHECKER(nr_sys) int __CONCAT(_sysrulecheck_, nr_sys)(RULE_CHECKER_ARGS)

extern char * prog_path;

rule_checker jk_get_checker(int nr_syscall);
void jk_set_syscall_nr(pid_t child, unsigned long new_syscall);
int jk_install_filter(struct sock_fprog * prog);
char * jk_read_string(pid_t child, unsigned long addr);

/* Defined in rules.c */
int apply_rules(void);

#endif /* JAILKEEPER_H */
