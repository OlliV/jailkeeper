#include <stdio.h>
#include <string.h>
#include "jailkeeper.h"

int install_filter(void)
{
    struct bpf_labels l;

    struct sock_filter filter[] = {
        LOAD_SYSCALL_NR,
        SYSCALL(__NR_read, ALLOW),
        SYSCALL(__NR_write, ALLOW),
        SYSCALL(__NR_open, ALLOW),
        SYSCALL(__NR_close, ALLOW),
        SYSCALL(__NR_stat, ALLOW),
        SYSCALL(__NR_fstat, ALLOW),
        SYSCALL(__NR_lstat, ALLOW),
        SYSCALL(__NR_poll, ALLOW),
        SYSCALL(__NR_lseek, ALLOW),
        SYSCALL(__NR_mmap, ALLOW),
        SYSCALL(__NR_mprotect, ALLOW),
        SYSCALL(__NR_munmap, ALLOW),
        SYSCALL(__NR_brk, ALLOW),
        SYSCALL(__NR_rt_sigaction, ALLOW),
        SYSCALL(__NR_rt_sigprocmask, ALLOW),
        SYSCALL(__NR_rt_sigreturn, ALLOW),
        SYSCALL(__NR_ioctl, ALLOW),
        SYSCALL(__NR_pread64, ALLOW),
        SYSCALL(__NR_pwrite64, ALLOW),
        SYSCALL(__NR_readv, ALLOW),
        SYSCALL(__NR_writev, ALLOW),
        SYSCALL(__NR_access, ALLOW),
        SYSCALL(__NR_pipe, ALLOW),
        SYSCALL(__NR_select, ALLOW),
        SYSCALL(__NR_sched_yield, ALLOW),
        SYSCALL(__NR_mremap, ALLOW),
        SYSCALL(__NR_msync, ALLOW),
        SYSCALL(__NR_mincore, ALLOW),
        SYSCALL(__NR_madvise, ALLOW),
        SYSCALL(__NR_shmget, ALLOW),
        SYSCALL(__NR_shmat, ALLOW),
        SYSCALL(__NR_shmctl, ALLOW),
        SYSCALL(__NR_dup, ALLOW),
        SYSCALL(__NR_dup2, ALLOW),
        SYSCALL(__NR_pause, ALLOW),
        SYSCALL(__NR_nanosleep, ALLOW),
        SYSCALL(__NR_getitimer, ALLOW),
        SYSCALL(__NR_alarm, ALLOW),
        SYSCALL(__NR_setitimer, ALLOW),
        SYSCALL(__NR_getpid, ALLOW),
#if 0
        SYSCALL(__NR_sendfile, ALLOW),
        SYSCALL(__NR_socket, ALLOW),
        SYSCALL(__NR_connect, ALLOW),
        SYSCALL(__NR_accept, ALLOW),
        SYSCALL(__NR_sendto, ALLOW),
        SYSCALL(__NR_recvfrom, ALLOW),
        SYSCALL(__NR_sendmsg, ALLOW),
        SYSCALL(__NR_recvmsg, ALLOW),
        SYSCALL(__NR_shutdown, ALLOW),
        SYSCALL(__NR_bind, ALLOW),
        SYSCALL(__NR_listen, ALLOW),
        SYSCALL(__NR_getsockname, ALLOW),
        SYSCALL(__NR_getpeername, ALLOW),
        SYSCALL(__NR_socketpair, ALLOW),
        SYSCALL(__NR_setsockopt, ALLOW),
        SYSCALL(__NR_getsockopt, ALLOW),
        SYSCALL(__NR_clone, ALLOW),
        SYSCALL(__NR_fork, ALLOW),
        SYSCALL(__NR_vfork, ALLOW),
#endif
        SYSCALL(__NR_execve, CHECK),
        SYSCALL(__NR_exit, ALLOW),
        SYSCALL(__NR_wait4, ALLOW),
#if 0
        SYSCALL(__NR_kill, ALLOW),
#endif
        SYSCALL(__NR_uname, ALLOW),
        SYSCALL(__NR_semget, ALLOW),
        SYSCALL(__NR_semop, ALLOW),
        SYSCALL(__NR_semctl, ALLOW),
        SYSCALL(__NR_shmdt, ALLOW),
        SYSCALL(__NR_msgget, ALLOW),
        SYSCALL(__NR_msgsnd, ALLOW),
        SYSCALL(__NR_msgrcv, ALLOW),
        SYSCALL(__NR_msgctl, ALLOW),
        SYSCALL(__NR_fcntl, ALLOW),
        SYSCALL(__NR_flock, ALLOW),
        SYSCALL(__NR_fsync, ALLOW),
        SYSCALL(__NR_fdatasync, ALLOW),
        SYSCALL(__NR_truncate, ALLOW),
        SYSCALL(__NR_ftruncate, ALLOW),
        SYSCALL(__NR_getdents, ALLOW),
        SYSCALL(__NR_getcwd, ALLOW),
#if 0
        SYSCALL(__NR_chdir, ALLOW),
        SYSCALL(__NR_fchdir, ALLOW),
        SYSCALL(__NR_rename, ALLOW),
        SYSCALL(__NR_mkdir, ALLOW),
        SYSCALL(__NR_rmdir, ALLOW),
        SYSCALL(__NR_creat, ALLOW),
        SYSCALL(__NR_link, ALLOW),
        SYSCALL(__NR_unlink, ALLOW),
        SYSCALL(__NR_symlink, ALLOW),
#endif
        SYSCALL(__NR_readlink, ALLOW),
#if 0
        SYSCALL(__NR_chmod, ALLOW),
        SYSCALL(__NR_fchmod, ALLOW),
        SYSCALL(__NR_chown, ALLOW),
        SYSCALL(__NR_fchown, ALLOW),
        SYSCALL(__NR_lchown, ALLOW),
        SYSCALL(__NR_umask, ALLOW),
#endif
        SYSCALL(__NR_gettimeofday, ALLOW),
        SYSCALL(__NR_getrlimit, ALLOW),
        SYSCALL(__NR_getrusage, ALLOW),
        SYSCALL(__NR_sysinfo, ALLOW),
        SYSCALL(__NR_times, ALLOW),
#if 0
        SYSCALL(__NR_ptrace, ALLOW),
#endif
        SYSCALL(__NR_getuid, ALLOW),
        SYSCALL(__NR_syslog, ALLOW),
#if 0
        SYSCALL(__NR_getgid, ALLOW),
        SYSCALL(__NR_setuid, ALLOW),
        SYSCALL(__NR_setgid, ALLOW),
#endif
        SYSCALL(__NR_geteuid, ALLOW),
        SYSCALL(__NR_getegid, ALLOW),
#if 0
        SYSCALL(__NR_setpgid, ALLOW),
        SYSCALL(__NR_getppid, ALLOW),
        SYSCALL(__NR_getpgrp, ALLOW),
        SYSCALL(__NR_setsid, ALLOW),
        SYSCALL(__NR_setreuid, ALLOW),
        SYSCALL(__NR_setregid, ALLOW),
        SYSCALL(__NR_getgroups, ALLOW),
        SYSCALL(__NR_setgroups, ALLOW),
        SYSCALL(__NR_setresuid, ALLOW),
        SYSCALL(__NR_getresuid, ALLOW),
        SYSCALL(__NR_setresgid, ALLOW),
        SYSCALL(__NR_getresgid, ALLOW),
#endif
        SYSCALL(__NR_getpgid, ALLOW),
#if 0
        SYSCALL(__NR_setfsuid, ALLOW),
        SYSCALL(__NR_setfsgid, ALLOW),
#endif
        SYSCALL(__NR_getsid, ALLOW),
        SYSCALL(__NR_capget, ALLOW),
        SYSCALL(__NR_capset, ALLOW),
        SYSCALL(__NR_rt_sigpending, ALLOW),
        SYSCALL(__NR_rt_sigtimedwait, ALLOW),
        SYSCALL(__NR_rt_sigqueueinfo, ALLOW),
        SYSCALL(__NR_rt_sigsuspend, ALLOW),
        SYSCALL(__NR_sigaltstack, ALLOW),
        SYSCALL(__NR_utime, ALLOW),
        SYSCALL(__NR_mknod, ALLOW),
        SYSCALL(__NR_uselib, ALLOW),
        SYSCALL(__NR_personality, ALLOW),
        SYSCALL(__NR_ustat, ALLOW),
        SYSCALL(__NR_statfs, ALLOW),
        SYSCALL(__NR_fstatfs, ALLOW),
        SYSCALL(__NR_sysfs, ALLOW),
        SYSCALL(__NR_getpriority, ALLOW),
        SYSCALL(__NR_setpriority, ALLOW),
#if 0
        SYSCALL(__NR_sched_setparam, ALLOW),
#endif
        SYSCALL(__NR_sched_getparam, ALLOW),
#if 0
        SYSCALL(__NR_sched_setscheduler, ALLOW),
        SYSCALL(__NR_sched_getscheduler, ALLOW),
#endif
        SYSCALL(__NR_sched_get_priority_max, ALLOW),
        SYSCALL(__NR_sched_get_priority_min, ALLOW),
        SYSCALL(__NR_sched_rr_get_interval, ALLOW),
        SYSCALL(__NR_mlock, ALLOW),
        SYSCALL(__NR_munlock, ALLOW),
        SYSCALL(__NR_mlockall, ALLOW),
        SYSCALL(__NR_munlockall, ALLOW),
        SYSCALL(__NR_vhangup, ALLOW),
#if 0
        SYSCALL(__NR_modify_ldt, ALLOW),
        SYSCALL(__NR_pivot_root, ALLOW),
        SYSCALL(__NR__sysctl, ALLOW),
        SYSCALL(__NR_prctl, ALLOW),
#endif
        SYSCALL(__NR_arch_prctl, ALLOW),
#if 0
        SYSCALL(__NR_adjtimex, ALLOW),
        SYSCALL(__NR_setrlimit, ALLOW),
        SYSCALL(__NR_chroot, ALLOW),
        SYSCALL(__NR_sync, ALLOW),
        SYSCALL(__NR_acct, ALLOW),
        SYSCALL(__NR_settimeofday, ALLOW),
        SYSCALL(__NR_mount, ALLOW),
        SYSCALL(__NR_umount2, ALLOW),
        SYSCALL(__NR_swapon, ALLOW),
        SYSCALL(__NR_swapoff, ALLOW),
        SYSCALL(__NR_reboot, ALLOW),
        SYSCALL(__NR_sethostname, ALLOW),
        SYSCALL(__NR_setdomainname, ALLOW),
        SYSCALL(__NR_iopl, ALLOW),
        SYSCALL(__NR_ioperm, ALLOW),
        SYSCALL(__NR_create_module, ALLOW),
        SYSCALL(__NR_init_module, ALLOW),
        SYSCALL(__NR_delete_module, ALLOW),
        SYSCALL(__NR_get_kernel_syms, ALLOW),
        SYSCALL(__NR_query_module, ALLOW),
        SYSCALL(__NR_quotactl, ALLOW),
        SYSCALL(__NR_nfsservctl, ALLOW),
#endif
        SYSCALL(__NR_getpmsg, ALLOW),
        SYSCALL(__NR_putpmsg, ALLOW),
        SYSCALL(__NR_afs_syscall, ALLOW),
#if 0
        SYSCALL(__NR_tuxcall, ALLOW),
#endif
        SYSCALL(__NR_security, ALLOW),
        SYSCALL(__NR_gettid, ALLOW),
        SYSCALL(__NR_readahead, ALLOW),
        SYSCALL(__NR_setxattr, ALLOW),
        SYSCALL(__NR_lsetxattr, ALLOW),
        SYSCALL(__NR_fsetxattr, ALLOW),
        SYSCALL(__NR_getxattr, ALLOW),
        SYSCALL(__NR_lgetxattr, ALLOW),
        SYSCALL(__NR_fgetxattr, ALLOW),
        SYSCALL(__NR_listxattr, ALLOW),
        SYSCALL(__NR_llistxattr, ALLOW),
        SYSCALL(__NR_flistxattr, ALLOW),
        SYSCALL(__NR_removexattr, ALLOW),
        SYSCALL(__NR_lremovexattr, ALLOW),
        SYSCALL(__NR_fremovexattr, ALLOW),
        SYSCALL(__NR_tkill, ALLOW),
        SYSCALL(__NR_time, ALLOW),
        SYSCALL(__NR_futex, ALLOW),
#if 0
        SYSCALL(__NR_sched_setaffinity, ALLOW),
        SYSCALL(__NR_sched_getaffinity, ALLOW),
        SYSCALL(__NR_set_thread_area, ALLOW),
        SYSCALL(__NR_io_setup, ALLOW),
        SYSCALL(__NR_io_destroy, ALLOW),
        SYSCALL(__NR_io_getevents, ALLOW),
        SYSCALL(__NR_io_submit, ALLOW),
        SYSCALL(__NR_io_cancel, ALLOW),
        SYSCALL(__NR_get_thread_area, ALLOW),
        SYSCALL(__NR_lookup_dcookie, ALLOW),
        SYSCALL(__NR_epoll_create, ALLOW),
        SYSCALL(__NR_epoll_ctl_old, ALLOW),
        SYSCALL(__NR_epoll_wait_old, ALLOW),
        SYSCALL(__NR_remap_file_pages, ALLOW),
#endif
        SYSCALL(__NR_getdents64, ALLOW),
        SYSCALL(__NR_set_tid_address, ALLOW),
#if 0
        SYSCALL(__NR_restart_syscall, ALLOW),
        SYSCALL(__NR_semtimedop, ALLOW),
#endif
        SYSCALL(__NR_fadvise64, ALLOW),
        SYSCALL(__NR_timer_create, ALLOW),
        SYSCALL(__NR_timer_settime, ALLOW),
        SYSCALL(__NR_timer_gettime, ALLOW),
        SYSCALL(__NR_timer_getoverrun, ALLOW),
        SYSCALL(__NR_timer_delete, ALLOW),
#if 0
        SYSCALL(__NR_clock_settime, ALLOW),
#endif
        SYSCALL(__NR_clock_gettime, ALLOW),
        SYSCALL(__NR_clock_getres, ALLOW),
        SYSCALL(__NR_clock_nanosleep, ALLOW),
        SYSCALL(__NR_exit_group, ALLOW),
        SYSCALL(__NR_epoll_wait, ALLOW),
        SYSCALL(__NR_epoll_ctl, ALLOW),
        SYSCALL(__NR_tgkill, ALLOW),
        SYSCALL(__NR_utimes, ALLOW),
        SYSCALL(__NR_vserver, ALLOW),
        SYSCALL(__NR_mbind, ALLOW),
#if 0
        SYSCALL(__NR_set_mempolicy, ALLOW),
        SYSCALL(__NR_get_mempolicy, ALLOW),
#endif
        SYSCALL(__NR_mq_open, ALLOW),
        SYSCALL(__NR_mq_unlink, ALLOW),
        SYSCALL(__NR_mq_timedsend, ALLOW),
        SYSCALL(__NR_mq_timedreceive, ALLOW),
        SYSCALL(__NR_mq_notify, ALLOW),
        SYSCALL(__NR_mq_getsetattr, ALLOW),
#if 0
        SYSCALL(__NR_kexec_load, ALLOW),
#endif
        SYSCALL(__NR_waitid, ALLOW),
#if 0
        SYSCALL(__NR_add_key, ALLOW),
        SYSCALL(__NR_request_key, ALLOW),
        SYSCALL(__NR_keyctl, ALLOW),
        SYSCALL(__NR_ioprio_set, ALLOW),
        SYSCALL(__NR_ioprio_get, ALLOW),
#endif
        SYSCALL(__NR_inotify_init, ALLOW),
        SYSCALL(__NR_inotify_add_watch, ALLOW),
        SYSCALL(__NR_inotify_rm_watch, ALLOW),
        SYSCALL(__NR_migrate_pages, ALLOW),
        SYSCALL(__NR_openat, ALLOW),
#if 0
        SYSCALL(__NR_mkdirat, ALLOW),
        SYSCALL(__NR_mknodat, ALLOW),
        SYSCALL(__NR_fchownat, ALLOW),
        SYSCALL(__NR_futimesat, ALLOW),
        SYSCALL(__NR_newfstatat, ALLOW),
        SYSCALL(__NR_unlinkat, ALLOW),
        SYSCALL(__NR_renameat, ALLOW),
        SYSCALL(__NR_linkat, ALLOW),
        SYSCALL(__NR_symlinkat, ALLOW),
#endif
        SYSCALL(__NR_readlinkat, ALLOW),
#if 0
        SYSCALL(__NR_fchmodat, ALLOW),
#endif
        SYSCALL(__NR_faccessat, ALLOW),
        SYSCALL(__NR_pselect6, ALLOW),
        SYSCALL(__NR_ppoll, ALLOW),
        SYSCALL(__NR_unshare, ALLOW),
        SYSCALL(__NR_set_robust_list, ALLOW),
        SYSCALL(__NR_get_robust_list, ALLOW),
        SYSCALL(__NR_splice, ALLOW),
        SYSCALL(__NR_tee, ALLOW),
        SYSCALL(__NR_sync_file_range, ALLOW),
#if 0
        SYSCALL(__NR_vmsplice, ALLOW),
        SYSCALL(__NR_move_pages, ALLOW),
        SYSCALL(__NR_utimensat, ALLOW),
        SYSCALL(__NR_epoll_pwait, ALLOW),
        SYSCALL(__NR_signalfd, ALLOW),
        SYSCALL(__NR_timerfd_create, ALLOW),
        SYSCALL(__NR_eventfd, ALLOW),
        SYSCALL(__NR_fallocate, ALLOW),
        SYSCALL(__NR_timerfd_settime, ALLOW),
        SYSCALL(__NR_timerfd_gettime, ALLOW),
        SYSCALL(__NR_accept4, ALLOW),
        SYSCALL(__NR_signalfd4, ALLOW),
        SYSCALL(__NR_eventfd2, ALLOW),
        SYSCALL(__NR_epoll_create1, ALLOW),
        SYSCALL(__NR_dup3, ALLOW),
        SYSCALL(__NR_pipe2, ALLOW),
        SYSCALL(__NR_inotify_init1, ALLOW),
#endif
        SYSCALL(__NR_preadv, ALLOW),
        SYSCALL(__NR_pwritev, ALLOW),
#if 0
        SYSCALL(__NR_rt_tgsigqueueinfo, ALLOW),
        SYSCALL(__NR_perf_event_open, ALLOW),
        SYSCALL(__NR_recvmmsg, ALLOW),
        SYSCALL(__NR_fanotify_init, ALLOW),
        SYSCALL(__NR_fanotify_mark, ALLOW),
        SYSCALL(__NR_prlimit64, ALLOW),
        SYSCALL(__NR_name_to_handle_at, ALLOW),
        SYSCALL(__NR_open_by_handle_at, ALLOW),
        SYSCALL(__NR_clock_adjtime, ALLOW),
        SYSCALL(__NR_syncfs, ALLOW),
        SYSCALL(__NR_sendmmsg, ALLOW),
        SYSCALL(__NR_setns, ALLOW),
        SYSCALL(__NR_getcpu, ALLOW),
#endif
        SYSCALL(__NR_process_vm_readv, ALLOW),
        SYSCALL(__NR_process_vm_writev, ALLOW),
        DENY,
    };

    struct sock_fprog prog = {
        .filter = filter,
        .len = (unsigned short)num_elem(filter),
    };
    bpf_resolve_jumps(&l, filter, num_elem(filter));

    return jk_apply_filter(&prog);
}

RULE_CHECKER(__NR_execve)
{
    char * str;

#ifdef DEBUG
    fprintf(stderr, "execve checker\n");
#endif

    if (arg1 == 0)
        return 0;

    str = jk_read_string(child, arg1);
    if (!str)
        return 1;

#ifdef DEBUG
    fprintf(stderr, "0x%016lx, \"%s\"\n", arg1, str);
#endif

    //if (strcmp(str, "./ttest"))
    if (strcmp(str, prog_path))
        return 1;

    return 0;
}
