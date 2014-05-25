/* ptrace_utils -- helper functions to not call ptrace manually            */

/* most of the provided functions are documented. The remaining ones should be documented or removed/placed elsewhere */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */


#include "ptrace_utils.h"
#include "sysdep.h"
#include <xbt.h>
#include "simterpose.h" // FIXME: remove that circular dependency. Currently needed for statistics purposes (create a stats module then)

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(PTRACE_UTILS, SIMTERPOSE, "ptrace utils log");

static char *syscall_list[] = {
		"read", "write", "open", "close", "stat", "fstat", "lstat", "poll", "lseek", "mmap", "mprotect", "munmap", "brk",
		"rt_sigaction", "rt_sigprocmask", "rt_sigreturn", "ioctl", "pread64", "pwrite64", "readv", "writev", "access", "pipe", "select",
		"sched_yield", "mremap", "msync", "mincore", "madvise", "shmget", "shmat", "shmctl", "dup", "dup2", "pause", "nanosleep", "getitimer",
		"alarm", "setitimer", "getpid", "sendfile", "socket", "connect", "accept", "sendto", "recvfrom", "sendmsg", "recvmsg", "shutdown", "bind",
		"listen", "getsockname", "getpeername", "socketpair", "setsockopt", "getsockopt", "clone", "fork", "vfork", "execve", "exit", "wait4",
		"kill", "uname", "semget", "semop", "semctl", "shmdt", "msgget", "msgsnd", "msgrcv", "msgctl", "fcntl", "flock", "fsync", "fdatasync",
		"truncate", "ftruncate", "getdents", "getcwd", "chdir", "fchdir", "rename", "mkdir", "rmdir", "creat", "link", "unlink", "symlink",
		"readlink", "chmod", "fchmod", "chown", "fchown", "lchown", "umask", "gettimeofday", "getrlimit", "getrusage", "sysinfo", "times", "ptrace",
		"getuid", "syslog", "getgid", "setuid", "setgid", "geteuid", "getegid", "setpgid", "getppid", "getpgrp", "setsid", "setreuid", "setregid",
		"getgroups", "setgroups", "setresuid", "getresuid", "setresgid", "getresgid", "getpgid", "setfsuid", "setfsgid", "getsid", "capget",
		"capset", "rt_sigpending", "rt_sigtimedwait", "rt_sigqueueinfo", "rt_sigsuspend", "sigaltstack", "utime", "mknod", "uselib", "personality",
		"ustat", "statfs", "fstatfs", "sysfs", "getpriority", "setpriority", "sched_setparam", "sched_getparam", "sched_setscheduler",
		"sched_getscheduler", "sched_get_priority_max", "sched_get_priority_min", "sched_rr_get_interval", "mlock", "munlock", "mlockall",
		"munlockall", "vhangup", "modify_ldt", "pivot_root", "_sysctl", "prctl", "arch_prctl", "adjtimex", "setrlimit", "chroot", "sync", "acct",
		"settimeofday", "mount", "umount2", "swapon", "swapoff", "reboot", "sethostname", "setdomainname", "iopl", "ioperm", "create_module",
		"init_module", "delete_module", "get_kernel_syms", "query_module", "quotactl", "nfsservctl", "getpmsg", "putpmsg", "afs_syscall", "tuxcall",
		"security", "gettid", "readahead", "setxattr", "lsetxattr", "fsetxattr", "getxattr", "lgetxattr", "fgetxattr", "listxattr", "llistxattr",
		"flistxattr", "removexattr", "lremovexattr", "fremovexattr", "tkill", "time", "futex", "sched_setaffinity", "sched_getaffinity",
		"set_thread_area", "io_setup", "io_destroy", "io_getevents", "io_submit", "io_cancel", "get_thread_area", "lookup_dcookie", "epoll_create",
		"epoll_ctl_old", "epoll_wait_old", "remap_file_pages", "getdents64", "set_tid_address", "restart_syscall", "semtimedop", "fadvise64",
		"timer_create", "timer_settime", "timer_gettime", "timer_getoverrun", "timer_delete", "clock_settime", "clock_gettime", "clock_getres",
		"clock_nanosleep", "exit_group", "epoll_wait", "epoll_ctl", "tgkill", "utimes", "vserver", "mbind", "set_mempolicy", "get_mempolicy",
		"mq_open", "mq_unlink", "mq_timedsend", "mq_timedreceive", "mq_notify", "mq_getsetattr", "kexec_load", "waitid", "add_key", "request_key",
		"keyctl", "ioprio_set", "ioprio_get", "inotify_init", "inotify_add_watch", "inotify_rm_watch", "migrate_pages", "openat", "mkdirat",
		"mknodat", "fchownat", "futimesat", "newfstatat", "unlinkat", "renameat", "linkat", "symlinkat", "readlinkat", "fchmodat", "faccessat",
		"pselect6", "ppoll", "unshare", "set_robust_list", "get_robust_list", "splice", "tee", "sync_file_range", "vmsplice", "move_pages",
		"utimensat", "epoll_pwait", "signalfd", "timerfd_create", "eventfd", "fallocate", "timerfd_settime", "timerfd_gettime", "accept4",
		"signalfd4", "eventfd2", "epoll_create1", "dup3", "pipe2", "inotify_init1", "preadv", "pwritev"
};

#define SYSERROR(...) THROWF(system_error, errno, __VA_ARGS__)


void ptrace_cpy(pid_t child, void *dst, void *src, size_t length, char *syscall)
{

  int i = 0;
  long size_copy = 0;

  errno = 0;
  long ret;
  size_t len = length & ~0x8;
  long *temp_dest = (long *) dst;

  while (size_copy < len) {
    ret = ptrace(PTRACE_PEEKDATA, child, src + i * sizeof(long), NULL);
    nb_peek++;

    if (ret == -1 && errno != 0)
      SYSERROR("%s : ptrace peekdata in %s\n", strerror(errno), syscall);

    *temp_dest = ret;
    ++temp_dest;
    size_copy += sizeof(long);
    i++;
  }
  size_t rest = length & 0x8;
  if (rest) {
    ret = ptrace(PTRACE_PEEKDATA, child, src + i * sizeof(long), NULL);
    nb_peek++;

    if (ret == -1 && errno != 0)
      SYSERROR("%s : ptrace peekdata in %s\n", strerror(errno), syscall);

    memcpy(temp_dest, &ret, rest);
  }
}

void ptrace_poke(pid_t pid, void *dst, void *src, size_t len)
{
  size_t size_copy = 0;
  long ret;
  errno = 0;
  while (size_copy < len) {
    ret = ptrace(PTRACE_POKEDATA, pid, dst + size_copy, *((long *) (src + size_copy)));
    nb_poke++;
    if (ret == -1 && errno != 0)
      SYSERROR("[%d] Unable to write at memory address %p\n", pid, dst);

    size_copy += sizeof(long);
  }
}

/** @brief restart the tracked process until its next syscall */
void ptrace_resume_process(const pid_t pid)
{
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL) == -1)
    SYSERROR("[%d] Error while resuming until next syscall: %s\n", pid, strerror(errno));
  nb_syscall++;
}

/** @brief the tracked process is dead, don't follow it anymore */
void ptrace_detach_process(const pid_t pid)
{
  if (ptrace(PTRACE_DETACH, pid, NULL, NULL) == -1)
	  SYSERROR("[%d] Error while detaching process: %s\n", pid, strerror(errno));
  nb_detach++;
}


int ptrace_record_socket(pid_t pid)
{
  struct user_regs_struct save_reg, reg;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &save_reg) == -1)
    SYSERROR("[%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;

  reg.orig_rax = SYS_socket;
  reg.rdi = AF_INET;
  reg.rsi = SOCK_STREAM;
  reg.rdx = 0;

  if (ptrace(PTRACE_SETREGS, pid, NULL, &reg) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_setregs++;
  ptrace_resume_process(pid);

  int status;
  waitpid(pid, &status, 0);

  if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;

  int res = (int) reg.rax;


  if (ptrace(PTRACE_SETREGS, pid, NULL, &save_reg) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_setregs++;
  ptrace_rewind_syscalls(pid);
  ptrace_resume_process(pid);

  waitpid(pid, &status, 0);

  return res;
}

/** @brief retrieve the registers of the tracked process and copy them into our nice architecture-independent structure */
void ptrace_get_register(const pid_t pid, reg_s * arg)
{
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));

  nb_getregs++;

  // FIXME: test architecture and use the right registers
  arg->reg_orig = regs.orig_rax;
  arg->ret = regs.rax;
  arg->arg1 = regs.rdi;
  arg->arg2 = regs.rsi;
  arg->arg3 = regs.rdx;
  arg->arg4 = regs.r10;
  arg->arg5 = regs.r8;
  arg->arg6 = regs.r9;
}

/** @brief Make sure that the syscall that the tracked process is about to do does nothing
 *
 * We rewrite the syscall to tuxcall() that is an ancien syscall that will never be implemented on linux (I hope so)
 */
void ptrace_neutralize_syscall(const pid_t pid)
{
  struct user_regs_struct regs;
  int status;
  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));

  nb_getregs++;
  XBT_DEBUG("neutralize syscall %s", syscall_list[regs.orig_rax]);
  regs.orig_rax = 184; /* FIXME: don't use the numerical value of SYS_tuxcall */
  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));

  nb_setregs++;
  ptrace_resume_process(pid);
  waitpid(pid, &status, 0);
}

/** @brief Fake the result of a syscall that was neutralized earlier
 *
 * We restore the syscall and put the result we like. This is typically used for syscalls
 * were we want simterpose to answer instead of the real kernel.
 */
void ptrace_restore_syscall(pid_t pid, unsigned long syscall, unsigned long result)
{
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;

  regs.orig_rax = syscall;
  regs.rax = result;

  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace setregs %s\n", pid, strerror(errno));
  nb_setregs++;
}

void ptrace_restore_syscall_arg1(pid_t pid, unsigned long syscall, unsigned long arg1)
{
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;

  regs.orig_rax = syscall;
  regs.rdi = arg1;

  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_setregs++;
}


void ptrace_rewind_syscalls(const pid_t pid)
{
  struct user_regs_struct regs;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;

  regs.rax = regs.orig_rax;
  regs.rip -= 2;

  if (ptrace(PTRACE_SETREGS, pid, NULL, &regs) == -1)
    SYSERROR(" [%d] ptrace getregs %s", pid, strerror(errno));
  nb_setregs++;

}

unsigned long ptrace_get_pid_fork(const pid_t pid)
{
  unsigned long new_pid;
  if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid) == -1)
    SYSERROR("[%d] ptrace geteventmsg %s", pid, strerror(errno));
  nb_geteventmsg++;
  return new_pid;
}

int ptrace_find_free_binding_port(const pid_t pid)
{
  struct user_regs_struct save_reg;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &save_reg) == -1)
    SYSERROR(" [%d] ptrace getregs %s", pid, strerror(errno));
  nb_getregs++;

  struct user_regs_struct reg;

  if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1)
    SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
  nb_getregs++;
  struct sockaddr_in in;
  struct sockaddr_in temp;
  ptrace_cpy(pid, &in, (void *) reg.rsi, reg.rdx, "");
  temp = in;

  static unsigned short port = 0;
  --port;
  int status;

  while (1) {
    temp.sin_port = htons(port);
    temp.sin_addr.s_addr = inet_addr("127.0.0.1");
    ptrace_poke(pid, (void *) reg.rsi, &temp, reg.rdx);
    ptrace_resume_process(pid);
    waitpid(pid, &status, 0);
    if (ptrace(PTRACE_GETREGS, pid, NULL, &reg) == -1)
      SYSERROR(" [%d] ptrace getregs %s\n", pid, strerror(errno));
    nb_getregs++;
    if (reg.rax == 0)
      break;

    --port;
    ptrace_rewind_syscalls(pid);
    ptrace_resume_process(pid);
    waitpid(pid, &status, 0);
  }
  ptrace_poke(pid, (void *) reg.rsi, &in, reg.rdx);

  return port;
}
