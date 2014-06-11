#include "syscall_process_msg.h"
#include "syscall_data_msg.h"
#include "sysdep.h"
#include "args_trace_msg.h"
#include "ptrace_utils_msg.h"
#include "print_syscall_msg.h"
#include "process_descriptor_msg.h"

#include "xbt.h"
#include "simdag/simdag.h"
#include "xbt/log.h"

#include <time.h>
#include <linux/futex.h>

#define SYSCALL_ARG1 rdi

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS_MSG, simterpose, "Syscall process log");


void process_handle_msg(process_descriptor_t * proc)
{
  reg_s arg;
  syscall_arg_u *sysarg = &(proc->sysarg);
  pid_t pid = proc->pid;
  ptrace_get_register(pid, &arg);
  XBT_DEBUG("found syscall: [%d] %s = %ld", pid, syscall_list[arg.reg_orig], arg.ret);

  switch (arg.reg_orig) {
  case SYS_read:
    get_args_read(pid, &arg, sysarg);
    print_read_syscall(pid, sysarg);
    break;

  case SYS_write:
    get_args_write(pid, &arg, sysarg);
    print_write_syscall(pid, sysarg);
    break;

    /* case SYS_open:
       break;

       case SYS_close:
       break; */

    // ignore SYS_stat, SYS_fstat, SYS_lstat

  case SYS_poll:
    get_args_poll(pid, &arg, sysarg);
    print_poll_syscall(pid, sysarg);
    break;

    // ignore SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
    // SYS_ioctl, SYS_pread64, SYS_pwrite64 , SYS_readv, SYS_writev, SYS_access, SYS_pipe

  case SYS_select:
    get_args_select(pid, &arg, sysarg);
    print_select_syscall(pid, sysarg);
    break;

    // ignore SYS_sched_yield, SYS_mremap, SYS_msync, SYS_mincore, SYS_madvise, SYS_shmget, SYS_shmat, SYS_shmctl
    // SYS_dup, SYS_dup2, SYS_pause, SYS_nanosleep, SYS_getitimer, SYS_alarm, SYS_setitimer, SYS_getpid, SYS_sendfile

    /* case SYS_socket:
       break;*/

       case SYS_connect:
    	   get_args_bind_connect(pid, &arg, sysarg);
       	   print_connect_syscall(pid, sysarg);
       break;

       case SYS_accept:
    	get_args_accept(pid, &arg, sysarg);
    	print_accept_syscall(pid, sysarg);
       break;

       case SYS_sendto:
    	get_args_sendto(pid, &arg, sysarg);
    	print_sendto_syscall(pid, sysarg);
       break;

       case SYS_recvfrom:
       	get_args_recvfrom(pid, &arg, sysarg);
       	print_recvfrom_syscall(pid, sysarg);
       break;

  case SYS_sendmsg:
    get_args_sendmsg(pid, &arg, sysarg);
    print_sendmsg_syscall(pid, sysarg);
    break;

  case SYS_recvmsg:
    get_args_recvmsg(pid, &arg, sysarg);
    print_recvmsg_syscall(pid, sysarg);
    break;

    /*  case SYS_shutdown:
       break;*/

       case SYS_bind:
       get_args_bind_connect(pid, &arg, sysarg);
       print_bind_syscall(pid, sysarg);
       break;

  case SYS_listen:
    get_args_listen(pid, &arg, sysarg);
    print_listen_syscall(pid, sysarg);
    break;

    // ignore SYS_getsockname

    /*   case SYS_getpeername:
       break;
     */
    // ignore SYS_socketpair

  case SYS_setsockopt:
    get_args_setsockopt(pid, &arg, sysarg);
    print_setsockopt_syscall(pid, sysarg);
    break;

  case SYS_getsockopt:
    get_args_getsockopt(pid, &arg, sysarg);
    print_getsockopt_syscall(pid, sysarg);
    break;

    // ignore SYS_clone, SYS_fork, SYS_vfork, SYS_execve

    /*  case SYS_exit:
       break; */

    // ignore SYS_wait4, SYS_kill, SYS_uname, SYS_semget, SYS_semop, SYS_semctl, SYS_shmdt, SYS_msgget, SYS_msgsnd, SYS_msgrcv, SYS_msgctl

  case SYS_fcntl:
    get_args_fcntl(pid, &arg, sysarg);
    print_fcntl_syscall(pid, sysarg);
    break;

    // ignore SYS_flock, SYS_fsync, SYS_fdatasync, SYS_truncate, SYS_ftruncate, SYS_getdents
    // ignore SYS_getcwd, SYS_chdir, SYS_fchdir, SYS_rename, SYS_mkdir, SYS_rmdir

    /*  case SYS_creat:
       break;

       // ignore SYS_link, SYS_unlink, SYS_symlink, SYS_readlink, SYS_chmod, SYS_fchmod, SYS_chown, SYS_fchown, SYS_lchown, SYS_umask

       case SYS_gettimeofday:
       break; */

    // ignore SYS_getrlimit, SYS_getrusage, SYS_sysinfo, SYS_times, SYS_ptrace, SYS_getuid, SYS_syslog, SYS_getgid, SYS_setuid
    // SYS_setgid, SYS_geteuid, SYS_getegid, SYS_setpgid, SYS_getppid, SYS_getpgrp, SYS_setsid, SYS_setreuid, SYS_setregid,
    // SYS_getgroups, SYS_setgroups, SYS_setresuid, SYS_getresuid, SYS_setresgid, SYS_getresgid, SYS_getpgid, SYS_setfsuid,
    // SYS_setfsgid, SYS_getsid, SYS_capget, SYS_capset, SYS_rt_sigpending, SYS_rt_sigtimedwait, SYS_rt_sigqueueinfo, SYS_rt_sigsuspend
    // SYS_sigaltstack, SYS_utime, SYS_mknod, SYS_uselib, SYS_personality, SYS_ustat, SYS_statfs, SYS_fstatfs
    // SYS_sysfs, SYS_getpriority, SYS_setpriority, SYS_sched_setparam, SYS_sched_getparam, SYS_sched_setscheduler, SYS_sched_getscheduler
    // SYS_sched_get_priority_max, SYS_sched_get_priority_min, SYS_sched_rr_get_interval, SYS_mlock, SYS_munlock, SYS_mlockall,
    // SYS_munlockall, SYS_vhangup, SYS_modify_ldt, SYS_pivot_root, SYS_sysctl, SYS_prctl, SYS_arch_prctl, SYS_adjtimex, SYS_etrlimit,
    // SYS_chroot, SYS_sync, SYS_acct, SYS_settimeofday, SYS_mount, SYS_umount2, SYS_swapon, SYS_swapoff, SYS_reboot
    // SYS_sethostname, SYS_setdomainname, SYS_iopl, SYS_ioperm, SYS_create_module, SYS_init_module, SYS_delete_module
    // SYS_get_kernel_syms, SYS_query_module, SYS_quotactl, SYS_nfsservctl, SYS_getpmsg, SYS_putpmsg, SYS_afs_syscall, SYS_tuxcall
    // SYS_security, SYS_gettid, SYS_readahead, SYS_setxattr, SYS_setxattr, SYS_fsetxattr, SYS_getxattr, SYS_lgetxattr, SYS_fgetxattr
    // SYS_listxattr, SYS_llistxattr, SYS_flistxattr, SYS_removexattr, SYS_lremovexattr, SYS_fremovexattr, SYS_tkill

    /* case SYS_time:
       break;

       // ignore SYS_futex, SYS_sched_setaffinity, SYS_sched_getaffinity, SYS_set_thread_area, SYS_io_setup, SYS_io_destroy, SYS_io_getevents,
       // SYS_io_submit, SYS_io_cancel, SYS_get_thread_area, SYS_lookup_dcookie, SYS_epoll_create, SYS_epoll_ctl_old,
       // SYS_epoll_wait_old, SYS_remap_file_pages, SYS_getdents64, SYS_set_tid_address, SYS_restart_syscall, SYS_semtimedop,
       // SYS_fadvise64, SYS_timer_create, SYS_timer_settime, SYS_timer_gettime, SYS_timer_getoverrun, SYS_timer_delete, SYS_clock_settime

       case SYS_clock_gettime:
       break;

       // ignore SYS_clock_getres, SYS_clock_nanosleep

       case SYS_exit_group:
       break; */

    // ignore SYS_epoll_wait, SYS_epoll_ctl, SYS_tgkill,
    // SYS_utimes, SYS_vserver, SYS_mbind, SYS_set_mempolicy, SYS_get_mempolicy, SYS_mq_open, SYS_mq_unlink, SYS_mq_timedsend,
    // SYS_mq_timedreceive, SYS_mq_notify, SYS_mq_getsetattr, SYS_kexec_load, SYS_waitid, SYS_add_key, SYS_request_key,
    // SYS_keyctl, SYS_ioprio_set, SYS_ioprio_get, SYS_inotify_init, SYS_inotify_add_watch, SYS_inotify_rm_watch,
    // SYS_migrate_pages, SYS_openat, SYS_mkdirat, SYS_mknodat, SYS_fchownat, SYS_futimesat, SYS_newfstatat, SYS_unlinkat,
    // SYS_renameat, SYS_linkat, SYS_symlinkat, SYS_readlinkat, SYS_fchmodat, SYS_faccessat, SYS_pselect6, SYS_ppoll
    // SYS_unshare, SYS_set_robust_list, SYS_get_robust_list, SYS_splice, SYS_tee, SYS_sync_file_range, SYS_vmsplice,
    // SYS_move_pages, SYS_utimensat, SYS_epoll_pwait, SYS_signalfd, SYS_timerfd_create, SYS_eventfd, SYS_allocate
    // SYS_timerfd_settime, SYS_timerfd_gettime, SYS_accept4, SYS_signalfd4, SYS_eventfd2, SYS_epoll_create1, SYS_dup3,
    // SYS_pipe2, SYS_inotify_init1, SYS_preadv, SYS_pwritev, SYS_rt_tgsigqueueinfo, SYS_perf_event_open, SYS_recvmmsg,
    // SYS_fanotify_init, SYS_fanotify_mark, SYS_prlimit64, SYS_name_to_handle_at, SYS_open_by_handle_at, SYS_clock_adjtime,
    // SYS_syncfs, SYS_sendmmsg, SYS_setns, SYS_getcpu, SYS_process_vm_readv, SYS_process_vm_writev, SYS_kcmp, SYS_finit_module

  default:
    XBT_DEBUG("Unhandled syscall: [%d] %s = %ld", pid, syscall_list[arg.reg_orig], arg.ret);
    break;
  }
}
