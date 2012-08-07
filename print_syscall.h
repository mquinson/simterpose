#ifndef INCLUDED_PRINT_SYSCALL_H
#define INCLUDED_PRINT_SYSCALL_H

#include "syscall_data.h"

#include <sys/types.h>

void print_accept_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_connect_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_bind_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_socket_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_getsockopt_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_setsockopt_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_listen_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_recv_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_send_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_sendto_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_recvfrom_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_recvmsg_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_sendmsg_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_poll_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_select_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_fcntl_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_read_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_write_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_shutdown_syscall(pid_t pid, syscall_arg_u *sysarg);

void print_getpeername_syscall(pid_t pid, syscall_arg_u *sysarg);

void print_time_syscall(pid_t pid, syscall_arg_u *sysarg);

#endif