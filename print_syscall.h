#ifndef INCLUDED_PRINT_SYSCALL_H
#define INCLUDED_PRINT_SYSCALL_H

#include "args_trace.h"

#include <sys/types.h>

void print_accept_syscall(pid_t pid, accept_arg_t arg);

void print_connect_syscall(pid_t pid, connect_arg_t arg);

void print_bind_syscall(pid_t pid, syscall_arg_u* sysarg);

void print_socket_syscall(pid_t pid, syscall_arg_u* sysarg);


#endif