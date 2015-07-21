/* print_syscall -- Functions to print a strace-like log of
   syscalls */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef PRINT_SYSCALL_H
#define PRINT_SYSCALL_H

#include <sys/types.h>

#include <xbt/log.h>

#include "syscall_data.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"

// The XBT log appender that we use to write our logs to the corresponding files.
xbt_log_appender_t xbt_log_appender_strace_new(void);

void print_accept_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_connect_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_bind_syscall(reg_s * reg, process_descriptor_t * proc);

void print_socket_syscall(reg_s * reg, process_descriptor_t * proc);

void print_getsockopt_syscall(reg_s * reg, process_descriptor_t * proc);

void print_setsockopt_syscall(reg_s * reg, process_descriptor_t * proc);

void print_listen_syscall(reg_s * reg, process_descriptor_t * proc);

void print_sendto_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_recvfrom_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_recvmsg_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_sendmsg_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_poll_syscall(reg_s * reg, process_descriptor_t * proc, struct pollfd *fd_list, int timeout);

void print_select_syscall(reg_s * reg, process_descriptor_t * proc, int fd_state);

void print_fcntl_syscall(reg_s * reg, process_descriptor_t * proc);

void print_read_syscall(reg_s * reg, process_descriptor_t * proc);

void print_write_syscall(reg_s * reg, process_descriptor_t * proc);

void print_shutdown_syscall(reg_s * reg, process_descriptor_t * proc);

void print_getpeername_syscall(reg_s * reg, process_descriptor_t * proc);

void print_time_syscall(reg_s * reg, process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_gettimeofday_syscall(reg_s * reg, process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_clone_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_execve_syscall_pre(reg_s * reg, process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_execve_syscall_post(reg_s * reg, process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_open_syscall(reg_s * reg, process_descriptor_t * proc, syscall_arg_u * sysarg);

void stprintf(process_descriptor_t * proc, const char*fmt, ...);
void stprintf_tabto(process_descriptor_t * proc);
void stprintf_eol(process_descriptor_t * proc);
#endif
