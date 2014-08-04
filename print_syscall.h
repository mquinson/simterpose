/* print_syscall --  functions to print a strace-like log of syscalls */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */

#ifndef PRINT_SYSCALL_H
#define PRINT_SYSCALL_H

#include "syscall_data.h"
#include "process_descriptor.h"

#include <sys/types.h>

void print_accept_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_connect_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_bind_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_socket_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_getsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_setsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_listen_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_recv_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_send_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_sendto_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_recvfrom_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_recvmsg_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_sendmsg_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_poll_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_select_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_fcntl_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_read_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_write_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_shutdown_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_getpeername_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_time_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_gettimeofday_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_clone_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_execve_syscall_pre(process_descriptor_t * proc, syscall_arg_u * sysarg);

void print_execve_syscall_post(process_descriptor_t * proc, syscall_arg_u * sysarg);

#endif
