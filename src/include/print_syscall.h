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

void print_accept_syscall(reg_s * reg, process_descriptor_t * proc);

void print_connect_syscall(reg_s * reg, process_descriptor_t * proc);

void print_bind_syscall(reg_s * reg, process_descriptor_t * proc);

void print_socket_syscall(reg_s * reg, process_descriptor_t * proc);

void print_getsockopt_syscall(reg_s * reg, process_descriptor_t * proc);

void print_setsockopt_syscall(reg_s * reg, process_descriptor_t * proc);

void print_listen_syscall(reg_s * reg, process_descriptor_t * proc);

void print_send_syscall(reg_s * reg, process_descriptor_t * proc, void * data);

void print_recv_syscall(reg_s * reg, process_descriptor_t * proc, void * data);

void print_sendto_syscall(reg_s * reg, process_descriptor_t * proc, void * data, int is_addr, socklen_t addrlen, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl);

void print_recvfrom_syscall(reg_s * reg, process_descriptor_t * proc, void * data, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl, int is_addr, socklen_t addrlen);

void print_recvmsg_syscall(reg_s * reg, process_descriptor_t * proc, struct msghdr * msg);

void print_sendmsg_syscall(reg_s * reg, process_descriptor_t * proc, int len, void * data, 
  struct msghdr * msg);

void print_poll_syscall(reg_s * reg, process_descriptor_t * proc, struct pollfd *fd_list, int timeout);

void print_select_syscall(reg_s * reg, process_descriptor_t * proc, int fd_state);

void print_fcntl_syscall(reg_s * reg, process_descriptor_t * proc);

void print_lseek_syscall(reg_s * reg, process_descriptor_t * proc);

void print_read_syscall(reg_s * reg, process_descriptor_t * proc);

void print_write_syscall(reg_s * reg, process_descriptor_t * proc);

void print_shutdown_syscall(reg_s * reg, process_descriptor_t * proc);

void print_getpeername_syscall(reg_s * reg, process_descriptor_t * proc);

void print_clone_syscall(reg_s * reg, process_descriptor_t * proc);

void print_execve_syscall_pre(reg_s * reg, process_descriptor_t * proc);

void print_execve_syscall_post(reg_s * reg, process_descriptor_t * proc);

void print_open_syscall(reg_s * reg, process_descriptor_t * proc);

void print_creat_syscall(reg_s * reg, process_descriptor_t * proc);

void print_close_syscall(reg_s * reg, process_descriptor_t * proc);

void print_tuxcall_syscall(reg_s * reg, process_descriptor_t * proc);

void stprintf(process_descriptor_t * proc, const char*fmt, ...);
void stprintf_tabto(process_descriptor_t * proc);
void stprintf_eol(process_descriptor_t * proc);
#endif
