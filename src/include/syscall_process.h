/* syscall_process -- Handlers every syscall at the entrance/exit. */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef SYSCALL_PROCESS_H
#define SYSCALL_PROCESS_H

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "sockets.h"
#include "syscall_data.h"
#include "communication.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "syscall_data.h"

/* Memory-related */
#include "sys_close.h"
#include "sys_creat.h"
#include "sys_fcntl.h"
#include "sys_lseek.h"
#include "sys_dup.h"
#include "sys_dup2.h"
#include "sys_open.h"
#include "sys_pipe.h"
#include "sys_poll.h"
#include "sys_read.h"
#include "sys_select.h"
#include "sys_write.h"
#include "sys_brk.h"
/* Network-related */
#include "sys_accept.h"
#include "sys_bind.h"
#include "sys_connect.h"
#include "sys_getpeername.h"
#include "sys_getsockopt.h"
#include "sys_listen.h"
#include "sys_recvfrom.h"
#include "sys_recvmsg.h"
#include "sys_sendmsg.h"
#include "sys_sendto.h"
#include "sys_setsockopt.h"
#include "sys_shutdown.h"
#include "sys_socket.h"
/* Process-related */
#include "sys_clone.h"
#include "sys_execve.h"
#include "sys_exit.h"
#include "sys_getpid.h"
#include "sys_tuxcall.h"

enum { PROCESS_CONTINUE = 0, PROCESS_DEAD, PROCESS_GROUP_DEAD, PROCESS_TASK_FOUND };
extern const char *state_names[4];

#define RECV_CLOSE              10

int process_handle(process_descriptor_t * proc);
int process_send_call(reg_s * reg, process_descriptor_t * proc, process_descriptor_t * remote_proc, void * data);
void process_close_call(process_descriptor_t * proc, int fd);
void syscall_default(pid_t pid, reg_s * reg, process_descriptor_t * proc);

#endif
