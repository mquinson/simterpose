/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef SYSCALL_PROCESS_H
#define SYSCALL_PROCESS_H

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "sockets.h"
#include "syscall_data.h"
#include "args_trace.h"
#include "communication.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "syscall_data.h"

#include "sys_process.h"
/* Memory-related */
#include "sys_memory.h"
/* Network-related */
#include "sys_network.h"
/* Process-related */
/* #include "sys_process.h" */


enum { PROCESS_CONTINUE = 0, PROCESS_DEAD, PROCESS_GROUP_DEAD, PROCESS_TASK_FOUND };
extern const char *state_names[4];

#define RECV_CLOSE              10

int process_handle(process_descriptor_t * proc);
int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc);
void process_close_call(process_descriptor_t * proc, int fd);
int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg);


#endif
