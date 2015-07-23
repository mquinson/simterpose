/* args_trace -- Retrieve the syscall arguments from registers, and
   build new ones */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#ifndef __ARGS_TRACE_H
#define __ARGS_TRACE_H


#include "syscall_data.h"
#include "ptrace_utils.h"
#include "process_descriptor.h"

void get_args_recvfrom(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void get_args_recvmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg);

void sys_build_recvmsg(process_descriptor_t * proc, syscall_arg_u * sysarg);


#endif
