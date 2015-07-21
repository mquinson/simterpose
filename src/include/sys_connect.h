/* sys_connect -- Handlers connect syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "ptrace_utils.h"
#include "syscall_data.h"
#include "process_descriptor.h"

void syscall_connect(reg_s * reg, process_descriptor_t * proc);
int syscall_connect_pre(reg_s * reg, process_descriptor_t * proc);
void syscall_connect_post(reg_s * reg, process_descriptor_t * proc);
int process_connect_in_call(reg_s * reg, process_descriptor_t * proc);
void sys_translate_connect_in(reg_s * reg, process_descriptor_t * proc);
void sys_translate_connect_out(reg_s * reg, process_descriptor_t * proc);
