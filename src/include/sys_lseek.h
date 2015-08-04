/* sys_lseek -- Handlers of lseek syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "syscall_data.h"

void syscall_lseek(reg_s * reg, process_descriptor_t * proc);
void process_lseek_call(reg_s * reg, process_descriptor_t * proc);
