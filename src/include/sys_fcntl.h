/* sys_fcntl -- Handlers of fcntl syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <math.h>

#include "process_descriptor.h"
#include "ptrace_utils.h"

void syscall_fcntl(reg_s * reg, process_descriptor_t * proc);
void process_fcntl_call(reg_s * reg, process_descriptor_t * proc);
