/* sys_mem -- handlers of all memory-related syscalls                        */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "simterpose.h"
#include "syscall_process.h"
#include "print_syscall.h"

void syscall_brk(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc) {
	if (proc_entering(proc)) {
		proc_inside(proc);
	} else {
		proc_outside(proc);

		if (!strace_option)
			return;

		if (reg->arg[0])
			stprintf(proc,"brk(%#lx)",reg->arg[0]);
		else
			stprintf(proc,"brk(0)");
		stprintf_tabto(proc);
		stprintf(proc,"= %#lx",reg->ret);
		stprintf_eol(proc);
	}
}

