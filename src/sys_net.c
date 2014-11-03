/* sys_net -- handlers of all network-related syscalls                       */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "simterpose.h"
#include "syscall_process.h"
#include "print_syscall.h"

void syscall_socket(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
	if (proc_entering(proc))
		proc_inside(proc);
	else {
		proc_outside(proc);

		socket_arg_t arg = &sysarg->socket;
		arg->ret = reg->ret;
		arg->domain = (int) reg->arg[0];
		arg->type = (int) reg->arg[1];
		arg->protocol = (int) reg->arg[2];

		if (strace_option)
			print_socket_syscall(proc, sysarg);

		if (arg->ret > 0)
			register_socket(proc, arg->ret, arg->domain, arg->protocol);
	}
}
