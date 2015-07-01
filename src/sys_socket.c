/* sys_socket -- Handles socket syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_socket.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles socket syscall at the entrance and the exit */
void syscall_socket(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc))
    proc_inside(proc);
  else {
    proc_outside(proc);

    socket_arg_t arg = &sysarg->socket;
    arg->ret = (int) reg->ret;
    arg->domain = (int) reg->arg[0];
    arg->type = (int) reg->arg[1];
    arg->protocol = (int) reg->arg[2];

    if (strace_option)
      print_socket_syscall(proc, sysarg);

    if (arg->ret > 0)
      register_socket(proc, arg->ret, arg->domain, arg->protocol);
  }
}
