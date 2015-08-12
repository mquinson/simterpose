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
void syscall_socket(reg_s * reg, process_descriptor_t * proc)
{
  if (proc_entering(proc))
    proc_inside(proc);
  else {
    proc_outside(proc);

    if (strace_option)
      print_socket_syscall(reg, proc);

    if ((int) reg->ret > 0)
      register_socket(proc, (int) reg->ret, (int) reg->arg[0], (int) reg->arg[1], (int) reg->arg[2]);
  }
}
