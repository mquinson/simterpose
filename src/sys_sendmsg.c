/* sys_sendmsg -- Handles sendmsg syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_sendmsg.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles sendmsg syscall at the entrance
 *
 * In case of full mediation, everything is done when entering the syscall:
 *   - We retrieve the message intended to be sent by the application
 *   - We send it through MSG
 *   - We neutralize the real syscall so that we never exit the syscall afterward
 *
 * In case of address translation we send the MSG task in order to return
 * control to the MSG process receiving the message
 */
int syscall_sendmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
#ifndef address_translation
    XBT_DEBUG("sendmsg_pre");
    get_args_sendmsg(proc, reg, sysarg);
    process_descriptor_t remote_proc;
    if (process_send_call(proc, sysarg, &remote_proc)) {
      ptrace_neutralize_syscall(pid);

      sendmsg_arg_t arg = &(sysarg->sendmsg);
      proc_outside(proc);
      ptrace_restore_syscall(pid, SYS_sendmsg, arg->ret);

      if (strace_option)
	print_sendmsg_syscall(proc, sysarg);
      return PROCESS_TASK_FOUND;
    }
#endif
    return PROCESS_CONTINUE;
  } else {
    proc_outside(proc);
    // XBT_DEBUG("[%d] sendmsg_out", pid);
    XBT_DEBUG("sendmsg_post");
    get_args_sendmsg(proc, reg, sysarg);
    if (strace_option)
      print_sendmsg_syscall(proc, sysarg);
#ifdef address_translation
    if ((long) reg->ret > 0) {
      process_descriptor_t remote_proc;
      if (process_send_call(proc, sysarg, &remote_proc)) {
	return PROCESS_TASK_FOUND;
      }
    }
#endif
    return PROCESS_CONTINUE;
  }
}
