/* sys_sendto -- Handles sendto syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_sendto.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles sendto syscall at the entrance and the exit */
int syscall_sendto(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  int ret;

  if (proc_entering(proc))
    ret = syscall_sendto_pre(pid, reg, sysarg, proc);
  else
    ret = syscall_sendto_post(pid, reg, sysarg, proc);
  if (ret)
    return ret;

  return 0;
}

/** @brief handles sendto syscall at the entrance
 *
 * In case of full mediation, we retrieve the message intended to be sent by
 * the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_sendto_post afterwards.
 *
 * In case of address translation we translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall
 */
int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
#ifndef address_translation
  //  XBT_DEBUG("[%d] sendto_pre", pid);
  XBT_DEBUG("sendto_pre");
  get_args_sendto(proc, reg, sysarg);
  process_descriptor_t remote_proc;
  if (process_send_call(proc, sysarg, &remote_proc)) {
    ptrace_neutralize_syscall(pid);

    sendto_arg_t arg = &(sysarg->sendto);
    proc_outside(proc);
    ptrace_restore_syscall(pid, SYS_sendto, arg->ret);

    if (strace_option)
      print_sendto_syscall(proc, sysarg);
    return PROCESS_TASK_FOUND;
  }
#else
  if (socket_registered(proc, (int) reg->arg[0]) != -1) {
    if (socket_network(proc, (int) reg->arg[0]))
      sys_translate_sendto_in(proc, sysarg);
  }
#endif
  return PROCESS_CONTINUE;
}

/** @brief handles sendto syscall at the exit
 *
 * In case of address translation we translate the arguments back (from the
 * real local address to the global simulated one) to wrong the application.
 * We also send the MSG task in order to return control to the MSG process
 * receiving the message
 */
int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] sendto_out", pid);
  XBT_DEBUG("sendto_post");
  get_args_sendto(proc, reg, sysarg);
  if (strace_option)
    print_sendto_syscall(proc, sysarg);
#ifdef address_translation
  if (socket_registered(proc, (int) reg->arg[0]) != -1) {
    if (socket_network(proc, (int) reg->arg[0])) {
      sys_translate_sendto_out(proc, sysarg);
    }
  }
  if ((int) reg->ret > 0) {
    process_descriptor_t remote_proc;
    if (process_send_call(proc, sysarg, &remote_proc))
      return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}
