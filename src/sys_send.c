/* sys_send -- Handles send syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_send.h"

#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

#if UINTPTR_MAX == 0xffffffff
/* 32-bit architecture */
/* recv syscall does not exist on 64bit architectures */

/** @brief handles send syscall at the entrance and the exit */
int syscall_send(reg_s * reg, process_descriptor_t * proc){

  int ret = 0;
  
  if (proc_entering(proc))
    ret = syscall_send_pre(reg, proc);
  else
    ret = syscall_send_post(reg, proc);
  if (ret)
    return ret;

  return 0;
}

/** @brief handles send syscall at the entrance
 *
 * In case of full mediation, we retrieve the message intended to be sent by
 * the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_send_post afterwards.
 *
 * In case of address translation we let the kernel run the syscall.
 */
int syscall_send_pre(reg_s * reg, process_descriptor_t * proc)
{
pit_d pid = proc->pid;
  proc_inside(proc);
  //  XBT_DEBUG("[%d] send_pre", pid);
  XBT_DEBUG("send_pre");
  void * data = NULL;
  
#ifndef address_translation
  data = xbt_new0(char, (size_t) reg->arg[2]);
  ptrace_cpy(pid, data, (void *) reg->arg[1],  (size_t) reg->arg[2], "send");

  process_descriptor_t remote_proc;
  if (process_send_call(reg, proc, &remote_proc, data)) {
    ptrace_neutralize_syscall(pid);

    proc_outside(proc);
    ptrace_restore_syscall(pid, SYS_send, (int) reg->ret);

    if (strace_option)
      print_send_syscall(reg, proc, data);
    return PROCESS_TASK_FOUND;
  }
#else
  if (socket_registered(proc, (int) reg->arg[0]) == -1) 
    ABORT("SYS_send: Socket not registred.");
  if (!socket_network(proc, (int) reg->arg[0]))
    ABORT("SYS_send: The socket is not a network socket.");
  return PROCESS_CONTINUE;
#endif
}

/** @brief handles send syscall at the exit
 *
 * In case of address translation we translate the arguments back (from the
 * real local address to the global simulated one) to wrong the application.
 * We also send the MSG task in order to return control to the MSG process
 * receiving the message
 */
int syscall_send_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  XBT_DEBUG("send_post");
  void * data = NULL;
  ptrace_cpy(proc->pid, data, (void *) reg->arg[1], (size_t) reg->arg[2], "send");
  
  if (strace_option)
    print_send_syscall(reg, proc, data);

  if ((ssize_t) reg->ret > 0) {
    process_descriptor_t remote_proc;
    if (process_send_call(reg, proc, &remote_proc, data))
      return PROCESS_TASK_FOUND;
  }
  else
    ABORT("SYS_send: Error syscall return.");
  return PROCESS_CONTINUE;
}
#endif
