/* sys_sendmsg -- Handles sendmsg syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_sendmsg.h"

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
int syscall_sendmsg(reg_s * reg, process_descriptor_t * proc)
{
  void * data = NULL;
  pid_t pid = proc->pid;
  struct msghdr * msg = xbt_malloc0(sizeof(struct msghdr));
  size_t len = 0; 

  ptrace_cpy(pid, msg, (void *) reg->arg[1], sizeof(struct msghdr), "sendmsg");
#ifndef address_translation
  int i;
  for (i = 0; i < msg->msg_iovlen; ++i) {
    struct iovec * temp;
    ptrace_cpy(pid, &temp, msg->msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "sendmsg");
    data = realloc(data, len + temp->iov_len);
    ptrace_cpy(pid, (char *) data + len, temp->iov_base, temp->iov_len, "sendmsg");
    len += temp->iov_len;
  }
#endif

  if (proc_entering(proc)) {
    proc_inside(proc);
#ifndef address_translation
    XBT_DEBUG("sendmsg_pre");
    process_descriptor_t remote_proc;
    if (process_send_call(reg, proc, &remote_proc, data)) {
      ptrace_neutralize_syscall(pid);

      proc_outside(proc);
      ptrace_restore_syscall(pid, SYS_sendmsg, (ssize_t) reg->ret);

      if (strace_option)
	print_sendmsg_syscall(reg, proc, len, data, msg);
      return PROCESS_TASK_FOUND;
    }
#endif
    return PROCESS_CONTINUE;
  } else {
    proc_outside(proc);
    // XBT_DEBUG("[%d] sendmsg_out", pid);
    XBT_DEBUG("sendmsg_post");
    if (strace_option)
      print_sendmsg_syscall(reg, proc, len, data, msg);
#ifdef address_translation
    if ((int) reg->ret > 0) {
      process_descriptor_t remote_proc;
      if (process_send_call(reg, proc, &remote_proc, data)) {
	return PROCESS_TASK_FOUND;
      }
    }
#endif
    return PROCESS_CONTINUE;
  }
}
