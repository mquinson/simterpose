/* sys_write -- Handles write syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_write.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handle write syscall at the entrance and the exit
 *
 * At the entrance, in case of full mediation and if the socket is registered we retrieve the message intended
 * to be written by the application. We send it through MSG and neutralize the real syscall.
 * We don't go to syscall_write_post afterwards.
 *
 * At the exit, we send the MSG task in order to return control to the MSG process reading the message
 */
int syscall_write(reg_s * reg, process_descriptor_t * proc)
{
  int fd = (int) reg->arg[0];
  void * data = (void *) reg->arg[1];
  /* TODO: check this*/
  /* arg->dest = (void *) reg->arg[1]; */
  ssize_t ret = (ssize_t) reg->ret;
  ssize_t count = (size_t) reg->arg[2];
#ifndef address_translation
  pid_t pid = proc->pid;
  if (socket_registered(proc, fd)) {
    if (socket_network(proc, fd)) {
      data = xbt_new0(char, arg->count);
      ptrace_cpy(pid, data, (void *) reg->arg[1], count, "write");
    }
  }
#endif

  if (proc_entering(proc)) {
    proc_inside(proc);
    XBT_DEBUG(" write_pre");

#ifndef address_translation
    // XBT_DEBUG("[%d] write_in", pid);
    if (socket_registered(proc, fd) != -1) {
      process_descriptor_t remote_proc;
      if (process_send_call(reg, proc, &remote_proc, data)) {
        ptrace_neutralize_syscall(proc->pid);

        ptrace_restore_syscall(proc->pid, SYS_write, ret);
        if (strace_option)
          print_write_syscall(reg, proc);
        proc_outside(proc);
        return PROCESS_TASK_FOUND;
      }
    } else {
      // TODO: if the socket is not registered, for now we do nothing
      // and let the kernel run the syscall
      //XBT_WARN("socket unregistered");
    }
#endif
    return PROCESS_CONTINUE;
  } else {
    proc_outside(proc);
    XBT_DEBUG("write_post");
    //    XBT_DEBUG("[%d] write_out", pid);

    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, fd);
    /* XBT_DEBUG("On syscall_write pointer value of arg %p \n arg->fd = %d \n return value = %d", arg, arg->fd, arg->ret); */
    /* XBT_DEBUG("value of pointer via file_desc %p \n", file_desc); */
    file_desc->refcount++;

    if (file_desc != NULL && file_desc->type == FD_PIPE) {
      if (strace_option)
        print_write_syscall(reg, proc);
      pipe_t *pipe = file_desc->pipe;
      if (pipe == NULL)
        THROW_IMPOSSIBLE;

      pipe_end_t end_in = NULL;
      xbt_dynar_get_cpy(pipe->read_end, 0, &end_in);

      char buff[256];
      sprintf(buff, "%d", end_in->fd);
      msg_host_t receiver = end_in->proc->host;

      XBT_WARN("host %s trying to send to %s in pipe %d (size: %zd). Buff = %s", MSG_host_get_name(proc->host),
	       MSG_host_get_name(receiver), end_in->fd, ret, buff);

      double amount = ret;
      msg_task_t task = MSG_task_create(buff, 0, amount, data);
      XBT_WARN("hosts: %s send to %s in pipe %d (size: %zd)", MSG_host_get_name(proc->host), MSG_host_get_name(receiver),
        end_in->fd, ret);
      MSG_task_send(task, buff);
    } else if (strace_option)
      print_write_syscall(reg, proc);

    file_desc->refcount--;
    file_desc = NULL;

#ifdef address_translation
    if ((int)ret > 0) {
      if (socket_registered(proc, fd) != -1) {
        process_descriptor_t remote_proc;
	if (process_send_call(reg, proc, &remote_proc, data))
        return PROCESS_TASK_FOUND;
      }
    }
#endif
    return PROCESS_CONTINUE;
  }
}
