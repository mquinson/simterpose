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
int syscall_write(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
    XBT_DEBUG(" write_pre");
    get_args_write(proc, reg, sysarg);

#ifndef address_translation
    // XBT_DEBUG("[%d] write_in", pid);
    if (socket_registered(proc, sysarg->write.fd) != -1) {
      process_descriptor_t remote_proc;
      if (process_send_call(proc, sysarg, &remote_proc)) {
        ptrace_neutralize_syscall(proc->pid);

        write_arg_t arg = &(sysarg->write);
        ptrace_restore_syscall(proc->pid, SYS_write, arg->ret);
        if (strace_option)
          print_write_syscall(proc, sysarg);
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
    get_args_write(proc, reg, sysarg);

    write_arg_t arg = &(sysarg->write);

    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, arg->fd);
    XBT_DEBUG("On syscall_write pointer value of arg %p \n arg->fd = %lu \n return value = %lu", arg, arg->fd, arg->ret);
    XBT_DEBUG("value of pointer via file_desc %p \n", file_desc);
    file_desc->refcount++;

    if (file_desc != NULL && file_desc->type == FD_PIPE) {
      if (strace_option)
        print_write_syscall(proc, sysarg);
      pipe_t *pipe = file_desc->pipe;
      if (pipe == NULL)
        THROW_IMPOSSIBLE;

      pipe_end_t end_in = NULL;
      xbt_dynar_get_cpy(pipe->read_end, 0, &end_in);

      char buff[256];
      sprintf(buff, "%d", end_in->fd);
      msg_host_t receiver = end_in->proc->host;

      XBT_WARN("host %s trying to send to %s in pipe %d (size: %lu). Buff = %s", MSG_host_get_name(proc->host),
	       MSG_host_get_name(receiver), end_in->fd, arg->ret, buff);

      double amount = arg->ret;
      msg_task_t task = MSG_task_create(buff, 0, amount, arg->data);
      XBT_WARN("hosts: %s send to %s in pipe %d (size: %lu)", MSG_host_get_name(proc->host), MSG_host_get_name(receiver),
        end_in->fd, arg->ret);
      MSG_task_send(task, buff);
    } else if (strace_option)
      print_write_syscall(proc, sysarg);

    file_desc->refcount--;
    file_desc = NULL;

#ifdef address_translation
    if ((int) reg->ret > 0) {
      if (socket_registered(proc, sysarg->write.fd) != -1) {
        process_descriptor_t remote_proc;
      if (process_send_call(proc, sysarg, &remote_proc))
        return PROCESS_TASK_FOUND;
      }
    }
#endif
    return PROCESS_CONTINUE;
  }
}
