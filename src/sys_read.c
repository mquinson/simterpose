/* sys_read -- Handles read syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_read.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handle read syscall at the entrance and the exit
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_read_post afterwards.
 */
void syscall_read(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
    XBT_DEBUG(" read_pre");
    get_args_read(proc, reg, sysarg);
    read_arg_t arg = &(sysarg->read);
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, arg->fd);
    file_desc->refcount++;

    if (socket_registered(proc, reg->arg[0]) != -1) {
      const char *mailbox;
      if (MSG_process_self() == file_desc->stream->client)
        mailbox = file_desc->stream->to_client;
      else if (MSG_process_self() == file_desc->stream->server)
        mailbox = file_desc->stream->to_server;
      else
        THROW_IMPOSSIBLE;

      msg_task_t task = NULL;
      msg_error_t err = MSG_task_receive(&task, mailbox);

      arg->ret = (int) MSG_task_get_bytes_amount(task);
      arg->data = MSG_task_get_data(task);

      if (err != MSG_OK) {
        struct infos_socket *is = get_infos_socket(proc, arg->fd);
        int sock_status = socket_get_state(is);
#ifdef address_translation
        if (sock_status & SOCKET_CLOSED)
          process_read_out_call(proc);
#else
        if (sock_status & SOCKET_CLOSED)
          sysarg->read.ret = 0;
        ptrace_neutralize_syscall(proc->pid);
        proc_outside(proc);
        process_read_out_call(proc);
      } else {
        ptrace_neutralize_syscall(proc->pid);
        proc_outside(proc);
        process_read_out_call(proc);
#endif
      }
      MSG_task_destroy(task);
    } else if (file_desc != NULL && file_desc->type == FD_PIPE) {
      if (strace_option)
        print_read_syscall(proc, sysarg);
      fprintf(stderr, "[%d] read pre, pipe \n", proc->pid);
      pipe_t *pipe = file_desc->pipe;
      if (pipe == NULL)
	THROW_IMPOSSIBLE;

      XBT_WARN("host %s trying to receive from pipe %lu", MSG_host_get_name(proc->host), arg->fd);
      char buff[256];
      sprintf(buff, "%lu", arg->fd);

      msg_task_t task = NULL;
      MSG_task_receive(&task, buff);

      arg->ret = (int) MSG_task_get_bytes_amount(task);
      arg->data = MSG_task_get_data(task);
      XBT_WARN("hosts: %s received from pipe %lu (size: %lu)", MSG_host_get_name(proc->host), arg->fd, arg->ret);

      MSG_task_destroy(task);
    }
    file_desc->refcount--;
    file_desc = NULL;

  } else { // ---- Exiting syscall ---- //
    proc_outside(proc);
    XBT_DEBUG("read_post");
    get_args_read(proc, reg, sysarg);
    if (strace_option)
      print_read_syscall(proc, sysarg);
  }
}


/** @brief helper function to deal with read syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_read_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_read_out_call");
  syscall_arg_u *sysarg = &(proc->sysarg);
  read_arg_t arg = &(sysarg->read);
  ptrace_restore_syscall(proc->pid, SYS_read, arg->ret);
  if (arg->ret > 0) {
    ptrace_poke(proc->pid, (void *) arg->dest, arg->data, arg->ret);
    free(arg->data);
  }
}
