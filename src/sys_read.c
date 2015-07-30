/* sys_read -- Handles read syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_read.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handle read syscall at the entrance and the exit
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_read_post afterwards.
 */
void syscall_read(reg_s * reg, process_descriptor_t * proc)
{
  int fd = (int) reg->arg[0];
  
#ifndef address_translation
  void * dest = (void *) reg->arg[1];
#endif
  void * data = (void*) reg->arg[1];
  ssize_t ret = (ssize_t) reg->ret;
  ssize_t count = (size_t) reg->arg[2];

  if (proc_entering(proc)) {
    proc_inside(proc);
    XBT_DEBUG(" read_pre");

    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, fd);
    file_desc->refcount++;

    if (socket_registered(proc, fd) != -1) {
      const char *mailbox;
      if (MSG_process_self() == file_desc->stream->client)
        mailbox = file_desc->stream->to_client;
      else if (MSG_process_self() == file_desc->stream->server)
        mailbox = file_desc->stream->to_server;
      else
        THROW_IMPOSSIBLE;

      msg_task_t task = NULL;
      msg_error_t err = MSG_task_receive(&task, mailbox);

      ret = (ssize_t) MSG_task_get_bytes_amount(task);
      data = MSG_task_get_data(task);

      if (err != MSG_OK) {
        struct infos_socket *is = get_infos_socket(proc, fd);
        int sock_status = socket_get_state(is);
#ifdef address_translation
        if (sock_status & SOCKET_CLOSED)
          process_read_out_call(reg, proc);
#else
        if (sock_status & SOCKET_CLOSED)
          ret = 0;
        ptrace_neutralize_syscall(proc->pid);
        proc_outside(proc);
        process_read_out_call(reg, proc);
      } else {
        ptrace_neutralize_syscall(proc->pid);
        proc_outside(proc);
        process_read_out_call(reg, proc);
#endif
      }
      MSG_task_destroy(task);
    } else if (file_desc != NULL && file_desc->type == FD_PIPE) {
      if (strace_option)
        print_read_syscall(reg, proc);
      fprintf(stderr, "[%d] read pre, pipe \n", proc->pid);
      pipe_t *pipe = file_desc->pipe;
      if (pipe == NULL)
	THROW_IMPOSSIBLE;

      XBT_WARN("host %s trying to receive from pipe %d", MSG_host_get_name(proc->host), fd);
      char buff[256];
      sprintf(buff, "%d", fd);

      msg_task_t task = NULL;
      MSG_task_receive(&task, buff);

      ret = (int) MSG_task_get_bytes_amount(task);
      data = MSG_task_get_data(task);
      XBT_WARN("hosts: %s received from pipe %d (size: %zd)", MSG_host_get_name(proc->host), fd, ret);

      MSG_task_destroy(task);
    }
    file_desc->refcount--;
    file_desc = NULL;

  } else { // ---- Exiting syscall ---- //
    proc_outside(proc);
    XBT_DEBUG("read_post");
    if (strace_option)
      print_read_syscall(reg, proc);
  }
}


/** @brief helper function to deal with read syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_read_out_call(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_read_out_call");
  ptrace_restore_syscall(proc->pid, SYS_read, (int) reg->ret);
  if ((int) reg->ret > 0) {
    ptrace_poke(proc->pid, (void *) reg->arg[1], (void *) reg->arg[1], (int) reg->ret);
  }
}
