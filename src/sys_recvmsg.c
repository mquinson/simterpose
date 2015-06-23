/* sys_recvmsg -- Handles recvmsg syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_recvmsg.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles recvmsg syscall at the entrance and the exit */
void syscall_recvmsg(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_recvmsg_pre(pid, reg, sysarg, proc);
  else
    syscall_recvmsg_post(pid, reg, sysarg, proc);

}

/** @brief handles recvmsg syscall at the entrance
 *
 * We receive the MSG task and in case of full mediation we neutralize the
 * real syscall and don't go to syscall_recvmsg_post afterwards.
 */
void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  //  XBT_DEBUG("[%d] recvmsg_in", pid);
  XBT_DEBUG("recvmsg_pre");
  get_args_recvmsg(proc, reg, sysarg);
  recvmsg_arg_t arg = &(sysarg->recvmsg);

  if (reg->ret > 0) {
    fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
    file_desc->refcount++;

    if (socket_registered(proc, arg->sockfd) != -1) {
      if (!socket_netlink(proc, arg->sockfd)) {
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
          struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            sys_build_recvmsg(proc, &(proc->sysarg));
#else
          if (sock_status & SOCKET_CLOSED)
            sysarg->recvmsg.ret = 0;
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          sys_build_recvmsg(proc, &(proc->sysarg));
        } else {
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          sys_build_recvmsg(proc, &(proc->sysarg));
#endif
        }
        MSG_task_destroy(task);
      }
    }
    file_desc->refcount--;
    file_desc = NULL;
  }
  XBT_DEBUG("recvmsg_pre");
}

/** @brief print recvmsg syscall at the exit */
void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] recvmsg_out", pid);
  XBT_DEBUG("recvmsg_post");
  get_args_recvmsg(proc, reg, sysarg);
  if (strace_option)
    print_recvmsg_syscall(proc, sysarg);
}
