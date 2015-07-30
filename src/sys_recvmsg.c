/* sys_recvmsg -- Handles recvmsg syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_recvmsg.h"

#include "args_trace.h"
#include "data_utils.h"
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
  /* get_args_recvmsg(proc, reg, sysarg); */
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  arg->sockfd = (int) reg->arg[0];
  arg->flags = (int) reg->arg[2];
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg[1], sizeof(struct msghdr), "recvmsg");

  arg->len = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");
    arg->len += temp.iov_len;
  }


  

  void * data;
  /* recvmsg_arg_t arg = &(sysarg->recvmsg); */

  /* if ( (int) reg->ret > 0) { */
  /* printf("I'm here reg->ret vaut %lu %d %li\n", reg->ret, (int) reg->ret, (long) reg->ret); */
  if ( reg->ret > 0) {
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, (int) reg->arg[0]);
    file_desc->refcount++;

    if (socket_registered(proc, (int) reg->arg[0]) != -1) {
      if (!socket_netlink(proc, (int) reg->arg[0])) {
        const char *mailbox;
        if (MSG_process_self() == file_desc->stream->client)
          mailbox = file_desc->stream->to_client;
        else if (MSG_process_self() == file_desc->stream->server)
          mailbox = file_desc->stream->to_server;
        else
          THROW_IMPOSSIBLE;

        msg_task_t task = NULL;
        msg_error_t err = MSG_task_receive(&task, mailbox);

        reg->ret = (ssize_t) MSG_task_get_bytes_amount(task);
        data = MSG_task_get_data(task);

        if (err != MSG_OK) {
          struct infos_socket *is = get_infos_socket(proc, (int) reg->arg[0]);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            sys_build_recvmsg(reg, proc, &(proc->sysarg), data);
#else
          if (sock_status & SOCKET_CLOSED)
            sysarg->recvmsg.ret = 0;
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          sys_build_recvmsg(reg, proc, &(proc->sysarg), data);
        } else {
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          sys_build_recvmsg(reg, proc, &(proc->sysarg), data);
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
  /* get_args_recvmsg(proc, reg, sysarg); */
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  arg->sockfd = (int) reg->arg[0];
  arg->flags = (int) reg->arg[2];
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg[1], sizeof(struct msghdr), "recvmsg");

  arg->len = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");
    arg->len += temp.iov_len;
  }



  /* if (strace_option) */
  /*   print_recvmsg_syscall(proc, sysarg); */
}


/** @brief put the message received in the registers of recvmsg syscall */
void sys_build_recvmsg(reg_s * reg, process_descriptor_t * proc, syscall_arg_u * sysarg, void * data)
{
  pid_t pid = proc->pid;
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  ptrace_restore_syscall(pid, SYS_recvmsg, (ssize_t) reg->ret);

  int length = (ssize_t) reg->ret;
  int global_size = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    if (length < 0)
      break;

    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");

    if (length < temp.iov_len)
      temp.iov_len = length;

    ptrace_poke(pid, arg->msg.msg_iov + i * sizeof(struct iovec), &temp, sizeof(struct iovec));

    ptrace_poke(pid, temp.iov_base, (char *) data + global_size, temp.iov_len);

  }
  /* free(arg->data); */
}
