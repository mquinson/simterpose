/* sys_recvfrom -- Handles recvfrom syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_recvfrom.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles recvfrom syscall at the entrance and the exit */
void syscall_recvfrom(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_recvfrom_pre(pid, reg, sysarg, proc);
  else
    syscall_recvfrom_post(pid, reg, sysarg, proc);

}

/** @brief handles recvfrom syscall at the entrance
 *
 * In case of address translation, we first translate the arguments (from a global
 * simulated address to a real local one) to let the kernel run the syscall. We also
 * receive the MSG task in order to unblock the MSG process sending the message
 *
 * In case of full mediation we receive the MSG task and we neutralize the
 * real syscall. We don't go to syscall_recvmsg_post afterwards.
 */
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  // XBT_DEBUG("[%d] RECVFROM_pre", pid);
  XBT_DEBUG("RECVFROM_pre");
  get_args_recvfrom(proc, reg, sysarg);

#ifdef address_translation
  if (socket_registered(proc, reg->arg[0]) != -1) {
    if (socket_network(proc, reg->arg[0])) {
      sys_translate_recvfrom_out(proc, sysarg);
    }
  }
#endif

  recvfrom_arg_t arg = &(sysarg->recvfrom);

  if (reg->ret > 0) {
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, arg->sockfd);
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

        arg->ret = (ssize_t) MSG_task_get_bytes_amount(task);
        arg->data = MSG_task_get_data(task);

        if (err != MSG_OK) {
          struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            process_recvfrom_out_call(proc);
#else
          if (sock_status & SOCKET_CLOSED)
            sysarg->recvfrom.ret = 0;
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          process_recvfrom_out_call(proc);
        } else {
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          process_recvfrom_out_call(proc);
#endif
        }
        MSG_task_destroy(task);
        file_desc->refcount--;
        file_desc = NULL;
      }
    }
  }
  XBT_DEBUG("recvfrom_pre");
}

/** @brief print recvfrom syscall at the exit */
void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] recvfrom_out", pid);
  XBT_DEBUG("recvfrom_post");
  get_args_recvfrom(proc, reg, sysarg);
  if (strace_option)
    print_recvfrom_syscall(proc, &(proc->sysarg));
}

/** @brief helper function to deal with recvfrom syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_recvfrom_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_RECVFROM_out_call");
  pid_t pid = proc->pid;
  // process_reset_state(proc);
  syscall_arg_u *sysarg = &(proc->sysarg);
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  if (strace_option)
    print_recvfrom_syscall(proc, &(proc->sysarg));
  ptrace_restore_syscall(pid, SYS_recvfrom, arg->ret);
  ptrace_poke(pid, (void *) arg->dest, arg->data, arg->ret);
  free(arg->data);
}
