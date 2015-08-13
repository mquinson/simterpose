/* sys_recv -- Handles recv syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_recv.h"

#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

#ifdef arch_32 /* recv syscall does not exist on 64bit architectures */

/** @brief handles recv syscall at the entrance and the exit */
void syscall_recv(reg_s * reg, process_descriptor_t * proc){
  
  void * data = NULL;
  
  if (proc_entering(proc))
    syscall_recv_pre(reg, proc, data);
  else
    syscall_recv_post(reg, proc, data);

}

/** @brief handles recv syscall at the entrance
 *
 * In case of address translation, we let the kernel run the syscall. We also
 * receive the MSG task in order to unblock the MSG process sending the message.
 *
 * In case of full mediation we receive the MSG task and we neutralize the
 * real syscall. We don't go to syscall_recvmsg_post afterwards.
 */
void syscall_recv_pre(reg_s * reg, process_descriptor_t * proc, void * data)
{
  proc_inside(proc);
  // XBT_DEBUG("[%d] RECV_pre", pid);
  XBT_DEBUG("RECV_pre");
  
#ifdef address_translation
  if ((ssize_t)reg->ret > 0) {
#endif
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, (int) reg->arg[0]);
    file_desc->refcount++;

    if (socket_registered(proc, (int) reg->arg[0]) != -1) {
      if (!socket_netlink(proc, (int) reg->arg[0])) {
        const char *mailbox = NULL;
        if (MSG_process_self() == file_desc->stream->client)
          mailbox = file_desc->stream->to_client;
        else if (MSG_process_self() == file_desc->stream->server)
          mailbox = file_desc->stream->to_server;
        else
          ABORT("SYS_recv: No mailbox available\n");;
        msg_task_t task = NULL;
        msg_error_t err = MSG_task_receive(&task, mailbox);
	reg->ret = (ssize_t) MSG_task_get_bytes_amount(task);
        data = MSG_task_get_data(task);

        if (err != MSG_OK) {
          struct infos_socket *is = get_infos_socket(proc, (int) reg->arg[0]);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            process_recv_out_call(reg, proc, data);
#else
          if (sock_status & SOCKET_CLOSED)
	    reg->ret = -1;
          ptrace_neutralize_syscall(proc->pid);
          proc_outside(proc);
          process_recv_out_call(reg, proc, data);
        } else {
	  ptrace_neutralize_syscall(proc->pid);
	  proc_outside(proc);
	  process_recv_out_call(reg, proc, data);
#endif
        }
        MSG_task_destroy(task);
      }
    }
    file_desc->refcount--;
    file_desc = NULL;
#ifdef address_translation
  }
#endif
  XBT_DEBUG("recv_pre");
}

/** @brief print recv syscall at the exit */
void syscall_recv_post(reg_s * reg, process_descriptor_t * proc, void * data)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] recv_out", pid);
  XBT_DEBUG("recv_post");

  if (strace_option)
    print_recv_syscall(reg, proc, data);
}

/** @brief helper function to deal with recv syscall in full mediation or with
 *  error in address translation
 *
 *  We restore the syscall registers with the right return value
 */
void process_recv_out_call(reg_s * reg, process_descriptor_t * proc, void * data)
{
  XBT_DEBUG("Entering process_RECV_out_call");
  pid_t pid = proc->pid;
  size_t len_data, len_buf;

  len_data = strlen((char *) data) + 1;
  len_buf = (size_t) reg->arg[2];
  if (len_buf >= len_data){
    ptrace_poke(pid, (void *) reg->arg[1], data, len_data);
    reg->ret = len_data;
  }
  else{
    ptrace_poke(pid, (void *) reg->arg[1], data, len_buf);
     reg->ret = len_buf;
  }
  ptrace_restore_syscall(pid, SYS_recv, (ssize_t) reg->ret);
  
  if (strace_option)
    print_recv_syscall(reg, proc, data);
}
#endif
