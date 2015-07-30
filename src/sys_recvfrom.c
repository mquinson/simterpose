/* sys_recvfrom -- Handles recvfrom syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_recvfrom.h"

#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles recvfrom syscall at the entrance and the exit */
void syscall_recvfrom(reg_s * reg, process_descriptor_t * proc){
  
  void * data;
  void * dest;
  struct sockaddr_in * sai;
  struct sockaddr_un * sau;
  struct sockaddr_nl * snl;
  
  if (proc_entering(proc))
    syscall_recvfrom_pre(reg, proc, data, dest, sai, sau, snl);
  else
    syscall_recvfrom_post(reg, proc, data, dest, sai, sau, snl);

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
void syscall_recvfrom_pre(reg_s * reg, process_descriptor_t * proc, void * data, void * dest, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  pid_t pid = proc->pid;
  socklen_t len;
  socklen_t addrlen;
  int is_addr;

  proc_inside(proc);
  // XBT_DEBUG("[%d] RECVFROM_pre", pid);
  XBT_DEBUG("RECVFROM_pre");

  int domain = get_domain_socket(proc, (int) reg->arg[0]);
  if ( (int) reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(pid, &sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(pid, &sau, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(pid, &snl, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
  } else
    is_addr = 0;

  dest = (void *) reg->arg[1];

  len = 0;
  if ( (int) reg->arg[4] != 0) {         // syscall "recv" doesn't exist on x86_64, it's recvfrom with struct sockaddr=NULL and addrlen=0
    ptrace_cpy(pid, &len, (void *) reg->arg[5], sizeof(socklen_t), "recvfrom");
  }
  addrlen = len;

#ifdef address_translation
  if (socket_registered(proc, (int) reg->arg[0]) != -1) {
    if (socket_network(proc, (int) reg->arg[0])) {
      sys_translate_recvfrom_out(reg, proc, sai);
    }
  }
#endif

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
            process_recvfrom_out_call(reg, proc, data, dest, sai, sau, snl, is_addr, addrlen);
#else
          if (sock_status & SOCKET_CLOSED)
	    reg->ret = 0;
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          process_recvfrom_out_call(reg, proc, data, dest, sai, sau, snl, is_addr, addrlen);
        } else {
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          process_recvfrom_out_call(reg, proc, data, dest, sai, sau, snl, is_addr, addrlen);
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
void syscall_recvfrom_post(reg_s * reg, process_descriptor_t * proc, void * data, void * dest, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] recvfrom_out", pid);
  XBT_DEBUG("recvfrom_post");
  pid_t pid = proc->pid;
  socklen_t len;
  socklen_t addrlen;
  int is_addr;

  int domain = get_domain_socket(proc, (int) reg->arg[0]);
  if ( (int) reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(pid, &sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(pid, &sau, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(pid, &snl, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
  } else
    is_addr = 0;

  dest = (void *) reg->arg[1];

  len = 0;
  if ( (int) reg->arg[4] != 0) {         // syscall "recv" doesn't exist on x86_64, it's recvfrom with struct sockaddr=NULL and addrlen=0
    ptrace_cpy(pid, &len, (void *) reg->arg[5], sizeof(socklen_t), "recvfrom");
  }
  addrlen = len;

  if (strace_option)
    print_recvfrom_syscall(reg, proc, data, sai, sau, snl, is_addr, addrlen);
}

/** @brief helper function to deal with recvfrom syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_recvfrom_out_call(reg_s * reg, process_descriptor_t * proc, void * data, void * dest, struct sockaddr_in * sai, struct sockaddr_un * sau, struct sockaddr_nl * snl, int is_addr, socklen_t addrlen)
{
  XBT_DEBUG("Entering process_RECVFROM_out_call");
  pid_t pid = proc->pid;
  // process_reset_state(proc);
  if (strace_option)
    print_recvfrom_syscall(reg, proc, data, sai, sau, snl, is_addr, addrlen);
    ptrace_restore_syscall(pid, SYS_recvfrom, (ssize_t) reg->ret);
  ptrace_poke(pid, (void *) dest, data, (ssize_t) reg->ret);
}



/** @brief translate the port and address of the exiting recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we received the message from. We translate them
 * into global simulated ones and put the result back in the registers, so
 * that the application gets wronged.
 */
void sys_translate_recvfrom_out(reg_s * reg, process_descriptor_t * proc, struct sockaddr_in * sai)
{
  pid_t pid = proc->pid;

  if ( (int) reg->arg[4] == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(sai->sin_port));
  sai->sin_port = htons(td->port_num);
  sai->sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg->arg[4], &sai, sizeof(struct sockaddr_in));
}
