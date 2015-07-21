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
void syscall_recvfrom(pid_t pid, reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_recvfrom_pre(pid, reg, proc);
  else
    syscall_recvfrom_post(pid, reg, proc);

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
void syscall_recvfrom_pre(pid_t pid, reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
  // XBT_DEBUG("[%d] RECVFROM_pre", pid);
  XBT_DEBUG("RECVFROM_pre");

  ssize_t ret = (ssize_t) reg->ret;
  int sockfd = (int) reg->arg[0];
  void * data = (void *) reg->arg[1];
  size_t len = (size_t) reg->arg[2];
  int flags = (int) reg->arg[3];
  struct sockaddr * addr = (struct sockaddr *) reg->arg[4];
  int is_addr;
  socklen_t * addrlen = 0;/* = (socklen_t *) reg->arg[5] */  /* TODO */
  struct sockaddr_in sai;
  struct sockaddr_un sau;
  struct sockaddr_nl snl;
  /* TODO void * dest =  (void *) reg->arg[1];*/
  int domain = get_domain_socket(proc, sockfd);

  if ( (int) reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(pid, &sai, addr, sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(pid, &sau, addr, sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(pid, &snl, addr, sizeof(struct sockaddr_in), "recvfrom");
  } else
    is_addr = 0;

  if ( (int) reg->arg[4] != 0) {         // syscall "recv" doesn't exist on x86_64, it's recvfrom with struct sockaddr=NULL and addrlen=0
    ptrace_cpy(pid, &addrlen, (void *) reg->arg[5], sizeof(socklen_t), "recvfrom");
  }
  
#ifdef address_translation
  if (socket_registered(proc, sockfd) != -1) {
    if (socket_network(proc, sockfd)) {
      sys_translate_recvfrom_out(reg, proc);
    }
  }
#endif

  if ( (int) reg->ret > 0) {
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, sockfd);
    file_desc->refcount++;

    if (socket_registered(proc, sockfd) != -1) {
      if (!socket_netlink(proc, sockfd)) {
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
          struct infos_socket *is = get_infos_socket(proc, sockfd);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            process_recvfrom_out_call(reg, proc);
#else
          if (sock_status & SOCKET_CLOSED)
	    reg->ret = 0;
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
void syscall_recvfrom_post(pid_t pid, reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  // XBT_DEBUG("[%d] recvfrom_out", pid);
  XBT_DEBUG("recvfrom_post");
  if (strace_option)
    print_recvfrom_syscall(reg, proc);
}

/** @brief helper function to deal with recvfrom syscall in full mediation
 *
 *  We restore the syscall registers with the right return value
 */
void process_recvfrom_out_call(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_RECVFROM_out_call");
  pid_t pid = proc->pid;
  // process_reset_state(proc);
  if (strace_option)
    print_recvfrom_syscall(reg, proc);
  ptrace_restore_syscall(pid, SYS_recvfrom, (int) reg->ret);
}

/** @brief translate the port and address of the entering recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the global
 * simulated address and port the application wants to receive the message
 * from. We translate them to real local ones and put the result back in the
 * registers to actually get the recvfrom syscall performed by the kernel.
 */
void sys_translate_recvfrom_in(reg_s * reg,process_descriptor_t * proc)
{
  pid_t pid = proc->pid;

  if ( (int) reg->arg[4] == 0)
    return;
  
  struct sockaddr_in sai;
  ptrace_cpy(pid, &sai, (struct sockaddr *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
  struct sockaddr_in temp = sai;
  int port = get_real_port(proc, temp.sin_addr.s_addr, ntohs(temp.sin_port));
  temp.sin_addr.s_addr = inet_addr("127.0.0.1");
  temp.sin_port = htons(port);
  ptrace_poke(pid, (void *) reg->arg[4], &temp, sizeof(struct sockaddr_in));
  sai = temp;
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

/** @brief translate the port and address of the exiting recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we received the message from. We translate them
 * into global simulated ones and put the result back in the registers, so
 * that the application gets wronged.
 */
void sys_translate_recvfrom_out(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;

  if ( (int) reg->arg[4] == 0)
    return;

  struct sockaddr_in sai;
  ptrace_cpy(pid, &sai, (struct sockaddr *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
  translate_desc_t *td = get_translation(ntohs(sai.sin_port));
  sai.sin_port = htons(td->port_num);
  sai.sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg->arg[4], &sai, sizeof(struct sockaddr_in));
}
