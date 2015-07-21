/* sys_accept -- Handles accept syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_accept.h"

#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles accept syscall at the entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
void syscall_accept(reg_s * reg, process_descriptor_t * proc)
{
  int sockfd = (int) reg->arg[0];
  void * addr = (void *) reg->arg[1];
  void * addrlen = (void *) reg->arg[2];
  int ret = (int) reg->ret;
  struct sockaddr_in sai;
  struct sockaddr_un sau;
  struct sockaddr_nl snl;
  
  int domain = get_domain_socket(proc, sockfd);
  pid_t pid = proc->pid;
    
  if (proc_entering(proc)) {
    XBT_DEBUG("syscall_accept_pre");
    proc_inside(proc);
      
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, sockfd);
    file_desc->refcount++;

    // We create the stream object for semaphores
    XBT_DEBUG("stream initialization by accept syscall");
    stream_t *stream = xbt_malloc0(sizeof(stream_t));
    stream->sem_client = MSG_sem_init(0);
    stream->sem_server = MSG_sem_init(0);
    stream->server = MSG_process_self();
    stream->to_server = MSG_host_get_name(MSG_host_self());

    XBT_DEBUG("Socket for accepting %lu", reg->arg[0]);

  if (domain == 2)              // PF_INET
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "accept");
  if (domain == 1)              // PF_UINX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_in), "accept");
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_in), "accept");

  ptrace_cpy(pid, &addrlen, (void *) reg->arg[2], sizeof(socklen_t), "accept");

    file_desc->stream = stream;
    XBT_DEBUG("accept_in: trying to take server semaphore ...");
    MSG_sem_acquire(file_desc->stream->sem_server);
    XBT_DEBUG("accept_in: took server semaphore! trying to release client");
    MSG_sem_release(file_desc->stream->sem_client);
    XBT_DEBUG("accept_in: client semaphore released !");

    //We try to find here if there's a connection to accept
    if (comm_has_connect_waiting(get_infos_socket(proc, sockfd))) {
      struct sockaddr_in in;

#ifdef address_translation
      process_descriptor_t *conn_proc = comm_accept_connect(get_infos_socket(proc, sockfd), &in);
      sai = in;
      ptrace_resume_process(conn_proc->pid);
#else
      comm_accept_connect(get_infos_socket(proc, sockfd), &in);
      arg->sai = in;
#endif

#ifndef address_translation
      pid_t pid = proc->pid;
      //Now we rebuild the syscall.
      int new_fd = ptrace_record_socket(pid);

      reg->ret = new_fd;
      ptrace_neutralize_syscall(pid);
      proc_outside(proc);
      
      ptrace_restore_syscall(pid, SYS_accept, reg->ret);

      ptrace_poke(pid, addr, &sai, sizeof(struct sockaddr_in));

      process_accept_out_call(reg, proc);

      if (strace_option)
	print_accept_syscall(reg, proc);

      XBT_DEBUG("accept_in: did the accept_out, before I go on I'm trying to take server semaphore ...");
      MSG_sem_acquire(file_desc->stream->sem_server);
      XBT_DEBUG("accept_in: took server semaphore! (2nd time)");
#endif
    }
    file_desc->refcount--;
    file_desc = NULL;

  } else { // **** Exit syscall ****

    proc_outside(proc);
#ifdef address_translation
    process_accept_out_call(reg, proc);
#endif

    if (strace_option)
      print_accept_syscall(reg, proc);

    // Never called by full mediation
    fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, sockfd);
    file_desc->refcount++;

    XBT_DEBUG("accept_post: trying to take server semaphore ...");
    MSG_sem_acquire(file_desc->stream->sem_server);
    XBT_DEBUG("accept_post: took server semaphore!");

    file_desc->refcount--;
    file_desc = NULL;
  }
}

/** @brief helper function to handle accept syscall
 *
 * We use semaphores to synchronize client and server during a connection.
 */
void process_accept_out_call(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG(" CONNEXION: process_accept_out_call");

  if ((int) reg->ret >= 0) {
    int domain = get_domain_socket(proc, (int) reg->arg[0]);
    int protocol = get_protocol_socket(proc, (int) reg->arg[0]);

    struct infos_socket *is = register_socket(proc, (int) reg->ret, domain, protocol);

#ifdef address_translation
    sys_translate_accept_out(reg, proc);
#endif

    comm_join_on_accept(is, proc, (int) reg->arg[0]);

    struct infos_socket *s = get_infos_socket(proc, (int) reg->arg[0]);
    register_port(proc->host, s->port_local);

    struct in_addr in;
    if (s->ip_local == 0) {
      struct infos_socket *temp = is->comm->info[0].socket;

      if (temp->ip_local == inet_addr("127.0.0.1"))
	in.s_addr = inet_addr("127.0.0.1");
      else
	in.s_addr = get_ip_of_host(proc->host);
    } else
      in.s_addr = s->ip_local;

    set_localaddr_port_socket(proc, (int) reg->ret, inet_ntoa(in), s->port_local);

    fd_descriptor_t *file_desc_is = (fd_descriptor_t *) is;
    fd_descriptor_t *file_desc_s = (fd_descriptor_t *) s;
    // we need to give the stream to the new socket
    file_desc_is->stream = file_desc_s->stream;
  }
}

/** @brief translate the port and address of the exiting accept syscall
 *
 * We take the arguments in the registers, which correspond to the
 * real local address and port we obtained. We translate them into
 * global simulated ones and put the result back in the registers, so
 * that the application gets wronged.
 */
void sys_translate_accept_out(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;

  struct sockaddr_in sai;
  ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
  
  int port = ntohs(sai.sin_port);
  struct infos_socket *is = get_infos_socket(proc, (int) reg->arg[0]);

  comm_get_ip_port_accept(is, &sai);
  msg_host_t host;
  if (sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
    host = proc->host;
  else
    host = get_host_by_ip(sai.sin_addr.s_addr);

  set_real_port(host, ntohs(sai.sin_port), port);
  add_new_translation(port, ntohs(sai.sin_port), sai.sin_addr.s_addr);

  ptrace_poke(pid, (void *) reg->arg[1], &sai, sizeof(struct sockaddr_in));
}
