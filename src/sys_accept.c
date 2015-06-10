/* sys_accept -- Handles accept syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_accept.h"

#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles accept syscall at the entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
void syscall_accept(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    XBT_DEBUG("syscall_accept_pre");
    proc_inside(proc);
    get_args_accept(proc, reg, sysarg);

    accept_arg_t arg = &(sysarg->accept);
    fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
    file_desc->refcount++;

    // We create the stream object for semaphores
    XBT_INFO("stream initialization by accept syscall");
    stream_t *stream = xbt_malloc0(sizeof(stream_t));
    stream->sem_client = MSG_sem_init(0);
    stream->sem_server = MSG_sem_init(0);
    stream->server = MSG_process_self();
    stream->to_server = MSG_host_get_name(MSG_host_self());

    file_desc->stream = stream;
    XBT_DEBUG("accept_in: trying to take server semaphore ...");
    MSG_sem_acquire(file_desc->stream->sem_server);
    XBT_DEBUG("accept_in: took server semaphore! trying to release client");
    MSG_sem_release(file_desc->stream->sem_client);
    XBT_DEBUG("accept_in: client semaphore released !");

    //We try to find here if there's a connection to accept
    if (comm_has_connect_waiting(get_infos_socket(proc, arg->sockfd))) {
      struct sockaddr_in in;

#ifdef address_translation
      process_descriptor_t *conn_proc = comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);
      arg->sai = in;
      ptrace_resume_process(conn_proc->pid);
#else
      comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);
      arg->sai = in;
#endif

#ifndef address_translation
      pid_t pid = proc->pid;
      //Now we rebuild the syscall.
      int new_fd = ptrace_record_socket(pid);

      arg->ret = new_fd;
      ptrace_neutralize_syscall(pid);
      proc_outside(proc);

      accept_arg_t arg = &(sysarg->accept);
      ptrace_restore_syscall(pid, SYS_accept, arg->ret);

      ptrace_poke(pid, arg->addr_dest, &(arg->sai), sizeof(struct sockaddr_in));

      process_accept_out_call(proc, sysarg);

      if (strace_option)
	print_accept_syscall(proc, sysarg);

      XBT_DEBUG("accept_in: did the accept_out, before I go on I'm trying to take server semaphore ...");
      MSG_sem_acquire(file_desc->stream->sem_server);
      XBT_DEBUG("accept_in: took server semaphore! (2nd time)");
#endif
    }
    file_desc->refcount--;
    file_desc = NULL;


  } else { // **** Exit syscall ****

    proc_outside(proc);
    get_args_accept(proc, reg, sysarg);
#ifdef address_translation
    process_accept_out_call(proc, sysarg);
#endif

    if (strace_option)
      print_accept_syscall(proc, sysarg);

    // Never called by full mediation
    get_args_accept(proc, reg, sysarg);
    accept_arg_t arg = &(sysarg->accept);
    fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
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
void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_accept_out_call");
  accept_arg_t arg = &(sysarg->accept);

  if (arg->ret >= 0) {
    int domain = get_domain_socket(proc, arg->sockfd);
    int protocol = get_protocol_socket(proc, arg->sockfd);

    struct infos_socket *is = register_socket(proc, arg->ret, domain, protocol);

#ifdef address_translation
    sys_translate_accept_out(proc, sysarg);
#endif

    comm_join_on_accept(is, proc, arg->sockfd);

    struct infos_socket *s = get_infos_socket(proc, arg->sockfd);
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

    set_localaddr_port_socket(proc, arg->ret, inet_ntoa(in), s->port_local);

    fd_descriptor_t *file_desc_is = (fd_descriptor_t *) is;
    fd_descriptor_t *file_desc_s = (fd_descriptor_t *) s;
    // we need to give the stream to the new socket
    file_desc_is->stream = file_desc_s->stream;
  }
}
