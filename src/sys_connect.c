/* sys_connect -- Handles connect syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_connect.h"

#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles connect syscall at the entrance and the exit */
void syscall_connect(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_connect_pre(reg, sysarg, proc);
  else
    syscall_connect_post(reg, sysarg, proc);

}

/** @brief handles connect syscall at the entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  XBT_DEBUG("syscall_connect_pre");
  get_args_bind_connect(proc, reg, sysarg);
  if (process_connect_in_call(proc, sysarg)) {
    connect_arg_t arg = &(sysarg->connect);

    struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
    struct infos_socket *s = comm_get_peer(is);
    fd_descriptor_t *file_desc = (fd_descriptor_t *) is;
    fd_descriptor_t *file_desc_remote = (fd_descriptor_t *) s;

    // We copy the stream to have it in both sides
    file_desc->stream = file_desc_remote->stream;
    file_desc->stream->client = MSG_process_self();
    file_desc->stream->to_client = MSG_host_get_name(MSG_host_self());

    XBT_DEBUG("connect_pre: trying to release server semaphore ...");
    MSG_sem_release(file_desc->stream->sem_server);
    XBT_DEBUG("connect_pre: server semaphore released, trying to take client semaphore ...");
    MSG_sem_acquire(file_desc->stream->sem_client);
    XBT_DEBUG("connect_pre: took client semaphore!");

    return process_handle(proc);
  } else {
    XBT_WARN("syscall_connect_pre: process_connect_in_call == 0  <--------- ");
    proc_outside(proc);
  }
  return PROCESS_CONTINUE;
}

/** @brief handles connect syscall at exit
 *
 * We use semaphores to synchronize client and server during a connection. */
void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  XBT_DEBUG("connect_post");
  get_args_bind_connect(proc, reg, sysarg);

  connect_arg_t arg = &(sysarg->connect);
#ifdef address_translation
  int domain = get_domain_socket(proc, arg->sockfd);
  if (domain == 2 && arg->ret >= 0) {
    struct infos_socket *is = get_infos_socket(proc, arg->sockfd);

    sys_translate_connect_out(proc, sysarg);
    int port = socket_get_local_port(proc, arg->sockfd);
    set_real_port(proc->host, is->port_local, ntohs(port));
    add_new_translation(ntohs(port), is->port_local, get_ip_of_host(proc->host));
  }
#endif
  if (strace_option)
    print_connect_syscall(proc, sysarg);

  fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, arg->sockfd);
  file_desc->refcount++;

  XBT_DEBUG("connect_post: trying to release server semaphore ...");
  MSG_sem_release(file_desc->stream->sem_server);
  XBT_DEBUG("connect_post: server semaphore released");

  file_desc->refcount--;
  file_desc = NULL;
}

/** @brief helper function to handle connect syscall */
int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  XBT_DEBUG("CONNEXION: process_connect_in_call");
  pid_t pid = proc->pid;
  int domain = get_domain_socket(proc, arg->sockfd);

  if (domain == 2)              //PF_INET
    {
      struct sockaddr_in *sai = &(arg->sai);

      msg_host_t host;
      int device;
      struct in_addr in;

      if (sai->sin_addr.s_addr == inet_addr("127.0.0.1")) {
        in.s_addr = inet_addr("127.0.0.1");
        device = PORT_LOCAL;
        host = proc->host;
      } else {
        in.s_addr = get_ip_of_host(proc->host);
        device = PORT_REMOTE;
        host = get_host_by_ip(sai->sin_addr.s_addr);
        if (host == NULL) {
          arg->ret = -ECONNREFUSED;       /* ECONNREFUSED       111 Connection refused */
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
          connect_arg_t arg = &(sysarg->connect);
          ptrace_restore_syscall(pid, SYS_connect, arg->ret);
          return 0;
        }
      }

      //We ask for a connection on the socket
      process_descriptor_t *acc_proc = comm_ask_connect(host, ntohs(sai->sin_port), proc, arg->sockfd, device);

      //if the process is waiting for connection
      if (acc_proc) {
        //Now attribute ip and port to the socket.
        int port = get_random_port(proc->host);

        XBT_DEBUG("New socket %s:%d", inet_ntoa(in), port);
        set_localaddr_port_socket(proc, arg->sockfd, inet_ntoa(in), port);
        register_port(proc->host, port);
        XBT_DEBUG("Free port found on host %s (%s:%d)", MSG_host_get_name(proc->host), inet_ntoa(in), port);
            } else {
        XBT_DEBUG("No peer found");
        arg->ret = -ECONNREFUSED; /* ECONNREFUSED 111 Connection refused */
        ptrace_neutralize_syscall(pid);
        proc_outside(proc);
        connect_arg_t arg = &(sysarg->connect);
        ptrace_restore_syscall(pid, SYS_connect, arg->ret);
        return 0;
      }
#ifndef address_translation
      //Now we try to see if the socket is blocking of not
      int flags = socket_get_flags(proc, arg->sockfd);
      if (flags & O_NONBLOCK)
	arg->ret = -EINPROGRESS;  /* EINPROGRESS  115      Operation now in progress */
      else
	arg->ret = 0;

      ptrace_neutralize_syscall(pid);
      connect_arg_t arg = &(sysarg->connect);
      ptrace_restore_syscall(pid, SYS_connect, arg->ret);

      //now mark the process as waiting for connection
      if (flags & O_NONBLOCK)
	return 0;

      return 1;
#else
      XBT_DEBUG("connect_in address translation");
      sys_translate_connect_in(proc, sysarg);
      int flags = socket_get_flags(proc, arg->sockfd);
      if (flags & O_NONBLOCK)
	return 0;

      return 1;
#endif
    } else
    return 0;
}
