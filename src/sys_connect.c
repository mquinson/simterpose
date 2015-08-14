/* sys_connect -- Handles connect syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_connect.h"

#include "data_utils.h"
#include "print_syscall.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles connect syscall at the entrance and the exit */
void syscall_connect(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_connect_pre(reg, proc);
  else
    syscall_connect_post(reg, proc);

}

/** @brief handles connect syscall at the entrance
 *
 * We use semaphores to synchronize client and server during a connection. */
int syscall_connect_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
  XBT_DEBUG("syscall_connect_pre");

  pid_t pid = proc->pid;
  int sockfd = (int) reg->arg[0];
  int domain = get_domain_socket(proc, sockfd);
  struct sockaddr_in sai; 
  struct sockaddr_un sau;
  struct sockaddr_nl snl;
 
 if ((int) reg->ret == -EINPROGRESS) /* EINPROGRESS        115      Operation now in progress */
    reg->ret = 0;

  if (domain == 2)              // PF_INET
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
  if (domain == 1)              // PF_UNIX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_un), "connect");
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_nl), "connect");


  if (process_connect_in_call(reg, proc)) {
    struct infos_socket *is = get_infos_socket(proc, sockfd);
    
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
void syscall_connect_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  XBT_DEBUG("connect_post");
  pid_t pid = proc->pid;
  int sockfd = (int) reg->arg[0];
  int domain = get_domain_socket(proc, sockfd);
  struct sockaddr_in sai; 
  struct sockaddr_un sau;
  struct sockaddr_nl snl;
 
 if ((int) reg->ret == -EINPROGRESS) /* EINPROGRESS        115      Operation now in progress */
    reg->ret = 0;

  if (domain == 2)              // PF_INET
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
  if (domain == 1)              // PF_UNIX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_un), "connect");
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_nl), "connect");
  
#ifdef address_translation
  domain = get_domain_socket(proc, sockfd);
  if (domain == 2 && (int)reg->ret >= 0) {
    struct infos_socket *is = get_infos_socket(proc, sockfd);
    sys_translate_connect_out(reg, proc);
    
    int port = socket_get_local_port(proc, sockfd);
    set_real_port(proc->host, is->port_local, ntohs(port));
    add_new_translation(ntohs(port), is->port_local, get_ip_of_host(proc->host));
  }
#endif
  if (strace_option)
    print_connect_syscall(reg, proc);

  fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, sockfd);
  file_desc->refcount++;

  XBT_DEBUG("connect_post: trying to release server semaphore ...");
  MSG_sem_release(file_desc->stream->sem_server);
  XBT_DEBUG("connect_post: server semaphore released");

  file_desc->refcount--;
  file_desc = NULL;
}

/** @brief helper function to handle connect syscall */
int process_connect_in_call(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG("CONNEXION: process_connect_in_call");
  pid_t pid = proc->pid;
  int domain = get_domain_socket(proc, (int) reg->arg[0]);

  if (domain == 2)              //PF_INET
    {
      struct sockaddr_in sai;
      ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
      msg_host_t host;
      int device;
      struct in_addr in;

      if (sai.sin_addr.s_addr == inet_addr("127.0.0.1")) {
        in.s_addr = inet_addr("127.0.0.1");
        device = PORT_LOCAL;
        host = proc->host;
      } else {
        in.s_addr = get_ip_of_host(proc->host);
        device = PORT_REMOTE;
        host = get_host_by_ip(sai.sin_addr.s_addr);
        if (host == NULL) {
          reg->ret = -ECONNREFUSED;       /* ECONNREFUSED       111 Connection refused */
          ptrace_neutralize_syscall(pid);
          proc_outside(proc);
	  ptrace_restore_syscall(pid, SYS_connect, (int) reg->ret);
          return 0;
        }
      }

      //We ask for a connection on the socket
      process_descriptor_t *acc_proc = comm_ask_connect(host, ntohs(sai.sin_port), proc, (int) reg->arg[0], device);
      //if the process is waiting for connection
      if (acc_proc) {
        //Now attribute ip and port to the socket.
        int port = get_random_port(proc->host);

        XBT_DEBUG("New socket %s:%d", inet_ntoa(in), port);
	set_localaddr_port_socket(proc, (int) reg->arg[0], inet_ntoa(in), port);
        register_port(proc->host, port);
        XBT_DEBUG("Free port found on host %s (%s:%d)", MSG_host_get_name(proc->host), inet_ntoa(in), port);
            } else {
        XBT_DEBUG("No peer found");
        reg->ret = -ECONNREFUSED; /* ECONNREFUSED 111 Connection refused */
        ptrace_neutralize_syscall(pid);
        proc_outside(proc);
        ptrace_restore_syscall(pid, SYS_connect, (int) reg->ret);
        return 0;
      }
#ifndef address_translation
      //Now we try to see if the socket is blocking of not
      int flags = socket_get_flags(proc, (int) reg->arg[0]);
      if (flags & O_NONBLOCK)
	reg->ret = -EINPROGRESS;  /* EINPROGRESS  115      Operation now in progress */
      else
	reg->ret = 0;
      
      ptrace_neutralize_syscall(pid);
      ptrace_restore_syscall(pid, SYS_connect, (int) reg->ret);

      //now mark the process as waiting for connection
      if (flags & O_NONBLOCK)
	return 0;

      return 1;
#else
      XBT_DEBUG("connect_in address translation");
      sys_translate_connect_in(reg, proc);
      int flags = socket_get_flags(proc, (int) reg->arg[0]);
      if (flags & O_NONBLOCK)
	return 0;

      return 1;
#endif
    } else
    return 0;
}

/** @brief translate the port and address of the entering connect syscall
 *
 * We take the arguments in the registers, which correspond to global
 * simulated address and port. We translate them to real local ones,
 * and put the result back in the registers to actually get the
 * connect syscall performed by the kernel.
 */
void sys_translate_connect_in(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;

  struct sockaddr_in sai;
  ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");

  sai.sin_port = htons(get_real_port(proc, sai.sin_addr.s_addr, ntohs(sai.sin_port)));
  sai.sin_addr.s_addr = inet_addr("127.0.0.1");
  XBT_DEBUG("Try to connect on 127.0.0.1:%d", sai.sin_port);
  ptrace_poke(pid, (void *) reg->arg[1], &sai, sizeof(struct sockaddr_in));
}

/** @brief translate the port and address of the exiting connect syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we established the connection on. We translate
 * them into global simulated ones and put the result back in the registers,
 * so that the application gets wronged.
 */
void sys_translate_connect_out(reg_s * reg, process_descriptor_t * proc)
{
  pid_t pid = proc->pid;

  struct sockaddr_in sai;
  ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "connect");
  
  translate_desc_t *td = get_translation(ntohs(sai.sin_port));
  sai.sin_port = htons(td->port_num);
  sai.sin_addr.s_addr = td->ip;

  XBT_DEBUG("Restore %s:%d", inet_ntoa(sai.sin_addr), td->port_num);
  ptrace_poke(pid, (void *) reg->arg[1], &sai, sizeof(struct sockaddr_in));
}
