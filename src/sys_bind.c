/* sys_bind -- Handles bind syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_bind.h"

#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
/* #include "simterpose.h" */
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles bind syscall at the entrance and the exit */
void syscall_bind(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_bind_pre(reg, proc);
  else
    syscall_bind_post(reg, proc);
}

/** @brief handles bind syscall at the entrance */
void syscall_bind_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);

  if ((int) reg->ret == -EINPROGRESS) /* EINPROGRESS        115      Operation now in progress */
    reg->ret = 0;

  pid_t pid = proc->pid;
  int sockfd =  (int) reg->arg[0];
  int domain = get_domain_socket(proc, sockfd);
  socklen_t addrlen = (socklen_t) reg->arg[2];
  struct sockaddr_in sai;
  struct sockaddr_un sau;
  struct sockaddr_nl snl;

  if (domain == 2)              // PF_INET
    ptrace_cpy(pid, &sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "bind");
  if (domain == 1)              // PF_UNIX
    ptrace_cpy(pid, &sau, (void *) reg->arg[1], sizeof(struct sockaddr_in), "bind");
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(pid, &snl, (void *) reg->arg[1], sizeof(struct sockaddr_in), "bind");

  if (socket_registered(proc, sockfd)) {
    if (socket_network(proc, sockfd)) {

      if (!is_port_in_use(proc->host, ntohs(sai.sin_port))) {
        XBT_DEBUG("Port %d is free", ntohs(sai.sin_port));
        register_port(proc->host, ntohs(sai.sin_port));

        struct infos_socket *is = get_infos_socket(proc, sockfd);
        int device = 0;
        if (sai.sin_addr.s_addr == INADDR_ANY)
          device = (PORT_LOCAL | PORT_REMOTE);
        else if (sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
          device = PORT_LOCAL;
        else
          device = PORT_REMOTE;
	set_port_on_binding(proc->host, ntohs(sai.sin_port), is, device);
        
        is->binded = 1;

	set_localaddr_port_socket(proc, sockfd, inet_ntoa(sai.sin_addr), ntohs(sai.sin_port));
        reg->ret = 0;
	
#ifdef address_translation
        int port = ptrace_find_free_binding_port(pid);
        XBT_DEBUG("Free port found %d", port);
        proc_outside(proc);
	set_real_port(proc->host, ntohs(sai.sin_port), port);
        add_new_translation(port, ntohs(sai.sin_port), get_ip_of_host(proc->host));
        if (strace_option)
          print_bind_syscall(reg, proc);
        return;
#endif
      } else {
	XBT_DEBUG("Port %d isn't free", ntohs(sai.sin_port));
        reg->ret = -EADDRINUSE; /* EADDRINUSE 98 Address already in use */

	ptrace_neutralize_syscall(pid);
	ptrace_restore_syscall(pid, SYS_bind, (int) reg->ret);
        proc_outside(proc);
        if (strace_option)
	  print_bind_syscall(reg, proc);
        return;
      }
#ifndef address_translation
      ptrace_neutralize_syscall(pid);
      ptrace_restore_syscall(pid, SYS_bind, (int) reg->ret);
      proc_outside(proc);
#endif
    }
  }
  if (strace_option)
    print_bind_syscall(reg, proc);
}

/** @brief print bind syscall at the exit */
void syscall_bind_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  if (strace_option)
    print_bind_syscall(reg, proc);
}
