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
void syscall_bind(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_bind_pre(reg, sysarg, proc);
  else
    syscall_bind_post(reg, sysarg, proc);
}

/** @brief handles bind syscall at the entrance */
void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  get_args_bind_connect(proc, reg, sysarg);
  bind_arg_t arg = &(sysarg->bind);
  pid_t pid = proc->pid;
  if (socket_registered(proc, arg->sockfd)) {
    if (socket_network(proc, arg->sockfd)) {

      if (!is_port_in_use(proc->host, ntohs(arg->sai.sin_port))) {
        XBT_DEBUG("Port %d is free", ntohs(arg->sai.sin_port));
        register_port(proc->host, ntohs(arg->sai.sin_port));

        struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
        int device = 0;
        if (arg->sai.sin_addr.s_addr == INADDR_ANY)
          device = (PORT_LOCAL | PORT_REMOTE);
        else if (arg->sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
          device = PORT_LOCAL;
        else
          device = PORT_REMOTE;

        set_port_on_binding(proc->host, ntohs(arg->sai.sin_port), is, device);

        is->binded = 1;

        set_localaddr_port_socket(proc, arg->sockfd, inet_ntoa(arg->sai.sin_addr), ntohs(arg->sai.sin_port));
        arg->ret = 0;
#ifdef address_translation
        int port = ptrace_find_free_binding_port(pid);
        XBT_DEBUG("Free port found %d", port);
        proc_outside(proc);
        set_real_port(proc->host, ntohs(arg->sai.sin_port), port);
        add_new_translation(port, ntohs(arg->sai.sin_port), get_ip_of_host(proc->host));
        if (strace_option)
          print_bind_syscall(proc, sysarg);
        return;
#endif
      } else {
        XBT_DEBUG("Port %d isn't free", ntohs(arg->sai.sin_port));
        arg->ret = -EADDRINUSE; /* EADDRINUSE 98 Address already in use */
        ptrace_neutralize_syscall(pid);
        bind_arg_t arg = &(sysarg->bind);
        ptrace_restore_syscall(pid, SYS_bind, arg->ret);
        proc_outside(proc);
        if (strace_option)
          print_bind_syscall(proc, sysarg);
        return;
      }
#ifndef address_translation
      ptrace_neutralize_syscall(pid);
      bind_arg_t arg = &(sysarg->bind);
      ptrace_restore_syscall(pid, SYS_bind, arg->ret);
      proc_outside(proc);
#endif
    }
  }
  if (strace_option)
    print_bind_syscall(proc, sysarg);
}

/** @brief print bind syscall at the exit */
void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  get_args_bind_connect(proc, reg, sysarg);
  if (strace_option)
    print_bind_syscall(proc, sysarg);
}
