/* sys_getpeername -- Handles getpeername syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_getpeername.h"
/* #include <netinet/in.h> */
#include "args_trace.h"
#include "data_utils.h"
#include "print_syscall.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles getpeername syscall at the entrance at the exit */
void syscall_getpeername(reg_s * reg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_getpeername_pre(reg, proc);
  else
    proc_outside(proc);

}

/** @brief handles getpeername syscall at the entrance */
void syscall_getpeername_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
  pid_t pid = proc->pid;

  socklen_t len = (socklen_t ) reg->arg[2];
  
  /* TODO */
  ptrace_cpy(proc->pid, &(len), &len, sizeof(socklen_t), "getpeername");

 if (socket_registered(proc, (int) reg->arg[0])) {
    if (socket_network(proc, (int) reg->arg[0])) {
      struct infos_socket *is = get_infos_socket(proc, (int) reg->arg[0]);
      struct sockaddr * in;
      socklen_t size = 0;
     
      if (!comm_getpeername(is, in, &size)) {
        if (size < len)
          reg->arg[2] = size;
        reg->arg[1] = (long) in;
        reg->ret = 0;
      } else
        reg->ret = -ENOTCONN; 
      ptrace(PTRACE_SETREGS, pid, NULL, &reg);

      ptrace_neutralize_syscall(pid);
      proc_outside(proc);
      ptrace_restore_syscall(pid, SYS_getpeername, (int) reg->ret);
	if ( (int) reg->ret == 0) {
	  /* TODO */
	ptrace_poke(pid, &len , &len, sizeof(socklen_t));
        ptrace_poke(pid, (void *) reg->arg[1], (struct sockaddr *) reg->arg[1], sizeof(struct sockaddr));
      }      
      if (strace_option)
	print_getpeername_syscall(reg, proc);
    }
 }
}
