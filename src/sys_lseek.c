/* sys_lseek -- Handles lseek syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */
/* Author Louisa Bessad */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_lseek.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles lseek syscall at the entrance and the exit */
void syscall_lseek(reg_s * reg, process_descriptor_t * proc)
{
  if (proc_entering(proc)){
    proc_inside(proc);
    XBT_DEBUG("lseek pre");

#ifndef address_translation
    process_lseek_call(reg, proc);

    if (strace_option)
      print_lseek_syscall(reg, proc);
#endif
  } else{
    proc_outside(proc);
    XBT_DEBUG("lseek post");
    if (strace_option)
      print_lseek_syscall(reg, proc);
#ifdef address_translation
    process_lseek_call(reg, proc);
#endif
  }
}

/** @brief helper function to handle lseek syscall */
void process_lseek_call(reg_s * reg, process_descriptor_t * proc){
  XBT_DEBUG("process lseek");

  /* Retrieve the arguments */
  int fd = (int) reg->arg[0];
  off_t ret_off = (off_t) reg->ret;

fd_descriptor_t * file_fd = process_descriptor_get_fd(proc, fd);
  if (ret_off >= 0 )
    file_fd->offset = ret_off;
  else
    XBT_WARN("Error on lseek");

 if (strace_option)
   fprintf(stderr, "[%d] lseek(%d, %jd, %d) = %jd \n", proc->pid, fd, (off_t) reg->arg[1], (int) reg->arg[2], ret_off);
}
