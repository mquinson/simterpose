/* sys_dup2 -- Handles dup2 syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_dup2.h"

#include "simterpose.h"
#include "syscall_process.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles dup2 syscall at the entrance and the exit */
void syscall_dup2(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    proc_inside(proc);
  else
    syscall_dup2_post(reg, sysarg, proc);

}

/** @brief handles dup2 at the exit
    Update the table of file descriptors, and also the pipe objects if needed */
void syscall_dup2_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  unsigned int oldfd = (int) reg->arg[0];
  unsigned int newfd = (int) reg->arg[1];

  fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, oldfd);
  file_desc->refcount++;
  process_descriptor_get_fd(proc, newfd)->refcount--;
  process_close_call(proc, newfd);
  process_descriptor_set_fd(proc, newfd, file_desc);
  file_desc->refcount++;

  if (strace_option)
    fprintf(stderr, "[%d] dup2(%d, %d) = %lu \n", proc->pid, oldfd, newfd, reg->ret);

  if (file_desc->type == FD_PIPE) {
    pipe_t *pipe = file_desc->pipe;

    // look for the fd in the read end of the pipe
    xbt_dynar_t read_end = pipe->read_end;
    unsigned int cpt_in;
    pipe_end_t end_in;
    xbt_dynar_foreach(read_end, cpt_in, end_in) {
      if (end_in->fd == oldfd && end_in->proc == proc) {
        pipe_end_t dup_end = xbt_malloc0(sizeof(pipe_end_s));
        dup_end->fd = newfd;
        dup_end->proc = end_in->proc;
        xbt_dynar_push(read_end, &dup_end);
      }
    }

    // look for the fd in the write end of the pipe
    xbt_dynar_t write_end = pipe->write_end;
    unsigned int cpt_out;
    pipe_end_t end_out;
    xbt_dynar_foreach(write_end, cpt_out, end_out) {
      if (end_out->fd == oldfd && end_out->proc == proc) {
        pipe_end_t dup_end = xbt_malloc0(sizeof(pipe_end_s));
        dup_end->fd = newfd;
        dup_end->proc = end_out->proc;
        xbt_dynar_push(write_end, &dup_end);
      }
    }
  }
}
