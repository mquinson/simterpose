/* sys_pipe -- Handles pipe syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_pipe.h"

#include "args_trace.h"
#include "simterpose.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles pipe syscall at the entrance and the exit */
void syscall_pipe(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    proc_inside(proc);
  else
    syscall_pipe_post(reg, sysarg, proc);

}

/** @brief handles pipe syscall at the entrance
    Create a SimTerpose pipe and the corresponding file descriptors */
void syscall_pipe_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  get_args_pipe(proc, reg, sysarg);
  pipe_arg_t arg = &(sysarg->pipe);

  // TODO: add gestion of O_NONBLOCK and O_CLOEXEC flags

  if (arg->ret == 0) {
    // we create the pipe
    int p0 = *arg->filedes;
    int p1 = *(arg->filedes + 1);

    pipe_end_t in = xbt_malloc0(sizeof(pipe_end_s));
    in->fd = p0;
    in->proc = proc;

    pipe_end_t out = xbt_malloc0(sizeof(pipe_end_s));
    out->fd = p1;
    out->proc = proc;

    xbt_dynar_t end_in = xbt_dynar_new(sizeof(pipe_end_t), NULL);
    xbt_dynar_t end_out = xbt_dynar_new(sizeof(pipe_end_t), NULL);

    xbt_dynar_push(end_in, &in);
    xbt_dynar_push(end_out, &out);

    pipe_t *pipe = xbt_malloc0(sizeof(pipe_t));
    pipe->read_end = end_in;
    pipe->write_end = end_out;

    // we create the fd
    fd_descriptor_t *file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->refcount = 0;
    file_desc->fd = p0;
    file_desc->proc = proc;
    file_desc->type = FD_PIPE;
    file_desc->pipe = pipe;
    process_descriptor_set_fd(proc, p0, file_desc);
    file_desc->refcount++;

    file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->refcount = 0;
    file_desc->fd = p1;
    file_desc->proc = proc;
    file_desc->type = FD_PIPE;
    file_desc->pipe = pipe;
    process_descriptor_set_fd(proc, p1, file_desc);
    file_desc->refcount++;

    if (strace_option)
      fprintf(stderr, "[%d] pipe([%d,%d]) = %lu \n", proc->pid, p0, p1, arg->ret);
  } else {
    if (strace_option)
      fprintf(stderr, "[%d] pipe = %lu \n", proc->pid, arg->ret);
  }
}
