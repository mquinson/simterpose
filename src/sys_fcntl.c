/* sys_fcntl -- Handles fcntl syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <sys/stat.h>
#include <fcntl.h>

#include "sys_fcntl.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles fcntl syscall at the entrance and the exit */
void syscall_fcntl(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
    XBT_DEBUG("fcntl pre");
#ifndef address_translation
    get_args_fcntl(proc, reg, sysarg);
    process_fcntl_call(proc, sysarg);
    if (strace_option)
      print_fcntl_syscall(proc, sysarg);
    sleep(4);
#endif
  } else {
    proc_outside(proc);
    XBT_DEBUG("fcntl post");
    get_args_fcntl(proc, reg, sysarg);
    if (strace_option)
      print_fcntl_syscall(proc, sysarg);
#ifdef address_translation
    process_fcntl_call(proc, sysarg);
#endif
  }
}

/** @brief helper function to handle fcntl syscall */
// TODO: handles the other flags
void process_fcntl_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG("process fcntl");

  fcntl_arg_t arg = &(sysarg->fcntl);

  if (arg->ret == -1){
    XBT_WARN("Error on fcntl syscall exit");
    exit(-1);
  }
  fd_descriptor_t* arg_fdesc = process_descriptor_get_fd(proc, arg->fd);

  switch (arg->cmd) {

  case F_DUPFD: {
#ifndef address_translation
    /* TODO: full mediation */
    /* Find the lowest free fd and realize the syscall*/
    /*arg->ret =*/ /*fd find*/
#endif
    fd_descriptor_t* file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->type = arg_fdesc->type;
    file_desc->proc = proc;
    file_desc->fd = arg->ret;
    file_desc->stream = arg_fdesc->stream;
    file_desc->pipe = arg_fdesc->pipe;
    file_desc->flags = arg_fdesc->flags;
    file_desc->refcount = 1; /* To check or 0 and then ++ */
    process_descriptor_set_fd(proc, arg->ret, file_desc);
    break; }

  case F_DUPFD_CLOEXEC: {
#ifndef address_translation
    /* TODO: full mediation */
    /* Find the lowest free fd and realize the syscall don't forget to add the O_CLOEXEC flag*/
    /*arg->ret =*/ /*fd find*/
#endif
    fd_descriptor_t* file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->type = arg_fdesc->type;
    file_desc->proc = proc;
    file_desc->fd = arg->ret;
    file_desc->stream = arg_fdesc->stream;
    file_desc->pipe = arg_fdesc->pipe;
    file_desc->flags = arg_fdesc->flags | O_CLOEXEC;
    file_desc->refcount = 1; /* To check or 0 and then ++ */
    process_descriptor_set_fd(proc, arg->ret, file_desc);
    break; }

  case F_GETFD:
#ifndef address_translation
    arg->ret = arg_fdesc->flags;
#endif
    break;

  case F_SETFD:
#ifndef address_translation
    /* TODO */
    /* Change the flags in the memory of the file*/
    arg->ret = 0;
#endif
    arg_fdesc->flags = (int) arg->arg.cmd_arg;
    break;

  case F_GETFL:
#ifndef address_translation
    arg->ret = socket_get_flags(proc, arg->fd, arg->arg->cmd_arg);

    /* TODO: */
    /* If the fd is not a socket: */
    /* arg->ret = process_descriptor_get_fd(proc, arg->fd)->flags; */
#endif
    break;

  case F_SETFL:

#ifndef address_translation
    /* TODO: */
    /* Change manually the state and mode flags in memory of the file */
    arg->ret = 0;
#endif

    socket_set_flags(proc, arg->fd,arg->arg.cmd_arg);

    /* TODO: */
    /* If the fd is not a socket: */
    /* process_descriptor_get_fd(proc, arg->fd)->flags = arg->arg; */
    break;

  case F_SETLK:
#ifndef address_translation
    int lock;
    /* TODO */
    /* Realize the syscall */
    /* lock = 0 ou 1 */
    if (!lock){
    arg->ret = -1;
    /*Put errno to the right value*/
  }
    else
      arg->ret = 0;
#endif

    if (arg->ret == 0){

    arg_fdesc->lock = 1;
    arg_fdesc->proc_locker = arg->arg.lock->l_pid;

    off_t begin = arg->arg.lock->l_start + arg->arg.lock->l_whence;
    off_t len = arg->arg.lock->l_len;
    if (len > 0){
    arg_fdesc->begin = begin;
    arg_fdesc->end = begin + len - 1;
  }
    if  (len < 0){
    arg_fdesc->begin = begin + len;
    arg_fdesc->end = begin - 1;
  }
    if (len == 0){
    arg_fdesc->begin = begin + len;
    arg_fdesc->end = begin - 1;
  }
  }
    break;

  case F_SETLKW:
    #ifndef address_translation
    int lock;
    /* TODO */
    /* Realize the syscall */
    /* lock = 0 ou 1 */
    if (!lock){
    arg->ret = -1;
    /*Put errno to the right value*/
  }
    else
      arg->ret = 0;
#endif

    if (arg->ret == 0){
    arg_fdesc->lock = 1;
    arg_fdesc->proc_locker = arg->arg.lock->l_pid;

    off_t begin = arg->arg.lock->l_start + arg->arg.lock->l_whence;
    off_t len = arg->arg.lock->l_len;
    if (len > 0){
    arg_fdesc->begin = begin;
    arg_fdesc->end = begin + len - 1;
  }
    if  (len < 0){
    arg_fdesc->begin = begin + len;
    arg_fdesc->end = begin - 1;
  }
    if (len == 0){
    arg_fdesc->begin = begin + len;
    arg_fdesc->end = begin - 1;
  }
  }
    break;

  case F_GETLK:
    XBT_WARN("F_GETLK unhandled");
    break;

  case F_GETOWN:
    XBT_WARN("F_GETOWN unhandled");
    break;

  case F_SETOWN:
    XBT_WARN("F_SETOWN unhandled");
    break;

#ifdef __USE_GNU
  case F_GETSIG:
    XBT_WARN("F_GETSIG unhandled");
    break;

  case F_SETSIG:
    XBT_WARN("F_SETSIG unhandled");
    break;

  case F_GETOWN_EX:
    XBT_WARN("F_GETOWN_EX unhandled");
    break;

  case F_SETOWN_EX:
    XBT_WARN("F_SETOWN_EX unhandled");
    break;

  case F_GETLEASE:
    XBT_WARN("F_GETLEASE unhandled");
    break;

  case F_SETLEASE:
    XBT_WARN("F_SETLEASE unhandled");
    break;

  case F_NOTIFY:
    XBT_WARN("F_NOTIFY unhandled");
    break;

  case F_GETPIPE_SZ:
    XBT_WARN("F_GETPIPE_SZ unhandled");
    break;

  case F_SETPIPE_SZ:
    XBT_WARN("F_SETPIPE_SZ unhandled");
    break;
#endif

  default:
    XBT_WARN("Unknown fcntl flag or non declared on this architecture");
    break;
  }
#ifndef address_translation
    ptrace_neutralize_syscall(proc->pid);
    ptrace_restore_syscall(proc->pid, SYS_fcntl, arg->ret);
    proc_outside(proc);
#endif

  }
