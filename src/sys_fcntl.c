/* sys_fcntl -- Handles fcntl syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <sys/stat.h>
#include <fcntl.h>

#include "sys_fcntl.h"

#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles fcntl syscall at the entrance and the exit */
void syscall_fcntl(reg_s * reg, process_descriptor_t * proc)
{
  if (proc_entering(proc)) {
    proc_inside(proc);
    XBT_DEBUG("fcntl pre");
#ifndef address_translation
    process_fcntl_call(reg, proc);
    
    if (strace_option)
      print_fcntl_syscall(reg, proc);
    sleep(4);
#endif
  } else {
    proc_outside(proc);
    XBT_DEBUG("fcntl post");
    if (strace_option)
      print_fcntl_syscall(reg, proc);
#ifdef address_translation
    process_fcntl_call(reg, proc);
#endif
  }
}

/** @brief helper function to handle fcntl syscall */
// TODO: handles the other flags
void process_fcntl_call(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG("process fcntl");

  /* Retrieve the command and its arguments */
  int cmd = (int) reg->arg[1];
  long cmd_arg;
  struct f_owner_ex * owner;
  struct flock * lock;
  
     if ((cmd == F_DUPFD) || (cmd == F_DUPFD_CLOEXEC)
      || (cmd == F_SETFD) || (cmd == F_SETFL)
      || (cmd == F_SETOWN))
    cmd_arg = (long) reg->arg[2];
#ifdef __USE_GNU
  if ((cmd == F_SETSIG) || (cmd == F_SETLEASE)
      || (cmd == F_NOTIFY)
      || (cmd == F_SETPIPE_SZ))
    cmd_arg = (long) reg->arg[2];
  if ((cmd == F_GETOWN_EX) || (cmd == F_SETOWN_EX))
    owner = (struct f_owner_ex *) reg->arg[2];
#endif
  if ((cmd == F_GETLK) || (cmd == F_SETLK) || (cmd == F_SETLKW))
    lock = (struct flock *) reg->arg[2];
  
  if ((int) reg->ret == -1){
    XBT_WARN("Error on fcntl syscall exit");
    exit(-1);
  }
  fd_descriptor_t* arg_fdesc = process_descriptor_get_fd(proc, (int) reg->arg[0]);

   switch (cmd) {

  case F_DUPFD: {
#ifndef address_translation
    /* TODO: full mediation */
    /* Find the lowest free fd and realize the syscall*/
    /*reg->ret =*/ /*fd find*/
#endif
    fd_descriptor_t* file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->type = arg_fdesc->type;
    file_desc->proc = proc;
    file_desc->fd = (int) reg->ret;
    file_desc->stream = arg_fdesc->stream;
    file_desc->pipe = arg_fdesc->pipe;
    file_desc->flags = arg_fdesc->flags;
    file_desc->refcount = 1; /* To check or 0 and then ++ */
    process_descriptor_set_fd(proc, (int) reg->ret, file_desc);
    break; }

  case F_DUPFD_CLOEXEC: {
#ifndef address_translation
    /* TODO: full mediation */
    /* Find the lowest free fd and realize the syscall don't forget to add the O_CLOEXEC flag */
    /*reg->ret =*/ /*fd find */
#endif
    fd_descriptor_t* file_desc = xbt_malloc0(sizeof(fd_descriptor_t));
    file_desc->type = arg_fdesc->type;
    file_desc->proc = proc;
    file_desc->fd = (int) reg->ret;
    file_desc->stream = arg_fdesc->stream;
    file_desc->pipe = arg_fdesc->pipe;
    file_desc->flags = arg_fdesc->flags | O_CLOEXEC;
    file_desc->refcount = 1; /* To check or 0 and then ++ */
    process_descriptor_set_fd(proc, (int) reg->ret, file_desc);
    break; }

  case F_GETFD:
#ifndef address_translation
    reg->ret = arg_fdesc->flags;
#endif
    break;

  case F_SETFD:
#ifndef address_translation
    /* TODO : full mediation */
    /* Change the flags in the memory of the file */
    reg->ret = 0;
#endif
    arg_fdesc->flags = (int) cmd_arg;
    break;

  case F_GETFL:
#ifndef address_translation
    reg->ret = socket_get_flags(proc, (int) reg->arg[0], cmd_arg);

    /* TODO: full mediation */
    /* If the fd is not a socket: */
    /* reg->ret = process_descriptor_get_fd(proc, (int) reg->arg[0])->flags; */
#endif
    break;

  case F_SETFL:

#ifndef address_translation
    /* TODO: full mediation */
    /* Change manually the state and mode flags in memory of the file */
    reg->ret = 0;
#endif

    socket_set_flags(proc, (int) reg->arg[0],cmd_arg);

    /* TODO: full mediaiton */
    /* If the fd is not a socket: */
    /* This suggestion is not possible now because we delete arg structure */
    /* process_descriptor_get_fd(proc, (int) reg->arg[0])->flags = arg->arg; */
    break;

  case F_SETLK:
#ifndef address_translation
    int lock_bit;
    /* TODO: full mediation */
    /* Realize the syscall */
    /* lock = 0 ou 1 */
    if (!lock_bit){
    reg->ret = -1;
    /*Put errno to the right value*/
  }
    else
      reg->ret = 0;
#endif

    if (reg->ret == 0){

    arg_fdesc->lock = 1;
    arg_fdesc->proc_locker = lock->l_pid;

    off_t begin = lock->l_start + lock->l_whence;
    off_t len = lock->l_len;
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
    arg_fdesc->ltype = lock->l_type;
  }
    break;

  case F_SETLKW:
#ifndef address_translation
    int lock_bit;
    /* TODO: full mediation */
    /* Realize the syscall */
    /* lock = 0 ou 1 */
    if (!lock_bit){
    reg->ret = -1;
    /*Put errno to the right value*/
  }
    else
      reg->ret = 0;
#endif

    if (reg->ret == 0){
    arg_fdesc->lock = 1;
    arg_fdesc->proc_locker = lock->l_pid;

    off_t begin = lock->l_start + lock->l_whence;
    off_t len = lock->l_len;
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
    arg_fdesc->ltype = lock->l_type;
  }
    break;

  case F_GETLK:
#ifndef address_trasnlation
    /* TODO: full mediation */
#endif
    if (lock->l_type != F_UNLCK){
      arg_fdesc->lock = 1;  
      arg_fdesc->proc_locker = lock->l_pid;
      
      off_t begin = lock->l_start + lock->l_whence;
      off_t len = lock->l_len;
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
      arg_fdesc->ltype = lock->l_type;
    }
    break;

  case F_GETOWN:
#ifndef address_trasnlation
    /* TODO: full mediation */
#endif
    if (reg->ret < 0)
      arg_fdesc->sig_group_id = fabs(reg->ret);
    else
      arg_fdesc->sig_proc_id = reg->ret;
    break;

  case F_SETOWN:
#ifndef address_trasnlation
    /* TODO: full mediation */
#endif
    if (reg->arg[2] < 0)
      arg_fdesc->sig_group_id = fabs(reg->arg[2]);
    else
      arg_fdesc->sig_proc_id = reg->arg[2];
    break;


#ifdef __USE_GNU 
    /* TODO: Be careful these commands are not awailable on all systems */
  case F_GETSIG:
    XBT_WARN("F_GETSIG unhandled, you use __USE_GNU");
    break;

  case F_SETSIG:
    XBT_WARN("F_SETSIG unhandled, you use __USE_GNU");
    break;

  case F_GETOWN_EX:
    XBT_WARN("F_GETOWN_EX unhandled, you use __USE_GNU");
    break;

  case F_SETOWN_EX:
    XBT_WARN("F_SETOWN_EX unhandled, you use __USE_GNU");
    break;

  case F_GETLEASE:
    XBT_WARN("F_GETLEASE unhandled, you use __USE_GNU");
    break;

  case F_SETLEASE:
    XBT_WARN("F_SETLEASE unhandled, you use __USE_GNU");
    break;

  case F_NOTIFY:
    XBT_WARN("F_NOTIFY unhandled, you use __USE_GNU");
    break;

  case F_GETPIPE_SZ:
    XBT_WARN("F_GETPIPE_SZ unhandled, you use __USE_GNU");
    break;

  case F_SETPIPE_SZ:
    XBT_WARN("F_SETPIPE_SZ unhandled, you use __USE_GNU");
    break;
#endif

  default:
    XBT_WARN("Unknown fcntl flag or non declared on this architecture");
    break;
  }
#ifndef address_translation
    ptrace_neutralize_syscall(proc->pid);
    ptrace_restore_syscall(proc->pid, SYS_fcntl, reg->ret);
    proc_outside(proc);
#endif

  }
