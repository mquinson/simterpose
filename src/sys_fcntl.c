/* sys_fcntl -- Handles fcntl syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */
/* Author Louisa Bessad */

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
  } else {
    proc_outside(proc);
    XBT_DEBUG("fcntl post");
    if (strace_option)
      print_fcntl_syscall(reg, proc);
    process_fcntl_call(reg, proc);
  }
}

/** @brief helper function to handle fcntl syscall */
void process_fcntl_call(reg_s * reg, process_descriptor_t * proc)
{
  XBT_DEBUG("process fcntl");

  /* Retrieve the command and its arguments */
  int cmd = (int) reg->arg[1];
  long cmd_arg;
  struct flock * lock = xbt_malloc(sizeof(struct flock));

  if ((cmd == F_DUPFD) || (cmd == F_DUPFD_CLOEXEC)
      || (cmd == F_SETFD) || (cmd == F_SETFL)
      || (cmd == F_SETOWN)) 
    cmd_arg = (long) reg->arg[2];
#ifdef __USE_GNU
  struct f_owner_ex * owner;
  if ((cmd == F_SETSIG) || (cmd == F_SETLEASE)
      || (cmd == F_NOTIFY)
      || (cmd == F_SETPIPE_SZ))
    cmd_arg = (long) reg->arg[2];
  if ((cmd == F_GETOWN_EX) || (cmd == F_SETOWN_EX))
    owner = (struct f_owner_ex *) reg->arg[2];
#endif
  if ((cmd == F_GETLK) || (cmd == F_SETLK) || (cmd == F_SETLKW)){
    ptrace_cpy(proc->pid, lock, (void *) reg->arg[2], sizeof(struct flock), "fcntl");
  }

  if ((int) reg->ret == -1){
    XBT_WARN("Error on fcntl syscall exit");
    exit(-1);
  }

  fd_descriptor_t * arg_fdesc = process_descriptor_get_fd(proc, (int) reg->arg[0]);
  fd_descriptor_t* file_desc_dup = xbt_malloc0(sizeof(fd_descriptor_t));
  fd_descriptor_t* file_desc_dup_cloexec = xbt_malloc0(sizeof(fd_descriptor_t)); 

  switch (cmd) {

  case F_DUPFD: 
    file_desc_dup->type = arg_fdesc->type;
    file_desc_dup->proc = proc;
    file_desc_dup->fd = (int) reg->ret;
    file_desc_dup->stream = arg_fdesc->stream;
    file_desc_dup->pipe = arg_fdesc->pipe;
    if ((arg_fdesc->flags & O_CLOEXEC) == O_CLOEXEC)
      file_desc_dup->flags = arg_fdesc->flags &~ O_CLOEXEC;
    else if ((arg_fdesc->flags & FD_CLOEXEC) == FD_CLOEXEC)
      file_desc_dup->flags = arg_fdesc->flags &~ FD_CLOEXEC;
    else
      file_desc_dup->flags = arg_fdesc->flags;
    file_desc_dup->refcount = 1; /* To check or 0 and then ++ */
    process_descriptor_set_fd(proc, (int) reg->ret, file_desc_dup);
    break; 

  case F_DUPFD_CLOEXEC:
    file_desc_dup_cloexec->type = arg_fdesc->type;
    file_desc_dup_cloexec->proc = proc;
    file_desc_dup_cloexec->fd = (int) reg->ret;
    file_desc_dup_cloexec->stream = arg_fdesc->stream;
    file_desc_dup_cloexec->pipe = arg_fdesc->pipe;
    file_desc_dup_cloexec->flags = arg_fdesc->flags | FD_CLOEXEC;
    file_desc_dup_cloexec->refcount = 1; /* To check or 0 and then ++ */
    process_descriptor_set_fd(proc, (int) reg->ret, file_desc_dup_cloexec);
    break; 

  case F_GETFD:
    break;

  case F_SETFD:
    if (cmd_arg == FD_CLOEXEC)
      arg_fdesc->flags |= (int) cmd_arg;
    else 
      ABORT("This flag is not FD_CLOEXEC.");
    break;

  case F_GETFL:
    break;

  case F_SETFL:
    if ((cmd_arg == O_APPEND) || (cmd_arg == O_ASYNC) || (cmd_arg == O_NONBLOCK) /*  || (cmd_arg == O_DIRECT) || (cmd_arg == O_NOATIME) */)
      arg_fdesc->flags |= (int) cmd_arg;
    break;

  case F_GETLK:
    if (lock->l_type == F_UNLCK) 
      arg_fdesc->ltype = F_UNLCK;
    else {
      arg_fdesc->ltype = lock->l_type;
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
    }
    break;

  case F_SETLK:
    if (reg->ret == 0){
      if ((lock->l_type == F_RDLCK) || (lock->l_type == F_WRLCK)){
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
	/*   (int) lock->l_start, (int) lock->l_len, lock->l_type); */
      }    
      else{
	arg_fdesc->lock = 0;
	arg_fdesc->ltype = F_UNLCK;
	arg_fdesc->begin = 0;
	arg_fdesc->end = 0;
	arg_fdesc->proc_locker = 0;
      }
    }
    break;

  case F_SETLKW:
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

  case F_GETOWN:
    if (reg->ret < 0)
      arg_fdesc->sig_group_id = fabs(reg->ret);
    else
      arg_fdesc->sig_proc_id = reg->ret;
    break;

  case F_SETOWN:
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

  if (strace_option)
    print_fcntl_syscall(reg, proc);
}
