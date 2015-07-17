/* sys_pool -- Handles pool syscall */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.           */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include "sys_pool.h"

#include "args_trace.h"
#include "print_syscall.h"
#include "simterpose.h"
#include "sockets.h"
/* #include "syscall_process.h" */

XBT_LOG_EXTERNAL_DEFAULT_CATEGORY(SYSCALL_PROCESS);

/** @brief handles poll syscall at the entrance and the exit */
void syscall_poll(reg_s * reg, process_descriptor_t * proc){
  if (proc_entering(proc))
    syscall_poll_pre(reg, proc);
  else
    syscall_poll_post(reg, proc);
}

/** @brief handles poll syscall at the entrance */
// TODO: doesn't work. We do irecv on each file descriptor and then a waitany
void syscall_poll_pre(reg_s * reg, process_descriptor_t * proc)
{
  proc_inside(proc);
  
  pid_t child = proc->pid;
  void *src = (void *) reg->arg[0];
  nfds_t nfds = (nfds_t) reg->arg[1];
  int timeout = ((int) reg->arg[2]) / 1000. ;     //the timeout is in millisecond 
  struct pollfd *fd_list = xbt_new0(struct pollfd, nfds);
  
  if (src != 0) {
        ptrace_cpy(child, fd_list, src, nfds * sizeof(struct pollfd), "poll");
  } else
    fd_list = NULL;
    
  if (strace_option)
    print_poll_syscall(reg, proc, fd_list, timeout);

  //  XBT_WARN("Poll: Timeout not handled\n");

  /*  int i;
      xbt_dynar_t comms = xbt_dynar_new(sizeof(msg_comm_t), NULL);
      xbt_dynar_t backup = xbt_dynar_new(sizeof(int), NULL);*/

  // for (i = 0; i < arg->nbfd; ++i) {
  if (nfds > 1)
    XBT_WARN("Poll only handles one fd\n");

  struct pollfd *temp = &(fd_list[0]);
  msg_comm_t comm;
  struct infos_socket *is = get_infos_socket(proc, temp->fd);

  if (is != NULL) {
    is->ref_nb++;
    //   continue;
    //  else {
    int sock_status = socket_get_state(is);
    XBT_DEBUG("%d-> %d\n", temp->fd, sock_status);
    if (temp->events & POLLIN) {
      msg_task_t task = NULL;
      XBT_DEBUG("irecv");
      comm = MSG_task_irecv(&task, MSG_host_get_name(is->host));
      //   xbt_dynar_push(comms, comm);
      //   xbt_dynar_push(backup, &i);
    } else
      XBT_WARN("Poll only handles POLLIN for now\n");

    is->ref_nb--;
  }
  //  }
  XBT_DEBUG("wait");
  //  int nb = MSG_comm_waitany(comms);
  //  msg_comm_t comm = xbt_dynar_get_ptr(comms, nb);
  //  int j = xbt_dynar_get_as(comms, nb, int);
  msg_error_t err = MSG_comm_wait(comm, timeout);
  if (err == MSG_OK) {
    //  struct pollfd *temp = &(arg->fd_list[j]);
    temp->revents = temp->revents | POLLIN;

    XBT_DEBUG("Result for poll\n");
    ptrace_restore_syscall(proc->pid, SYS_poll, 1);
    reg->ret = 1;
    if (reg->arg[0] != 0)
      ptrace_poke(proc->pid, (void *) reg->arg[0], fd_list, sizeof(struct pollfd) * nfds);
    if (strace_option)
      print_poll_syscall(reg, proc, fd_list, timeout);
    free(fd_list);
  } else if (err == MSG_TIMEOUT) {
    XBT_DEBUG("Time out on poll\n");
     ptrace_restore_syscall(proc->pid, SYS_poll, 0);
    reg->ret = 0;
    if (reg->arg[0] != 0)
      ptrace_poke(proc->pid, (void *) reg->arg[0], fd_list, sizeof(struct pollfd) * nfds);
    if (strace_option)
      print_poll_syscall(reg, proc, fd_list, timeout);
    free(fd_list);
  }
}

/** @brief prints poll syscall at the exit */
void syscall_poll_post(reg_s * reg, process_descriptor_t * proc)
{
  proc_outside(proc);
  pid_t child = proc->pid;
  void *src = (void *) reg->arg[0];
  nfds_t nfds = (nfds_t) reg->arg[1];
  int timeout = ((int) reg->arg[2]) / 1000;     //the timeout is in millisecond
  struct pollfd * fd_list = xbt_new0(struct pollfd, nfds);

  if (src != 0) {
    ptrace_cpy(child, fd_list, src, nfds * sizeof(struct pollfd), "poll");

  } else
    fd_list = NULL;
  
  if (strace_option)
    print_poll_syscall(reg, proc, fd_list, timeout);
}
