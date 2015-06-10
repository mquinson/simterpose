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
void syscall_poll(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc){

  if (proc_entering(proc))
    syscall_poll_pre(reg, sysarg, proc);
  else
    syscall_poll_post(reg, sysarg, proc);

}

/** @brief handles poll syscall at the entrance */
// TODO: doesn't work. We do irecv on each file descriptor and then a waitany
void syscall_poll_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_inside(proc);
  get_args_poll(proc, reg, sysarg);
  if (strace_option)
    print_poll_syscall(proc, sysarg);

  poll_arg_t arg = (poll_arg_t) & (proc->sysarg.poll);

  //  XBT_WARN("Poll: Timeout not handled\n");

  /*  int i;
      xbt_dynar_t comms = xbt_dynar_new(sizeof(msg_comm_t), NULL);
      xbt_dynar_t backup = xbt_dynar_new(sizeof(int), NULL);*/

  // for (i = 0; i < arg->nbfd; ++i) {
  if (arg->nbfd > 1)
    XBT_WARN("Poll only handles one fd\n");

  struct pollfd *temp = &(arg->fd_list[0]);
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
  msg_error_t err = MSG_comm_wait(comm, arg->timeout);
  if (err == MSG_OK) {
    //  struct pollfd *temp = &(arg->fd_list[j]);
    temp->revents = temp->revents | POLLIN;

    XBT_DEBUG("Result for poll\n");
    sys_build_poll(proc, &(proc->sysarg), 1);
    if (strace_option)
      print_poll_syscall(proc, &(proc->sysarg));
    free(proc->sysarg.poll.fd_list);
  } else if (err == MSG_TIMEOUT) {
    XBT_DEBUG("Time out on poll\n");
    sys_build_poll(proc, &(proc->sysarg), 0);
    if (strace_option)
      print_poll_syscall(proc, &(proc->sysarg));
    free(proc->sysarg.poll.fd_list);
  }
}

/** @brief prints poll syscall at the exit */
void syscall_poll_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc_outside(proc);
  get_args_poll(proc, reg, sysarg);
  if (strace_option)
    print_poll_syscall(proc, sysarg);
}
