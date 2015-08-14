/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <simgrid/platf.h>
#include <simgrid/datatypes.h>
#include <simgrid/msg.h>

#include <arpa/inet.h>
#include <errno.h>
#include <sys/socket.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <poll.h>
#include <setjmp.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/select.h>
#include <sys/wait.h>
#include <syscall.h>
#include <unistd.h>
#include <xbt/asserts.h>
#include <xbt/dynar.h>
#include <xbt/ex.h>
#include <xbt/log.h>
#include <xbt/misc.h>
#include <xbt/sysdep.h>

#include "syscall_process.h"

#ifndef unknown_error // that stupid eclipse seems to not find that symbol (which comes from SimGrid logging features)
#define unknown_error 0
#endif

#define SYSCALL_ARG1 rdi
const char *state_names[4] = { "PROCESS_CONTINUE", "PROCESS_DEAD", "PROCESS_GROUP_DEAD", "PROCESS_TASK_FOUND" };

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, simterpose, "Syscall process log");

/** @brief Handles all syscalls of the tracked pid until it does a blocking action.
 *
 *  Blocking actions are stuff that must be reported to the simulator and which
 *  completion takes time. The most prominent examples are related to sending and
 *  receiving data.
 *
 *  The tracked pid can run more than one syscall in this function if theses calls
 *  are about the metadata that we maintain in simterpose without exposing them to
 *  simgrid. For example, if you call socket() or accept(), we only have to maintain
 *  our metadata but there is no need to inform the simulator, nor to ask for the
 *  completion time of these things.
 */
int process_handle(process_descriptor_t * proc)
{
  reg_s arg;
  pid_t pid = proc->pid;
  XBT_DEBUG("PROCESS HANDLE MSG");
  while (1) {
    ptrace_get_register(pid, &arg);
    int ret;
    XBT_DEBUG("found syscall: [%d] %s (%ld) = %ld, in_syscall = %d", pid, syscall_list[arg.reg_orig], arg.reg_orig,
      arg.ret, proc->in_syscall);

    switch (arg.reg_orig) {
    case SYS_creat:
      syscall_creat(&arg, proc);
      break;

    case SYS_open:
      XBT_DEBUG("On open");
      XBT_DEBUG("Valeur des registres dans l'AS:");
      XBT_DEBUG("Valeur de retour %lu", arg.ret);
      XBT_DEBUG("Valeur des arg %lu %lu %lu %lu %lu %lu", arg.arg[0], arg.arg[1], arg.arg[2], arg.arg[3], arg.arg[4], arg.arg[5]);
      syscall_open(&arg, proc);
      break;

    case SYS_close:
      syscall_close(&arg, proc);
      break;

    case SYS_read:
      syscall_read(&arg, proc);
      break;

    case SYS_write:
      XBT_DEBUG("On write");
      XBT_DEBUG("Valeur des registres dans l'AS:");
      XBT_DEBUG("Valeur de retour %lu", arg.ret);
      XBT_DEBUG("Valeur des arg %lu %lu %lu %lu %lu %lu", arg.arg[0], arg.arg[1], arg.arg[2], arg.arg[3], arg.arg[4], arg.arg[5]);
      if ((ret = syscall_write(&arg, proc)))
	return ret;
      break;

    case SYS_dup:
      syscall_dup(&arg, proc);
      break;

    case SYS_dup2:
      syscall_dup2(&arg, proc);
      break;

    case SYS_fcntl:
      syscall_fcntl(&arg, proc);
      break;

    case SYS_lseek:
      syscall_lseek(&arg, proc);
      break;

    case SYS_poll:
      syscall_poll(&arg, proc);
      break;

    case SYS_select:
      syscall_select(&arg, proc);
      break;

    case SYS_pipe:
      syscall_pipe(&arg, proc);

    case SYS_brk:
      syscall_brk(&arg, proc);
      break;

    case SYS_socket:
      syscall_socket(&arg, proc);
      break;

    case SYS_connect:
      syscall_connect(&arg, proc);
      break;

    case SYS_bind:
      syscall_bind(&arg, proc);
      break;

    case SYS_listen:
      syscall_listen(&arg, proc);
      break;

    case SYS_accept:
      syscall_accept(&arg, proc);
      break;

#ifdef arch_32
    case SYS_send:
      ret = syscall_send(&arg, proc);
      if (ret)
	return ret;
      break;

    case SYS_recv:
      syscall_recv(&arg, proc);
      break;
#endif

    case SYS_sendto:
      ret = syscall_sendto(&arg, proc);
      if (ret)
        return ret;
      break;

    case SYS_recvfrom:
      syscall_recvfrom(&arg, proc);
      break;

    case SYS_sendmsg:
      if ((ret = syscall_sendmsg( &arg, proc)))
        return ret;
      break;

    case SYS_recvmsg:
      syscall_recvmsg(&arg, proc);
      break;

    case SYS_shutdown:
      syscall_shutdown(&arg, proc);
      break;

    case SYS_getpeername:
      syscall_getpeername(&arg, proc);
      break;

    case SYS_getsockopt:
      syscall_getsockopt(&arg, proc);
      break;

    case SYS_setsockopt:
      syscall_setsockopt(&arg, proc);
      break;

    case SYS_clone:
      syscall_clone(&arg, proc);
      break;

    case SYS_execve:
      syscall_execve(&arg, proc);
      break;

    case SYS_exit:
      XBT_DEBUG("exit(%ld) called", arg.arg[0]);
      return syscall_exit(&arg, proc);
      break;

    case SYS_exit_group:
      XBT_DEBUG("exit_group(%ld) called", arg.arg[0]);
      return syscall_exit(&arg, proc);
      break;

    case SYS_getpid:
      syscall_getpid(&arg, proc);
      break;

    default:
      syscall_default(pid, &arg, proc);
      break;
    }

    // Step the traced process
    ptrace_resume_process(pid);
    // XBT_DEBUG("process resumed, waitpid");
    waitpid(pid, &(proc->status), __WALL);
  }                             // while(1)

  THROW_IMPOSSIBLE;             //There's no way to quit the loop
  return 0;
}

/** @brief helper function to send task */
int process_send_call(reg_s * reg, process_descriptor_t * proc, process_descriptor_t * remote_proc, void * data)
{
  XBT_DEBUG("Entering process_send_call");
  if (socket_registered(proc, (int) reg->arg[0]) != -1) { 
    if (!socket_netlink(proc, (int) reg->arg[0])) {
      XBT_DEBUG("%d This is not a netlink socket", (int) reg->arg[0]);
      //   compute_computation_time(proc);   // cree la computation task
      struct infos_socket *is = get_infos_socket(proc, (int) reg->arg[0]);
      struct infos_socket *s = comm_get_peer(is);
      is->ref_nb++;
      s->ref_nb++;

      XBT_DEBUG("%d->%d", (int) reg->arg[0], (int) reg->ret);
      XBT_DEBUG("Sending data(%d) on socket %d", (int) reg->ret, s->fd.fd);
      handle_new_send(reg, is, data);

      msg_task_t task = create_send_communication_task(proc, is, (int) reg->ret, proc->host, s->fd.proc->host);
      XBT_DEBUG("hosts: %s send to %s (size: %d)", MSG_host_get_name(proc->host), MSG_host_get_name(s->fd.proc->host),
		(int) reg->ret);


      MSG_task_set_bytes_amount(task, (int) reg->ret);
      MSG_task_set_data(task, data);

      send_task(s->fd.proc->host, task);

      is->ref_nb--;
      s->ref_nb--;
      return 1;
    }
    return 0;
  } else
    xbt_die("The socket is not registered");
  return 0;
}

/** @brief helper function to close a file descriptor */
void process_close_call(process_descriptor_t * proc, int fd)
{
  fd_descriptor_t *file_desc = process_descriptor_get_fd(proc, fd);
  if (file_desc != NULL) {
    file_desc->refcount++;
    if (file_desc->type == FD_SOCKET)
      socket_close(proc, fd);
    else {
      if (file_desc->type == FD_PIPE) {
        pipe_t *pipe = file_desc->pipe;
        xbt_assert(pipe != NULL);

        unsigned int cpt_in;
        pipe_end_t end_in;
        xbt_dynar_t read_end = pipe->read_end;
        xbt_dynar_foreach(read_end, cpt_in, end_in) {
          if (end_in->fd == fd && end_in->proc->pid == proc->pid) {
            xbt_dynar_remove_at(read_end, cpt_in, NULL);
            cpt_in--;
          }
        }

        unsigned int cpt_out;
        pipe_end_t end_out;
        xbt_dynar_t write_end = pipe->write_end;
        xbt_dynar_foreach(write_end, cpt_out, end_out) {
          if (end_out->fd == fd && end_out->proc->pid == proc->pid) {
            xbt_dynar_remove_at(write_end, cpt_out, NULL);
            cpt_out--;
          }
        }

        // if both sides are closed we can free the pipe
        if (xbt_dynar_is_empty(read_end) && xbt_dynar_is_empty(write_end)) {
          xbt_dynar_free(&read_end);
          xbt_dynar_free(&write_end);
          free(pipe);
        }

      }
    }
    file_desc->refcount--;
    process_descriptor_set_fd(proc, fd, NULL);
  }
}

/** @brief Handles syscall that are still not implemented */
void syscall_default(pid_t pid, reg_s * reg, process_descriptor_t * proc){
  if (proc_entering(proc))
    proc_inside(proc);
  else {
    fprintf(stderr,"Unhandled syscall: [%d] %s = %ld\n", pid, syscall_list[reg->reg_orig], reg->ret);
    proc_outside(proc);
  }
}
