/* syscall_process -- Handles every syscall at the entrance/exit. */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */

#include "simterpose.h"
#include "syscall_process.h"
#include "syscall_data.h"
#include "sysdep.h"
#include "args_trace.h"
#include "data_utils.h"
#include "ptrace_utils.h"
#include "print_syscall.h"
#include "process_descriptor.h"
#include "sockets.h"

#include "xbt.h"
#include "xbt/log.h"

#include <time.h>
#include <linux/futex.h>
#include </usr/include/linux/sched.h>   /* For clone flags */

#define SYSCALL_ARG1 rdi
extern int strace_option;
const char *state_names[4] = { "PROCESS_CONTINUE", "PROCESS_DEAD", "PROCESS_GROUP_DEAD", "PROCESS_TASK_FOUND" };

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, simterpose, "Syscall process log");

int clone_number = 0;

static int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc)
{
  XBT_DEBUG("Entering process_send_call");
  sendto_arg_t arg = &(sysarg->sendto);
  if (socket_registered(proc, arg->sockfd) != -1) {
    if (!socket_netlink(proc, arg->sockfd)) {
      XBT_DEBUG("%d This is not a netlink socket", arg->sockfd);
      //   compute_computation_time(proc);   // cree la computation task
      struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
      struct infos_socket *s = comm_get_peer(is);

      XBT_DEBUG("%d->%d", arg->sockfd, arg->ret);
      XBT_DEBUG("Sending data(%d) on socket %d", arg->ret, s->fd.fd);
      handle_new_send(is, sysarg);

      msg_task_t task = create_send_communication_task(proc, is, arg->ret, proc->host, s->fd.proc->host);
      XBT_DEBUG("hosts: %s send to %s (size: %d)", MSG_host_get_name(proc->host), MSG_host_get_name(s->fd.proc->host),
                arg->ret);
      MSG_task_set_data_size(task, arg->ret);
      MSG_task_set_data(task, arg->data);

      send_task(s->fd.proc->host, task);

      return 1;
    }
    return 0;
  } else
    xbt_die("The socket is not registered");
  return 0;
}

static int syscall_sendmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  //  XBT_DEBUG("[%d] sendmsg_pre", pid);
  XBT_DEBUG("sendmsg_pre");
  get_args_sendmsg(proc, reg, sysarg);
  process_descriptor_t remote_proc;
  if (process_send_call(proc, sysarg, &remote_proc)) {
    ptrace_neutralize_syscall(pid);

    sendmsg_arg_t arg = &(sysarg->sendmsg);
    proc->in_syscall = 0;
    ptrace_restore_syscall(pid, SYS_sendmsg, arg->ret);

    if (strace_option)
      print_sendmsg_syscall(proc, sysarg);
    return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_sendmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] sendmsg_out", pid);
  XBT_DEBUG("sendmsg_post");
  get_args_sendmsg(proc, reg, sysarg);
  if (strace_option)
    print_sendmsg_syscall(proc, sysarg);
#ifdef address_translation
  if (reg->ret > 0) {
    process_descriptor_t remote_proc;
    if (process_send_call(proc, sysarg, &remote_proc)) {
      return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  //  XBT_DEBUG("[%d] sendto_pre", pid);
  XBT_DEBUG("sendto_pre");
  get_args_sendto(proc, reg, sysarg);
  process_descriptor_t remote_proc;
  if (process_send_call(proc, sysarg, &remote_proc)) {
    ptrace_neutralize_syscall(pid);

    sendto_arg_t arg = &(sysarg->sendto);
    proc->in_syscall = 0;
    ptrace_restore_syscall(pid, SYS_sendto, arg->ret);

    if (strace_option)
      print_sendto_syscall(proc, sysarg);
    return PROCESS_TASK_FOUND;
  }
#else
  if (socket_registered(proc, reg->arg1) != -1) {
    if (socket_network(proc, reg->arg1))
      sys_translate_sendto_in(proc, sysarg);
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] sendto_out", pid);
  XBT_DEBUG("sendto_post");
  get_args_sendto(proc, reg, sysarg);
  if (strace_option)
    print_sendto_syscall(proc, sysarg);
#ifdef address_translation
  if (socket_registered(proc, reg->arg1) != -1) {
    if (socket_network(proc, reg->arg1)) {
      sys_translate_sendto_out(proc, sysarg);
    }
  }
  if ((int) reg->ret > 0) {
    process_descriptor_t remote_proc;
    if (process_send_call(proc, sysarg, &remote_proc))
      return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_write_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  XBT_DEBUG(" write_pre");
  get_args_write(proc, reg, sysarg);

#ifndef address_translation
  // XBT_DEBUG("[%d] write_in", pid);
  if (socket_registered(proc, sysarg->write.fd) != -1) {
    process_descriptor_t remote_proc;
    if (process_send_call(proc, sysarg, &remote_proc)) {
      ptrace_neutralize_syscall(proc->pid);

      write_arg_t arg = &(sysarg->write);
      ptrace_restore_syscall(proc->pid, SYS_write, arg->ret);
      if (strace_option)
        print_write_syscall(proc, sysarg);
      proc->in_syscall = 0;
      return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_write_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("write_post");
  //    XBT_DEBUG("[%d] write_out", pid);
  get_args_write(proc, reg, sysarg);

  write_arg_t arg = &(sysarg->write);
  fd_descriptor_t *file_desc = proc->fd_list[arg->fd];
  file_desc->ref_nb++;
  if (file_desc != NULL && file_desc->type == FD_PIPE) {
    if (strace_option)
      print_write_syscall(proc, sysarg);
    pipe_t *pipe = file_desc->pipe;
    if (pipe == NULL)
      THROW_IMPOSSIBLE;

    pipe_end_t end_in = NULL;
    xbt_dynar_get_cpy(pipe->read_end, 0, &end_in);

    char buff[256];
    sprintf(buff, "%d", end_in->fd);
    msg_host_t receiver = end_in->proc->host;

    XBT_WARN("host %s trying to send to %s in pipe %d (size: %d). Buff = %s", MSG_host_get_name(proc->host),
             MSG_host_get_name(receiver), end_in->fd, arg->ret, buff);

    double amount = arg->ret;
    msg_task_t task = MSG_task_create(buff, 0, amount, arg->data);
    XBT_WARN("hosts: %s send to %s in pipe %d (size: %d)", MSG_host_get_name(proc->host), MSG_host_get_name(receiver),
             end_in->fd, arg->ret);
    MSG_task_send(task, buff);
  } else if (strace_option)
    print_write_syscall(proc, sysarg);

  file_desc->ref_nb--;
  file_desc = NULL;

#ifdef address_translation
  if ((int) reg->ret > 0) {
    if (socket_registered(proc, sysarg->write.fd) != -1) {
      process_descriptor_t remote_proc;
      if (process_send_call(proc, sysarg, &remote_proc))
        return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}


static void process_recvmsg_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_recvmsg_out_call");
  sys_build_recvmsg(proc, &(proc->sysarg));
  // process_reset_state(proc);
}

// TODO: le pattern est le même pour recvmsg_pre, recvfrom_pre, read_pre, faire une fonction
static void syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  //  XBT_DEBUG("[%d] recvmsg_in", pid);
  XBT_DEBUG("recvmsg_pre");
  get_args_recvmsg(proc, reg, sysarg);

  if (reg->ret > 0) {
    recvmsg_arg_t arg = &(sysarg->recvmsg);
    fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
    file_desc->ref_nb++;
    XBT_DEBUG("syscall_recvmsg_pre fd = %d", file_desc->fd);

    if (socket_registered(proc, arg->sockfd) != -1) {
      if (!socket_netlink(proc, arg->sockfd)) {
        const char *mailbox;
        if (MSG_process_self() == file_desc->stream->client)
          mailbox = file_desc->stream->to_client;
        else if (MSG_process_self() == file_desc->stream->server)
          mailbox = file_desc->stream->to_server;
        else
          THROW_IMPOSSIBLE;

        msg_task_t task = NULL;
        msg_error_t err = MSG_task_receive(&task, mailbox);

        arg->ret = (int) MSG_task_get_data_size(task);
        arg->data = MSG_task_get_data(task);

        if (err != MSG_OK) {
          struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            process_recvmsg_out_call(proc);
#else
          if (sock_status & SOCKET_CLOSED)
            sysarg->recvmsg.ret = 0;
          ptrace_neutralize_syscall(pid);
          proc->in_syscall = 0;
          process_recvmsg_out_call(proc);
        } else {
          ptrace_neutralize_syscall(pid);
          proc->in_syscall = 0;
          process_recvmsg_out_call(proc);
#endif
        }
        MSG_task_destroy(task);
      }
    }
    file_desc->ref_nb--;
    file_desc = NULL;
  }
  XBT_DEBUG("recvmsg_pre");
}

static void syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] recvmsg_out", pid);
  XBT_DEBUG("recvmsg_post");
  get_args_recvmsg(proc, reg, sysarg);
  if (strace_option)
    print_recvmsg_syscall(proc, sysarg);
}

static void process_recvfrom_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_RECVFROM_out_call");
  pid_t pid = proc->pid;
  // process_reset_state(proc);
  syscall_arg_u *sysarg = &(proc->sysarg);
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  if (strace_option)
    print_recvfrom_syscall(proc, &(proc->sysarg));
  ptrace_restore_syscall(pid, SYS_recvfrom, arg->ret);
  ptrace_poke(pid, (void *) arg->dest, arg->data, arg->ret);
  free(arg->data);
}

static void syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  // XBT_DEBUG("[%d] RECVFROM_pre", pid);
  XBT_DEBUG("RECVFROM_pre");
  get_args_recvfrom(proc, reg, sysarg);

#ifdef address_translation
  if (socket_registered(proc, reg->arg1) != -1) {
    if (socket_network(proc, reg->arg1)) {
      sys_translate_recvfrom_out(proc, sysarg);
    }
  }
#endif

  if (reg->ret > 0) {
    recvfrom_arg_t arg = &(sysarg->recvfrom);

    if (socket_registered(proc, arg->sockfd) != -1) {
      if (!socket_netlink(proc, arg->sockfd)) {
        fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
        file_desc->ref_nb++;
        XBT_DEBUG("syscall_recvfrom_pre fd = %d", file_desc->fd);

        const char *mailbox;
        if (MSG_process_self() == file_desc->stream->client)
          mailbox = file_desc->stream->to_client;
        else if (MSG_process_self() == file_desc->stream->server)
          mailbox = file_desc->stream->to_server;
        else
          THROW_IMPOSSIBLE;

        msg_task_t task = NULL;
        msg_error_t err = MSG_task_receive(&task, mailbox);

        arg->ret = (int) MSG_task_get_data_size(task);
        arg->data = MSG_task_get_data(task);

        if (err != MSG_OK) {
          struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
          int sock_status = socket_get_state(is);
#ifdef address_translation
          if (sock_status & SOCKET_CLOSED)
            process_recvfrom_out_call(proc);
#else
          if (sock_status & SOCKET_CLOSED)
            sysarg->recvfrom.ret = 0;
          ptrace_neutralize_syscall(pid);
          proc->in_syscall = 0;
          process_recvfrom_out_call(proc);
        } else {
          ptrace_neutralize_syscall(pid);
          proc->in_syscall = 0;
          process_recvfrom_out_call(proc);
#endif
        }
        MSG_task_destroy(task);
        file_desc->ref_nb--;
        file_desc = NULL;
      }
    }
  }
  XBT_DEBUG("recvfrom_pre");
}

static void syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] recvfrom_out", pid);
  XBT_DEBUG("recvfrom_post");
  get_args_recvfrom(proc, reg, sysarg);
  if (strace_option)
    print_recvfrom_syscall(proc, &(proc->sysarg));
}

static void process_read_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_read_out_call");
//  process_reset_state(proc);

  syscall_arg_u *sysarg = &(proc->sysarg);
  read_arg_t arg = &(sysarg->read);
  ptrace_restore_syscall(proc->pid, SYS_read, arg->ret);
  if (arg->ret > 0) {
    ptrace_poke(proc->pid, (void *) arg->dest, arg->data, arg->ret);
    free(arg->data);
  }
}

static void syscall_read_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  XBT_DEBUG(" read_pre");
  get_args_read(proc, reg, sysarg);
  read_arg_t arg = &(sysarg->read);
  fd_descriptor_t *file_desc = proc->fd_list[arg->fd];
  file_desc->ref_nb++;

  if (socket_registered(proc, reg->arg1) != -1) {
    XBT_DEBUG(" read socket_registered");
    const char *mailbox;
    if (MSG_process_self() == file_desc->stream->client)
      mailbox = file_desc->stream->to_client;
    else if (MSG_process_self() == file_desc->stream->server)
      mailbox = file_desc->stream->to_server;
    else
      THROW_IMPOSSIBLE;

    msg_task_t task = NULL;
    msg_error_t err = MSG_task_receive(&task, mailbox);

    arg->ret = (int) MSG_task_get_data_size(task);
    arg->data = MSG_task_get_data(task);

    if (err != MSG_OK) {
      struct infos_socket *is = get_infos_socket(proc, arg->fd);
      int sock_status = socket_get_state(is);
#ifdef address_translation
      if (sock_status & SOCKET_CLOSED)
        process_read_out_call(proc);
#else
      if (sock_status & SOCKET_CLOSED)
        sysarg->read.ret = 0;
      ptrace_neutralize_syscall(proc->pid);
      proc->in_syscall = 0;
      process_read_out_call(proc);
    } else {
      ptrace_neutralize_syscall(proc->pid);
      proc->in_syscall = 0;
      process_read_out_call(proc);
#endif
    }
    MSG_task_destroy(task);
  } else if (file_desc != NULL && file_desc->type == FD_PIPE) {
    if (strace_option)
      print_read_syscall(proc, sysarg);
    fprintf(stderr, "[%d] read pre, pipe \n", proc->pid);
    pipe_t *pipe = file_desc->pipe;
    if (pipe == NULL)
      THROW_IMPOSSIBLE;

    // print pipes
    unsigned int cpt_in;
    pipe_end_t end_in;
    xbt_dynar_t read_end = pipe->read_end;
    XBT_WARN("  Print read end of pipe: ");
    xbt_dynar_foreach(read_end, cpt_in, end_in)
        XBT_WARN("fd: %d, proc name: %s, pid = %d", end_in->fd, end_in->proc->name, end_in->proc->pid);

    unsigned int cpt_out;
    pipe_end_t end_out;
    xbt_dynar_t write_end = pipe->write_end;
    XBT_WARN("  Print write end of pipe: ");
    xbt_dynar_foreach(write_end, cpt_out, end_out)
        XBT_WARN("fd: %d, proc name: %s, pid = %d", end_out->fd, end_out->proc->name, end_out->proc->pid);

    //DEBUG
    if (reg->arg1 == 0) {
      XBT_WARN("etat des fd:");
      int i;
      fd_descriptor_t *file_desc;
      for (i = 0; i < 13; i++) {
        file_desc = proc->fd_list[i];
        if (file_desc == NULL)
          XBT_WARN("fd[%d] =  %s ", i, (char *) file_desc);
        else
          XBT_WARN("fd[%d] = %d, %s, type = %d", i, *(int *) file_desc, (char *) file_desc, file_desc->type);

      }
      file_desc = NULL;
    }
    //DEBUG

    XBT_WARN("host %s trying to receive from pipe %d", MSG_host_get_name(proc->host), arg->fd);
    char buff[256];
    sprintf(buff, "%d", arg->fd);

    msg_task_t task = NULL;
    MSG_task_receive(&task, buff);
    arg->ret = (int) MSG_task_get_data_size(task);
    arg->data = MSG_task_get_data(task);
    XBT_WARN("hosts: %s received from pipe %d (size: %d)", MSG_host_get_name(proc->host), arg->fd, arg->ret);

    MSG_task_destroy(task);
  }
  file_desc->ref_nb--;
  file_desc = NULL;
}

static void syscall_read_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("read_post");
  get_args_read(proc, reg, sysarg);
  if (strace_option)
    print_read_syscall(proc, sysarg);
}


static void process_poll_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering poll %lf \n", SD_get_clock());
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

static void syscall_poll_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;

  get_args_poll(proc, reg, sysarg);

  if (strace_option)
    print_poll_syscall(proc, sysarg);

  process_poll_call(proc);
//  ptrace_neutralize_syscall(proc->pid);
}

static void syscall_poll_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_poll(proc, reg, sysarg);
  if (strace_option)
    print_poll_syscall(proc, sysarg);
}

static void syscall_pipe_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_pipe(proc, reg, sysarg);
  pipe_arg_t arg = &(sysarg->pipe);

  if (arg->ret == 0) {
    // we create the pipe
    int p0 = *arg->filedes;
    int p1 = *(arg->filedes + 1);

    pipe_end_t in = malloc(sizeof(pipe_end_s));
    in->fd = p0;
    in->proc = proc;

    pipe_end_t out = malloc(sizeof(pipe_end_s));
    out->fd = p1;
    out->proc = proc;

    xbt_dynar_t end_in = xbt_dynar_new(sizeof(pipe_end_t), NULL);
    xbt_dynar_t end_out = xbt_dynar_new(sizeof(pipe_end_t), NULL);

    xbt_dynar_push(end_in, &in);
    xbt_dynar_push(end_out, &out);

    pipe_t *pipe = malloc(sizeof(pipe_t));
    pipe->read_end = end_in;
    pipe->write_end = end_out;

    // we create the fd
    fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->ref_nb = 0;
    file_desc->fd = p0;
    file_desc->proc = proc;
    file_desc->type = FD_PIPE;
    file_desc->pipe = pipe;
    proc->fd_list[p0] = file_desc;
    file_desc->ref_nb++;

    file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->ref_nb = 0;
    file_desc->fd = p1;
    file_desc->proc = proc;
    file_desc->type = FD_PIPE;
    file_desc->pipe = pipe;
    proc->fd_list[p1] = file_desc;
    file_desc->ref_nb++;

    if (strace_option)
      fprintf(stderr, "[%d] pipe([%d,%d]) = %d \n", proc->pid, p0, p1, arg->ret);
  } else {
    if (strace_option)
      fprintf(stderr, "[%d] pipe = %d \n", proc->pid, arg->ret);
  }
}

static int process_select_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_select_call");
  select_arg_t arg = &(proc->sysarg.select);
  int i;

  fd_set fd_rd, fd_wr, fd_ex;

  fd_rd = arg->fd_read;
  fd_wr = arg->fd_write;
  fd_ex = arg->fd_except;

  int match = 0;

  for (i = 0; i < arg->maxfd; ++i) {
    struct infos_socket *is = get_infos_socket(proc, i);
    //if i is NULL that means that i is not a socket
    if (is == NULL) {
      FD_CLR(i, &(fd_rd));
      FD_CLR(i, &(fd_wr));
      continue;
    }

    int sock_status = socket_get_state(is);
    if (FD_ISSET(i, &(fd_rd))) {
      if (sock_status & SOCKET_READ_OK || sock_status & SOCKET_CLOSED || sock_status & SOCKET_SHUT)
        ++match;
      else
        FD_CLR(i, &(fd_rd));
    }
    if (FD_ISSET(i, &(fd_wr))) {
      if (sock_status & SOCKET_WR_NBLK && !(sock_status & SOCKET_CLOSED) && !(sock_status & SOCKET_SHUT))
        ++match;
      else
        FD_CLR(i, &(fd_wr));
    }
    if (FD_ISSET(i, &(fd_ex))) {
      XBT_WARN("Select does not handle exception states for now");
    }
  }
  if (match > 0) {
    XBT_DEBUG("match for select");
    arg->fd_read = fd_rd;
    arg->fd_write = fd_wr;
    arg->fd_except = fd_ex;
    arg->ret = match;
    sys_build_select(proc, &(proc->sysarg), match);
    if (strace_option)
      print_select_syscall(proc, &(proc->sysarg));
    return match;
  }

  return 0;
}

static void syscall_select_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  THROW_UNIMPLEMENTED;

  get_args_select(proc, reg, sysarg);
  if (strace_option)
    print_select_syscall(proc, sysarg);

  XBT_WARN("Select: Timeout not handled\n");
  process_select_call(proc);
}


static void syscall_clone_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  int ret = reg->ret;
  proc->in_syscall = 0;

  if (ret > 0) {
    int pid_clone = ptrace_get_pid_clone(proc->pid);
    XBT_DEBUG("clone_post dans le père, ret = %d, pid_clone = %d", ret, pid_clone);
  } else {

    int pid_clone = ptrace_get_pid_clone(proc->pid);
    XBT_DEBUG("clone_post dans le fils, ret = %d, pid_clone = %d", ret, pid_clone);
    proc->in_syscall = 0;

    get_args_clone(proc, reg, sysarg);
    clone_arg_t arg = &(sysarg->clone);

    process_descriptor_t *clone = process_descriptor_new(proc->name, pid_clone);

    // the clone inherits the fd_list but subsequent actions on fd
    // do NOT affect the parent unless CLONE_FILES is set
    int i;
    for (i = 0; i < MAX_FD; ++i) {
      clone->fd_list[i] = proc->fd_list[i];
      if (clone->fd_list[i] != NULL) {
        clone->fd_list[i]->proc = clone;

        // deal with pipes
        if (clone->fd_list[i]->type == FD_PIPE) {
          pipe_t *pipe = clone->fd_list[i]->pipe;
          xbt_assert(pipe != NULL);

          // copy all the fds in the read end of the pipe
          unsigned int cpt_in;
          pipe_end_t end_in;
          xbt_dynar_t read_end = pipe->read_end;
          xbt_dynar_foreach(read_end, cpt_in, end_in) {
            // we have to make sure we don't add endlessly the fd from the clone
            //FIXME on ajoute encore une fois en trop
            if (end_in->proc != clone && end_in->proc->pid != clone->pid) {
              xbt_assert(end_in != NULL);
              pipe_end_t clone_end = malloc(sizeof(pipe_end_s));
              clone_end->fd = end_in->fd;
              clone_end->proc = clone;
              xbt_dynar_push(read_end, &clone_end);
            }
          }

          // copy all the fds in the write end of the pipe
          xbt_dynar_t write_end = pipe->write_end;
          unsigned int cpt_out;
          pipe_end_t end_out;
          xbt_dynar_foreach(write_end, cpt_out, end_out) {
            // we have to make sure we don't add endlessly the fd from the clone
            if (end_out->proc != clone && end_out->proc->pid != clone->pid) {
              xbt_assert(end_out != NULL);
              pipe_end_t clone_end = malloc(sizeof(pipe_end_s));
              clone_end->fd = end_out->fd;
              clone_end->proc = clone;
              xbt_dynar_push(write_end, &clone_end);
            }
          }
        }
      }
    }


    unsigned long flags = arg->clone_flags;

    if (flags & CLONE_VM)
      XBT_WARN("CLONE_VM unhandled");
    if (flags & CLONE_FS)
      XBT_WARN("CLONE_FS unhandled");
    if (flags & CLONE_FILES)
      xbt_die("CLONE_FILES unhandled");
    if (flags & CLONE_SIGHAND)
      XBT_WARN("CLONE_SIGHAND unhandled");
    if (flags & CLONE_PTRACE)
      XBT_WARN("CLONE_PTRACE ignored");
    if (flags & CLONE_VFORK)
      XBT_WARN("CLONE_VFORK unhandled");
    if (flags & CLONE_PARENT)
      XBT_WARN("CLONE_PARENT unhandled");
    if (flags & CLONE_THREAD)
      XBT_WARN("CLONE_THREAD unhandled");
    if (flags & CLONE_NEWNS)
      XBT_WARN("CLONE_NEWNS unhandled");
    if (flags & CLONE_SYSVSEM)
      XBT_WARN("CLONE_SYSVSEM unhandled");
    if (flags & CLONE_SETTLS)
      XBT_WARN("CLONE_SETTLS unhandled");
    if (flags & CLONE_UNTRACED)
      XBT_WARN("CLONE_UNTRACED unhandled");
    if (flags & CLONE_NEWUTS)
      XBT_WARN("CLONE_NEWUTS unhandled");
    if (flags & CLONE_NEWIPC)
      XBT_WARN("CLONE_NEWIPC unhandled");
    if (flags & CLONE_NEWUSER)
      XBT_WARN("CLONE_NEWUSER unhandled");
    if (flags & CLONE_NEWPID)
      XBT_WARN("CLONE_NEWPID unhandled");
    if (flags & CLONE_NEWNET)
      XBT_WARN("CLONE_NEWNET unhandled");
    if (flags & CLONE_IO)
      XBT_WARN("CLONE_IO unhandled");


    // TODO gérer ces flags
    if (flags & CLONE_PARENT_SETTID)
      XBT_WARN("CLONE_PARENT_SETTID unhandled");
    if (flags & CLONE_CHILD_CLEARTID)
      XBT_WARN("CLONE_CHILD_CLEARTID unhandled");
    if (flags & CLONE_CHILD_SETTID)
      XBT_WARN("CLONE_CHILD_SETTID unhandled");

    arg->ret = clone->pid;
    ptrace_restore_syscall(proc->pid, SYS_clone, arg->ret);

    if (strace_option)
      print_clone_syscall(proc, sysarg);

    char name[256];
    sprintf(name, "clone n°%d of %s", ++clone_number, MSG_process_get_name(MSG_process_self()));
    XBT_DEBUG("Creating %s, pid = %d", name, clone->pid);
    MSG_process_create(name, main_loop, clone, MSG_host_self());
    proc->in_syscall = 1;
  }
}

static void process_close_call(process_descriptor_t * proc, int fd);

static void syscall_execve_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  get_args_execve(proc, reg, sysarg);
  XBT_DEBUG("execve_pre");

  if (strace_option)
    print_execve_syscall_pre(proc, sysarg);

}

static void syscall_execve_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  if (proc->in_syscall == 1) {
    get_args_execve(proc, reg, sysarg);
    if (reg->ret == 0)
      proc->in_syscall = 2;
    else
      proc->in_syscall = 0;
    if (strace_option)
      print_execve_syscall_post(proc, sysarg);
    XBT_DEBUG("execve_post");
    /*if((int)(reg->ret) >= 0)
       sleep(5); */
  } else {
    proc->in_syscall = 0;
    int i;
    for (i = 0; i < MAX_FD; ++i) {
      if (proc->fd_list[i] != NULL) {
        XBT_WARN("fd n° %d; proc->fd_list[i]->flags = %d\n ", i, proc->fd_list[i]->flags);
        if (proc->fd_list[i]->flags == FD_CLOEXEC)
          XBT_WARN("FD_CLOEXEC not handled");
        //process_close_call(proc, i);
      }
    }
    XBT_DEBUG("execve retour");
  }
}

static void syscall_creat_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->ref_nb = 0;
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    proc->fd_list[(int) reg->ret] = file_desc;
    file_desc->ref_nb++;
  }
}

static void syscall_open_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->ref_nb = 0;
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    proc->fd_list[(int) reg->ret] = file_desc;
    file_desc->ref_nb++;
    // TODO print trace
    if (strace_option)
      fprintf(stderr, "[%d] open(...) = %ld\n", proc->pid, reg->ret);
  }
}

static void process_close_call(process_descriptor_t * proc, int fd)
{

  fd_descriptor_t *file_desc = proc->fd_list[fd];
  if (file_desc != NULL) {
    file_desc->ref_nb++;
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
      }
    }
    file_desc->ref_nb--;
    proc->fd_list[fd] = NULL;
  }
}

static void syscall_close_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  XBT_DEBUG("close post");
  proc->in_syscall = 0;
  int fd = reg->arg1;
  process_close_call(proc, fd);
  fprintf(stderr, "[%d] close(%d) = %ld\n", proc->pid, fd, reg->ret);
}

static void process_shutdown_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  shutdown_arg_t arg = &(sysarg->shutdown);
  struct infos_socket *is = get_infos_socket(proc, arg->fd);
  if (is == NULL) {
    arg->ret = -EBADF;
    return;
  }
  comm_shutdown(is);
}

static void syscall_shutdown_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  XBT_DEBUG(" shutdown_pre");
  shutdown_arg_t arg = &(sysarg->shutdown);
  arg->fd = reg->arg1;
  arg->how = reg->arg2;
  arg->ret = reg->ret;

  ptrace_neutralize_syscall(proc->pid);
  arg->ret = 0;
  ptrace_restore_syscall(proc->pid, SYS_shutdown, arg->ret);
  proc->in_syscall = 0;
  if (strace_option)
    print_shutdown_syscall(proc, sysarg);
#endif
}

static void syscall_shutdown_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  XBT_DEBUG(" shutdown_post");
  proc->in_syscall = 0;
  shutdown_arg_t arg = &(sysarg->shutdown);
  arg->fd = reg->arg1;
  arg->how = reg->arg2;
  arg->ret = reg->ret;

  process_shutdown_call(proc, sysarg);

  if (strace_option)
    print_shutdown_syscall(proc, sysarg);
}

static int syscall_exit_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  ptrace_detach_process(pid);
  return PROCESS_DEAD;
}


static void process_getpeername_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  getpeername_arg_t arg = &(sysarg->getpeername);
  pid_t pid = proc->pid;

  if (socket_registered(proc, arg->sockfd)) {
    if (socket_network(proc, arg->sockfd)) {
      struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
      struct sockaddr_in in;
      socklen_t size = 0;
      if (!comm_getpeername(is, &in, &size)) {
        if (size < arg->len)
          arg->len = size;
        arg->in = in;
        arg->ret = 0;
      } else
        arg->ret = -ENOTCONN;   /* ENOTCONN 107 End point not connected */

      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      ptrace_restore_syscall(pid, SYS_getpeername, arg->ret);
      if (arg->ret == 0) {
        ptrace_poke(pid, arg->len_dest, &(arg->len), sizeof(socklen_t));
        ptrace_poke(pid, arg->sockaddr_dest, &(arg->in), sizeof(struct sockaddr_in));
      }
      if (strace_option)
        print_getpeername_syscall(proc, sysarg);
    }
  }
}

static void syscall_getpeername_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  getpeername_arg_t arg = &(sysarg->getpeername);
  arg->ret = reg->ret;
  arg->sockfd = reg->arg1;
  arg->sockaddr_dest = (void *) reg->arg2;
  arg->len_dest = (void *) reg->arg3;
  ptrace_cpy(proc->pid, &(arg->len), arg->len_dest, sizeof(socklen_t), "getpeername");

  process_getpeername_call(proc, sysarg);
}

static void process_getsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  pid_t pid = proc->pid;

  arg->ret = 0;
  if (arg->optname == SO_REUSEADDR) {
    arg->optlen = sizeof(int);
    arg->optval = malloc(arg->optlen);
    *((int *) arg->optval) = socket_get_option(proc, arg->sockfd, SOCK_OPT_REUSEADDR);
  } else {
    XBT_WARN("Option non supported by Simterpose.");
    arg->optlen = 0;
    arg->optval = NULL;
  }

  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_getsockopt, arg->ret);

  if (arg->optname == SO_REUSEADDR) {
    ptrace_poke(pid, (void *) arg->dest, &(arg->optval), sizeof(arg->optlen));
    ptrace_poke(pid, (void *) arg->dest_optlen, &(arg->optlen), sizeof(socklen_t));
  }

  free(arg->optval);
  proc->in_syscall = 0;
}

static void syscall_getsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  get_args_getsockopt(proc, reg, sysarg);
  process_getsockopt_syscall(proc, sysarg);
  if (strace_option)
    print_getsockopt_syscall(proc, sysarg);
#endif
}

static void syscall_getsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_getsockopt(proc, reg, sysarg);
  if (strace_option)
    print_getsockopt_syscall(proc, sysarg);
}

static void process_setsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  setsockopt_arg_t arg = &(sysarg->setsockopt);
  pid_t pid = proc->pid;
  //TODO really handle setsockopt that currently raise a warning
  arg->ret = 0;

  if (arg->optname == SO_REUSEADDR)
    socket_set_option(proc, arg->sockfd, SOCK_OPT_REUSEADDR, *((int *) arg->optval));
  else
    XBT_WARN("Option non supported by Simterpose.");

  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_setsockopt, arg->ret);

  proc->in_syscall = 0;
}

static void syscall_setsockopt_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  get_args_setsockopt(proc, reg, sysarg);
  process_setsockopt_syscall(proc, sysarg);
  if (strace_option)
    print_setsockopt_syscall(proc, sysarg);
  free(sysarg->setsockopt.optval);
#endif
}

static void syscall_setsockopt_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_setsockopt(proc, reg, sysarg);
  if (strace_option)
    print_setsockopt_syscall(proc, sysarg);
}


static void process_fcntl_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  switch (arg->cmd) {

  case F_DUPFD:
    XBT_WARN("F_DUPFD unhandled");
    break;

  case F_DUPFD_CLOEXEC:
    XBT_WARN("F_DUPFD_CLOEXEC unhandled");
    break;

  case F_GETFD:
#ifndef address_translation
    arg->ret = proc->fd_list[arg->fd]->flags;
#endif
    break;

  case F_SETFD:
    proc->fd_list[arg->fd]->flags = arg->arg;
    return;
    break;

  case F_GETFL:
    XBT_WARN("F_GETFL unhandled");
    break;

  case F_SETFL:
    socket_set_flags(proc, arg->fd, arg->arg);
    return;
    break;

  case F_SETLK:
    XBT_WARN("F_SETLK unhandled");
    break;

  case F_SETLKW:
    XBT_WARN("F_SETLKW unhandled");
    break;

  case F_GETLK:
    XBT_WARN("F_GETLK unhandled");
    break;

  default:
    XBT_WARN("Unknown fcntl flag");
    return;
    break;
  }
#ifndef address_translation
  ptrace_neutralize_syscall(proc->pid);
  ptrace_restore_syscall(proc->pid, SYS_fcntl, arg->ret);
  proc->in_syscall = 0;
#endif
}

static void syscall_fcntl_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  get_args_fcntl(proc, reg, sysarg);
  if (strace_option)
    print_fcntl_syscall(proc, sysarg);
  process_fcntl_call(proc, sysarg);
#endif
}

static void syscall_fcntl_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_fcntl(proc, reg, sysarg);
  if (strace_option)
    print_fcntl_syscall(proc, sysarg);
#ifdef address_translation
  process_fcntl_call(proc, sysarg);
#endif
}

static void syscall_dup2_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  unsigned int oldfd = (int) reg->arg1;
  unsigned int newfd = (int) reg->arg2;

  fd_descriptor_t *file_desc = proc->fd_list[oldfd];
  file_desc->ref_nb++;
  proc->fd_list[newfd]->ref_nb--;
  process_close_call(proc, newfd);
  proc->fd_list[newfd] = file_desc;
  file_desc->ref_nb++;

  if (strace_option)
    fprintf(stderr, "[%d] dup2(%d, %d) = %ld \n", proc->pid, oldfd, newfd, reg->ret);

  if (file_desc->type == FD_PIPE) {
    pipe_t *pipe = file_desc->pipe;

    // look for the fd in the read end of the pipe
    xbt_dynar_t read_end = pipe->read_end;
    unsigned int cpt_in;
    pipe_end_t end_in;
    xbt_dynar_foreach(read_end, cpt_in, end_in) {
      if (end_in->fd == oldfd && end_in->proc == proc) {
        pipe_end_t dup_end = malloc(sizeof(pipe_end_s));
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
        pipe_end_t dup_end = malloc(sizeof(pipe_end_s));
        dup_end->fd = newfd;
        dup_end->proc = end_out->proc;
        xbt_dynar_push(write_end, &dup_end);
      }
    }
  }
}

static void process_socket_call(process_descriptor_t * proc, syscall_arg_u * arg)
{
  socket_arg_t sock = &(arg->socket);
  if (sock->ret > 0)
    register_socket(proc, sock->ret, sock->domain, sock->protocol);
}

static void syscall_socket_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;

  socket_arg_t arg = &sysarg->socket;
  arg->ret = reg->ret;
  arg->domain = (int) reg->arg1;
  arg->type = (int) reg->arg2;
  arg->protocol = (int) reg->arg3;

  if (strace_option)
    print_socket_syscall(proc, sysarg);
  process_socket_call(proc, sysarg);
}

static void process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  listen_arg_t arg = &(sysarg->listen);
  struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
  comm_t comm = comm_new(is);
  comm_set_listen(comm);

#ifndef address_translation
  pid_t pid = proc->pid;
  arg->ret = 0;
  ptrace_neutralize_syscall(pid);
  arg = &(sysarg->listen);
  ptrace_restore_syscall(pid, SYS_listen, arg->ret);
  proc->in_syscall = 0;
#endif
}

static void syscall_listen_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
#ifndef address_translation
  XBT_DEBUG("listen_in");
  get_args_listen(proc, reg, sysarg);
  process_listen_call(proc, sysarg);
  if (strace_option)
    print_listen_syscall(proc, sysarg);
#endif
}

static void syscall_listen_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("listen_out");
#ifdef address_translation
  get_args_listen(proc, reg, sysarg);
  process_listen_call(proc, sysarg);
  if (strace_option)
    print_listen_syscall(proc, sysarg);
#else
  THROW_IMPOSSIBLE;
#endif
}


static int process_bind_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  bind_arg_t arg = &(sysarg->bind);
  pid_t pid = proc->pid;
  if (socket_registered(proc, arg->sockfd)) {
    if (socket_network(proc, arg->sockfd)) {

      if (!is_port_in_use(proc->host, ntohs(arg->sai.sin_port))) {
        XBT_DEBUG("Port %d is free", ntohs(arg->sai.sin_port));
        register_port(proc->host, ntohs(arg->sai.sin_port));

        struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
        int device = 0;
        if (arg->sai.sin_addr.s_addr == INADDR_ANY)
          device = (PORT_LOCAL | PORT_REMOTE);
        else if (arg->sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
          device = PORT_LOCAL;
        else
          device = PORT_REMOTE;

        set_port_on_binding(proc->host, ntohs(arg->sai.sin_port), is, device);

        is->binded = 1;

        set_localaddr_port_socket(proc, arg->sockfd, inet_ntoa(arg->sai.sin_addr), ntohs(arg->sai.sin_port));
        arg->ret = 0;
#ifdef address_translation
        int port = ptrace_find_free_binding_port(pid);
        XBT_DEBUG("Free port found %d", port);
        proc->in_syscall = 0;
        set_real_port(proc->host, ntohs(arg->sai.sin_port), port);
        add_new_translation(port, ntohs(arg->sai.sin_port), get_ip_of_host(proc->host));
        return 0;
#endif
      } else {
        XBT_DEBUG("Port %d isn't free", ntohs(arg->sai.sin_port));
        arg->ret = -EADDRINUSE; /* EADDRINUSE 98 Address already in use */
        ptrace_neutralize_syscall(pid);
        bind_arg_t arg = &(sysarg->bind);
        ptrace_restore_syscall(pid, SYS_bind, arg->ret);
        proc->in_syscall = 0;
        return 0;
      }
#ifndef address_translation
      ptrace_neutralize_syscall(pid);
      bind_arg_t arg = &(sysarg->bind);
      ptrace_restore_syscall(pid, SYS_bind, arg->ret);
      proc->in_syscall = 0;
#endif
    }
  }
  return 0;
}

static void syscall_bind_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  get_args_bind_connect(proc, reg, sysarg);
  process_bind_call(proc, sysarg);
  if (strace_option)
    print_bind_syscall(proc, sysarg);
}

static void syscall_bind_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_bind_connect(proc, reg, sysarg);
  if (strace_option)
    print_bind_syscall(proc, sysarg);
}


static void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_accept_out_call");
  accept_arg_t arg = &(sysarg->accept);

  if (arg->ret >= 0) {
    int domain = get_domain_socket(proc, arg->sockfd);
    int protocol = get_protocol_socket(proc, arg->sockfd);

    struct infos_socket *is = register_socket(proc, arg->ret, domain, protocol);

#ifdef address_translation
    sys_translate_accept(proc, sysarg);
#endif

    comm_join_on_accept(is, proc, arg->sockfd);

    struct infos_socket *s = get_infos_socket(proc, arg->sockfd);
    register_port(proc->host, s->port_local);

    struct in_addr in;
    if (s->ip_local == 0) {
      struct infos_socket *temp = is->comm->info[0].socket;

      if (temp->ip_local == inet_addr("127.0.0.1"))
        in.s_addr = inet_addr("127.0.0.1");
      else
        in.s_addr = get_ip_of_host(proc->host);
    } else
      in.s_addr = s->ip_local;

    set_localaddr_port_socket(proc, arg->ret, inet_ntoa(in), s->port_local);

    fd_descriptor_t *file_desc_is = (fd_descriptor_t *) is;
    fd_descriptor_t *file_desc_s = (fd_descriptor_t *) s;
    // we need to give the stream to the new socket
    file_desc_is->stream = file_desc_s->stream;
  }
}

static void process_accept_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_accept_in_call");
  accept_arg_t arg = &(sysarg->accept);
  fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
  file_desc->ref_nb++;
  XBT_DEBUG("process_accept_in_call fd = %d", file_desc->fd);

  // We create the stream object for semaphores
  XBT_INFO("stream initialization by accept syscall");
  stream_t *stream = malloc(sizeof(stream_t));
  stream->sem_client = MSG_sem_init(0);
  stream->sem_server = MSG_sem_init(0);
  stream->server = MSG_process_self();
  stream->to_server = MSG_host_get_name(MSG_host_self());

  file_desc->stream = stream;
  XBT_DEBUG(" ----> S -> accept_in j'essaie de prendre server");
  MSG_sem_acquire(file_desc->stream->sem_server);
  XBT_DEBUG(" ----> S -> accept_in j'ai pris serveur je relâche client");
  MSG_sem_release(file_desc->stream->sem_client);
  XBT_DEBUG(" ----> S -> accept_in j'ai relâché client");

  //We try to find here if there's a connection to accept
  if (comm_has_connect_waiting(get_infos_socket(proc, arg->sockfd))) {
    struct sockaddr_in in;

#ifdef address_translation
    process_descriptor_t *conn_proc = comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);
    arg->sai = in;
    ptrace_resume_process(conn_proc->pid);
#else
    comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);
    arg->sai = in;
#endif

#ifndef address_translation
    pid_t pid = proc->pid;
    //Now we rebuild the syscall.
    int new_fd = ptrace_record_socket(pid);

    arg->ret = new_fd;
    ptrace_neutralize_syscall(pid);
    proc->in_syscall = 0;

    accept_arg_t arg = &(sysarg->accept);
    ptrace_restore_syscall(pid, SYS_accept, arg->ret);

    ptrace_poke(pid, arg->addr_dest, &(arg->sai), sizeof(struct sockaddr_in));

    process_accept_out_call(proc, sysarg);

    if (strace_option)
      print_accept_syscall(proc, sysarg);

    XBT_DEBUG
        (" ----> S -> accept_in (full_mediation): j'ai fini mon accept_out, avant de continuer j'essaie de prendre SERVER (2e episode)");
    MSG_sem_acquire(file_desc->stream->sem_server);
    XBT_DEBUG(" ----> S -> accept_in: SERVER pris! (2e episode)");
#endif
  }
  file_desc->ref_nb--;
  file_desc = NULL;
}

static void syscall_accept_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  XBT_DEBUG("syscall_accept_pre");
  proc->in_syscall = 1;
  get_args_accept(proc, reg, sysarg);

  process_accept_in_call(proc, sysarg);
}

static void syscall_accept_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_accept(proc, reg, sysarg);
#ifdef address_translation
  process_accept_out_call(proc, sysarg);
#endif

  if (strace_option)
    print_accept_syscall(proc, sysarg);

  // Never called by full mediation
  get_args_accept(proc, reg, sysarg);
  accept_arg_t arg = &(sysarg->accept);
  fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
  file_desc->ref_nb++;


  XBT_DEBUG(" ----> S -> accept_post (2e etape address translation?) je prends serveur");
  MSG_sem_acquire(file_desc->stream->sem_server);

  file_desc->ref_nb--;
  file_desc = NULL;
}


static int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  XBT_DEBUG("CONNEXION: process_connect_in_call");
  pid_t pid = proc->pid;
  int domain = get_domain_socket(proc, arg->sockfd);

  if (domain == 2)              //PF_INET
  {
    struct sockaddr_in *sai = &(arg->sai);

    msg_host_t host;
    int device;
    struct in_addr in;

    if (sai->sin_addr.s_addr == inet_addr("127.0.0.1")) {
      in.s_addr = inet_addr("127.0.0.1");
      device = PORT_LOCAL;
      host = proc->host;
    } else {
      in.s_addr = get_ip_of_host(proc->host);
      device = PORT_REMOTE;
      host = get_host_by_ip(sai->sin_addr.s_addr);
      if (host == NULL) {
        arg->ret = -ECONNREFUSED;       /* ECONNREFUSED       111 Connection refused */
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        connect_arg_t arg = &(sysarg->connect);
        ptrace_restore_syscall(pid, SYS_connect, arg->ret);
        return 0;
      }
    }

    //We ask for a connection on the socket
    process_descriptor_t *acc_proc = comm_ask_connect(host, ntohs(sai->sin_port), proc, arg->sockfd, device);

    //if the processus waiting for connection, we add it to schedule list
    if (acc_proc) {
      //Now attribute ip and port to the socket.
      int port = get_random_port(proc->host);

      XBT_DEBUG("New socket %s:%d", inet_ntoa(in), port);
      set_localaddr_port_socket(proc, arg->sockfd, inet_ntoa(in), port);
      register_port(proc->host, port);
      XBT_DEBUG("Free port found on host %s (%s:%d)", MSG_host_get_name(proc->host), inet_ntoa(in), port);
    } else {
      XBT_DEBUG("No peer found");
      arg->ret = -ECONNREFUSED; /* ECONNREFUSED 111 Connection refused */
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      connect_arg_t arg = &(sysarg->connect);
      ptrace_restore_syscall(pid, SYS_connect, arg->ret);
      return 0;
    }
#ifndef address_translation
    //Now we try to see if the socket is blocking of not
    int flags = socket_get_flags(proc, arg->sockfd);
    if (flags & O_NONBLOCK)
      arg->ret = -EINPROGRESS;  /* EINPROGRESS  115      Operation now in progress */
    else
      arg->ret = 0;

    ptrace_neutralize_syscall(pid);
    connect_arg_t arg = &(sysarg->connect);
    ptrace_restore_syscall(pid, SYS_connect, arg->ret);

    //now mark the process as waiting for conn

    if (flags & O_NONBLOCK)
      return 0;

    return 1;
#else
    XBT_DEBUG("connect_in address translation");
    sys_translate_connect_in(proc, sysarg);
    int flags = socket_get_flags(proc, arg->sockfd);
    if (flags & O_NONBLOCK)
      return 0;

    return 1;
#endif
  } else
    return 0;
}

static void process_connect_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_connect_out_call");
#ifdef address_translation
  connect_arg_t arg = &(sysarg->connect);

  int domain = get_domain_socket(proc, arg->sockfd);
  if (domain == 2 && arg->ret >= 0) {
    struct infos_socket *is = get_infos_socket(proc, arg->sockfd);

    sys_translate_connect_out(proc, sysarg);
    int port = socket_get_local_port(proc, arg->sockfd);
    set_real_port(proc->host, is->port_local, ntohs(port));
    add_new_translation(ntohs(port), is->port_local, get_ip_of_host(proc->host));
  }
#endif
}

static int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 1;
  XBT_DEBUG("syscall_connect_pre");
  get_args_bind_connect(proc, reg, sysarg);
  if (process_connect_in_call(proc, sysarg)) {
    connect_arg_t arg = &(sysarg->connect);

    struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
    struct infos_socket *s = comm_get_peer(is);
    fd_descriptor_t *file_desc = (fd_descriptor_t *) is;
    fd_descriptor_t *file_desc_remote = (fd_descriptor_t *) s;

    // We copy the stream to have it in both sides
    file_desc->stream = file_desc_remote->stream;
    file_desc->stream->client = MSG_process_self();
    file_desc->stream->to_client = MSG_host_get_name(MSG_host_self());

    XBT_DEBUG(" ----> S -> connect_pre je relâche serveur");
    MSG_sem_release(file_desc->stream->sem_server);
    XBT_DEBUG(" ----> S -> connect_pre j'ai relâché serveur je prends client");
    MSG_sem_acquire(file_desc->stream->sem_client);
    XBT_DEBUG(" ----> S -> connect_pre j'ai pris client");

    int status = 0;
    return process_handle(proc, status);
  } else {
    XBT_WARN("process_connect_in_call == 0  <--------- ");
    proc->in_syscall = 0;
  }
  return PROCESS_CONTINUE;
}

static void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("connect_post");
  get_args_bind_connect(proc, reg, sysarg);

#ifdef address_translation
  process_connect_out_call(proc, sysarg);
#endif
  if (strace_option)
    print_connect_syscall(proc, sysarg);

  connect_arg_t arg = &(sysarg->connect);
  fd_descriptor_t *file_desc = proc->fd_list[arg->sockfd];
  file_desc->ref_nb++;

  XBT_DEBUG(" ----> S -> connect_post je relâche serveur (2e?)");
  MSG_sem_release(file_desc->stream->sem_server);
  XBT_DEBUG(" ----> S -> connect_post j'ai relâché serveur");

  file_desc->ref_nb--;
  file_desc = NULL;
}

int process_handle(process_descriptor_t * proc, int status)
{
  reg_s arg;
  syscall_arg_u *sysarg = &(proc->sysarg);
  pid_t pid = proc->pid;
  XBT_DEBUG("PROCESS HANDLE MSG");
  while (1) {
    ptrace_get_register(pid, &arg);
    int ret;
    XBT_DEBUG("found syscall: [%d] %s (%ld) = %ld, in_syscall = %d", pid, syscall_list[arg.reg_orig], arg.reg_orig,
              arg.ret, proc->in_syscall);

    switch (arg.reg_orig) {
    case SYS_read:
      if (!(proc->in_syscall))
        syscall_read_pre(&arg, sysarg, proc);
      else
        syscall_read_post(&arg, sysarg, proc);
      break;

    case SYS_write:
      if (!(proc->in_syscall))
        ret = syscall_write_pre(&arg, sysarg, proc);
      else
        ret = syscall_write_post(pid, &arg, sysarg, proc);
      if (ret)
        return ret;
      break;

    case SYS_open:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_open_post(&arg, sysarg, proc);
      break;

    case SYS_close:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_close_post(&arg, sysarg, proc);
      break;

      // ignore SYS_stat, SYS_fstat, SYS_lstat

    case SYS_poll:
      if (!(proc->in_syscall))
        syscall_poll_pre(&arg, sysarg, proc);
      else
        syscall_poll_post(&arg, sysarg, proc);
      break;

      // ignore SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
      // SYS_ioctl, SYS_pread64, SYS_pwrite64 , SYS_readv, SYS_writev, SYS_access

    case SYS_pipe:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_pipe_post(&arg, sysarg, proc);
      break;

    case SYS_select:
      if (!(proc->in_syscall))
        syscall_select_pre(&arg, sysarg, proc);
      else {
        proc->in_syscall = 0;
        // THROW_IMPOSSIBLE;
      }
      break;

      // ignore SYS_sched_yield, SYS_mremap, SYS_msync, SYS_mincore, SYS_madvise, SYS_shmget, SYS_shmat, SYS_shmctl, SYS_dup

    case SYS_dup2:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_dup2_post(&arg, sysarg, proc);
      break;

      // ignore SYS_pause, SYS_nanosleep, SYS_getitimer, SYS_alarm, SYS_setitimer, SYS_getpid, SYS_sendfile

    case SYS_socket:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_socket_post(&arg, sysarg, proc);
      break;

    case SYS_connect:
      if (!(proc->in_syscall))
        syscall_connect_pre(&arg, sysarg, proc);
      else
        syscall_connect_post(&arg, sysarg, proc);
      break;

    case SYS_accept:
      if (!(proc->in_syscall))
        syscall_accept_pre(&arg, sysarg, proc);
      else
        syscall_accept_post(&arg, sysarg, proc);
      break;

    case SYS_sendto:
      if (!(proc->in_syscall))
        ret = syscall_sendto_pre(pid, &arg, sysarg, proc);
      else
        ret = syscall_sendto_post(pid, &arg, sysarg, proc);
      if (ret)
        return ret;
      break;

    case SYS_recvfrom:
      if (!(proc->in_syscall))
        syscall_recvfrom_pre(pid, &arg, sysarg, proc);
      else
        syscall_recvfrom_post(pid, &arg, sysarg, proc);
      break;

    case SYS_sendmsg:
      if (!(proc->in_syscall))
        ret = syscall_sendmsg_pre(pid, &arg, sysarg, proc);
      else
        ret = syscall_sendmsg_post(pid, &arg, sysarg, proc);
      if (ret)
        return ret;
      break;

    case SYS_recvmsg:
      if (!(proc->in_syscall))
        syscall_recvmsg_pre(pid, &arg, sysarg, proc);
      else
        syscall_recvmsg_post(pid, &arg, sysarg, proc);
      break;

    case SYS_shutdown:
      if (!(proc->in_syscall))
        syscall_shutdown_pre(&arg, sysarg, proc);
      else
        syscall_shutdown_post(&arg, sysarg, proc);
      break;

    case SYS_bind:
      if (!(proc->in_syscall))
        syscall_bind_pre(&arg, sysarg, proc);
      else
        syscall_bind_post(&arg, sysarg, proc);
      break;

    case SYS_listen:
      if (!(proc->in_syscall))
        syscall_listen_pre(&arg, sysarg, proc);
      else
        syscall_listen_post(&arg, sysarg, proc);
      break;

      // ignore SYS_getsockname

    case SYS_getpeername:
      if (!(proc->in_syscall))
        syscall_getpeername_pre(&arg, sysarg, proc);
      else
        proc->in_syscall = 0;
      break;

      // ignore SYS_socketpair

    case SYS_setsockopt:
      if (!(proc->in_syscall))
        syscall_setsockopt_pre(&arg, sysarg, proc);
      else
        syscall_setsockopt_post(&arg, sysarg, proc);
      break;

    case SYS_getsockopt:
      if (!(proc->in_syscall))
        syscall_getsockopt_pre(&arg, sysarg, proc);
      else
        syscall_getsockopt_post(&arg, sysarg, proc);
      break;

    case SYS_clone:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_clone_post(&arg, sysarg, proc);
      break;

      // ignore SYS_fork, SYS_vfork

    case SYS_execve:
      if (!(proc->in_syscall))
        syscall_execve_pre(&arg, sysarg, proc);
      else
        syscall_execve_post(&arg, sysarg, proc);
      break;


    case SYS_exit:
      if (!(proc->in_syscall)) {
        XBT_DEBUG("exit(%ld) called", arg.arg1);
        return syscall_exit_pre(pid, &arg, sysarg, proc);
      } else
        proc->in_syscall = 0;
      break;

      // ignore SYS_wait4, SYS_kill, SYS_uname, SYS_semget, SYS_semop, SYS_semctl, SYS_shmdt, SYS_msgget, SYS_msgsnd, SYS_msgrcv, SYS_msgctl

    case SYS_fcntl:
      if (!(proc->in_syscall))
        syscall_fcntl_pre(&arg, sysarg, proc);
      else
        syscall_fcntl_post(&arg, sysarg, proc);
      break;

      // ignore SYS_flock, SYS_fsync, SYS_fdatasync, SYS_truncate, SYS_ftruncate, SYS_getdents
      // ignore SYS_getcwd, SYS_chdir, SYS_fchdir, SYS_rename, SYS_mkdir, SYS_rmdir

    case SYS_creat:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        syscall_creat_post(&arg, sysarg, proc);
      break;
      // ignore SYS_link, SYS_unlink, SYS_symlink, SYS_readlink, SYS_chmod, SYS_fchmod, SYS_chown, SYS_fchown, SYS_lchown, SYS_umask

      /*  case SYS_gettimeofday:
         break; */

      // ignore SYS_getrlimit, SYS_getrusage, SYS_sysinfo, SYS_times, SYS_ptrace, SYS_getuid, SYS_syslog, SYS_getgid, SYS_setuid
      // SYS_setgid, SYS_geteuid, SYS_getegid, SYS_setpgid, SYS_getppid, SYS_getpgrp, SYS_setsid, SYS_setreuid, SYS_setregid,
      // SYS_getgroups, SYS_setgroups, SYS_setresuid, SYS_getresuid, SYS_setresgid, SYS_getresgid, SYS_getpgid, SYS_setfsuid,
      // SYS_setfsgid, SYS_getsid, SYS_capget, SYS_capset, SYS_rt_sigpending, SYS_rt_sigtimedwait, SYS_rt_sigqueueinfo, SYS_rt_sigsuspend
      // SYS_sigaltstack, SYS_utime, SYS_mknod, SYS_uselib, SYS_personality, SYS_ustat, SYS_statfs, SYS_fstatfs
      // SYS_sysfs, SYS_getpriority, SYS_setpriority, SYS_sched_setparam, SYS_sched_getparam, SYS_sched_setscheduler, SYS_sched_getscheduler
      // SYS_sched_get_priority_max, SYS_sched_get_priority_min, SYS_sched_rr_get_interval, SYS_mlock, SYS_munlock, SYS_mlockall,
      // SYS_munlockall, SYS_vhangup, SYS_modify_ldt, SYS_pivot_root, SYS_sysctl, SYS_prctl, SYS_arch_prctl, SYS_adjtimex, SYS_etrlimit,
      // SYS_chroot, SYS_sync, SYS_acct, SYS_settimeofday, SYS_mount, SYS_umount2, SYS_swapon, SYS_swapoff, SYS_reboot
      // SYS_sethostname, SYS_setdomainname, SYS_iopl, SYS_ioperm, SYS_create_module, SYS_init_module, SYS_delete_module
      // SYS_get_kernel_syms, SYS_query_module, SYS_quotactl, SYS_nfsservctl, SYS_getpmsg, SYS_putpmsg, SYS_afs_syscall, SYS_tuxcall
      // SYS_security, SYS_gettid, SYS_readahead, SYS_setxattr, SYS_setxattr, SYS_fsetxattr, SYS_getxattr, SYS_lgetxattr, SYS_fgetxattr
      // SYS_listxattr, SYS_llistxattr, SYS_flistxattr, SYS_removexattr, SYS_lremovexattr, SYS_fremovexattr, SYS_tkill

      /*case SYS_time:
         break;

         // ignore SYS_futex, SYS_sched_setaffinity, SYS_sched_getaffinity, SYS_set_thread_area, SYS_io_setup, SYS_io_destroy, SYS_io_getevents,
         // SYS_io_submit, SYS_io_cancel, SYS_get_thread_area, SYS_lookup_dcookie, SYS_epoll_create, SYS_epoll_ctl_old,
         // SYS_epoll_wait_old, SYS_remap_file_pages, SYS_getdents64, SYS_set_tid_address, SYS_restart_syscall, SYS_semtimedop,
         // SYS_fadvise64, SYS_timer_create, SYS_timer_settime, SYS_timer_gettime, SYS_timer_getoverrun, SYS_timer_delete, SYS_clock_settime

         case SYS_clock_gettime:
         break; */

      // ignore SYS_clock_getres, SYS_clock_nanosleep

    case SYS_exit_group:
      if (!(proc->in_syscall)) {
        XBT_DEBUG("exit_group(%ld) called", arg.arg1);
        return syscall_exit_pre(pid, &arg, sysarg, proc);
      } else
        proc->in_syscall = 0;
      break;

      // ignore SYS_epoll_wait, SYS_epoll_ctl, SYS_tgkill,
      // SYS_utimes, SYS_vserver, SYS_mbind, SYS_set_mempolicy, SYS_get_mempolicy, SYS_mq_open, SYS_mq_unlink, SYS_mq_timedsend,
      // SYS_mq_timedreceive, SYS_mq_notify, SYS_mq_getsetattr, SYS_kexec_load, SYS_waitid, SYS_add_key, SYS_request_key,
      // SYS_keyctl, SYS_ioprio_set, SYS_ioprio_get, SYS_inotify_init, SYS_inotify_add_watch, SYS_inotify_rm_watch,
      // SYS_migrate_pages, SYS_openat, SYS_mkdirat, SYS_mknodat, SYS_fchownat, SYS_futimesat, SYS_newfstatat, SYS_unlinkat,
      // SYS_renameat, SYS_linkat, SYS_symlinkat, SYS_readlinkat, SYS_fchmodat, SYS_faccessat, SYS_pselect6, SYS_ppoll
      // SYS_unshare, SYS_set_robust_list, SYS_get_robust_list, SYS_splice, SYS_tee, SYS_sync_file_range, SYS_vmsplice,
      // SYS_move_pages, SYS_utimensat, SYS_epoll_pwait, SYS_signalfd, SYS_timerfd_create, SYS_eventfd, SYS_allocate
      // SYS_timerfd_settime, SYS_timerfd_gettime, SYS_accept4, SYS_signalfd4, SYS_eventfd2, SYS_epoll_create1, SYS_dup3,
      // SYS_pipe2, SYS_inotify_init1, SYS_preadv, SYS_pwritev, SYS_rt_tgsigqueueinfo, SYS_perf_event_open, SYS_recvmmsg,
      // SYS_fanotify_init, SYS_fanotify_mark, SYS_prlimit64, SYS_name_to_handle_at, SYS_open_by_handle_at, SYS_clock_adjtime,
      // SYS_syncfs, SYS_sendmmsg, SYS_setns, SYS_getcpu, SYS_process_vm_readv, SYS_process_vm_writev, SYS_kcmp, SYS_finit_module

    default:
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else {
        XBT_DEBUG("Unhandled syscall: [%d] %s = %ld", pid, syscall_list[arg.reg_orig], arg.ret);
        proc->in_syscall = 0;
      }
      break;
    }

    // Step the traced process
    ptrace_resume_process(pid);
    // XBT_DEBUG("process resumed, waitpid");
    waitpid(pid, &status, 0);
  }                             // while(1)

  THROW_IMPOSSIBLE;             //There's no way to quit the loop
  return 0;
}
