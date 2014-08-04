/* args_trace -- functions to retrieve syscall arguments from registers, and to build new ones   */

/* Copyright (c) 2010-2014. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPL) which comes with this package. */

#include "args_trace.h"
#include "sockets.h"
#include "data_utils.h"
#include "simterpose.h"
#include "sysdep.h"
#include "xbt/log.h"
#include <sys/uio.h>

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(ARGS_TRACE, simterpose, "args trace log");

void get_args_bind_connect(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);

  arg->ret = (int) reg->ret;
  if (arg->ret == -EINPROGRESS) /* EINPROGRESS        115      Operation now in progress */
    arg->ret = 0;

  arg->sockfd = (int) reg->arg1;
  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  arg->addrlen = (socklen_t) reg->arg3;
  const char *sysname = "bind ou connect";
  if (domain == 2)              // PF_INET
    ptrace_cpy(child, &arg->sai, (void *) reg->arg2, sizeof(struct sockaddr_in), sysname);
  if (domain == 1)              // PF_UNIX
    ptrace_cpy(child, &arg->sau, (void *) reg->arg2, sizeof(struct sockaddr_in), sysname);
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(child, &arg->sau, (void *) reg->arg2, sizeof(struct sockaddr_in), sysname);
}

void get_args_accept(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  arg->ret = reg->ret;
  arg->sockfd = (int) reg->arg1;
  XBT_DEBUG("Socket for accepting %lu", reg->arg1);

  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  if (domain == 2)              // PF_INET
    ptrace_cpy(child, &arg->sai, (void *) reg->arg2, sizeof(struct sockaddr_in), "accept");
  if (domain == 1)              // PF_UINX
    ptrace_cpy(child, &arg->sau, (void *) reg->arg2, sizeof(struct sockaddr_in), "accept");
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(child, &arg->snl, (void *) reg->arg2, sizeof(struct sockaddr_in), "accept");

  ptrace_cpy(child, &arg->addrlen, (void *) reg->arg3, sizeof(socklen_t), "accept");

  arg->addr_dest = (void *) reg->arg2;
  arg->len_dest = (void *) reg->arg3;
}

void get_args_listen(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  listen_arg_t arg = &(sysarg->listen);

  arg->sockfd = (int) reg->arg1;
  arg->backlog = (int) reg->arg2;
  arg->ret = (int) reg->ret;
}

void get_args_select(process_descriptor_t * proc, reg_s * r, syscall_arg_u * sysarg)
{
  select_arg_t arg = &(sysarg->select);
  pid_t child = proc->pid;

  arg->fd_state = 0;
  arg->maxfd = (int) r->arg1;

  if (r->arg2 != 0) {
    ptrace_cpy(child, &arg->fd_read, (void *) r->arg2, sizeof(fd_set), "select");
    arg->fd_state = arg->fd_state | SELECT_FDRD_SET;
  } else
    FD_ZERO(&arg->fd_read);

  if (r->arg3 != 0) {
    ptrace_cpy(child, &arg->fd_write, (void *) r->arg3, sizeof(fd_set), "select");
    arg->fd_state = arg->fd_state | SELECT_FDWR_SET;
  } else
    FD_ZERO(&arg->fd_write);

  if (r->arg4 != 0) {
    ptrace_cpy(child, &arg->fd_except, (void *) r->arg4, sizeof(fd_set), "select");
    arg->fd_state = arg->fd_state | SELECT_FDEX_SET;
  } else
    FD_ZERO(&arg->fd_except);

  if (r->arg5 != 0) {
    struct timeval t;
    ptrace_cpy(child, &t, (void *) r->arg5, sizeof(struct timeval), "select");
    arg->timeout = t.tv_sec + 0.000001 * t.tv_usec;
  } else
    arg->timeout = -1;

  arg->ret = (int) r->ret;
}

void get_args_setsockopt(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  setsockopt_arg_t arg = &(sysarg->setsockopt);
  arg->ret = (int) reg->ret;
  arg->sockfd = (int) reg->arg1;
  arg->level = (int) reg->arg2;
  arg->optname = (int) reg->arg3;
  arg->dest = (void *) reg->arg4;
  arg->optlen = reg->arg5;

#ifndef address_translation
  arg->optval = malloc(arg->optlen);
  ptrace_cpy(proc->pid, arg->optval, (void *) arg->dest, arg->optlen, "setsockopt");
#endif
}

void get_args_getsockopt(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  arg->ret = (int) reg->ret;
  arg->sockfd = (int) reg->arg1;
  arg->level = (int) reg->arg2;
  arg->optname = (int) reg->arg3;
  arg->dest = (void *) reg->arg4;
  arg->dest_optlen = (void *) reg->arg5;

  ptrace_cpy(proc->pid, &arg->optlen, (void *) reg->arg5, sizeof(socklen_t), "getsockopt");
}

void get_args_sendto(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  pid_t pid = proc->pid;

  arg->ret = reg->ret;

  arg->sockfd = (int) reg->arg1;
  arg->len = (int) reg->arg3;
  arg->flags = (int) reg->arg4;

  int domain = get_domain_socket(proc, arg->sockfd);
  if (reg->arg5 != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(pid, &arg->sai, (void *) reg->arg5, sizeof(struct sockaddr_in), "sendto");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(pid, &arg->sau, (void *) reg->arg5, sizeof(struct sockaddr_in), "sendto");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(pid, &arg->snl, (void *) reg->arg5, sizeof(struct sockaddr_in), "sendto");
  } else
    arg->is_addr = 0;

#ifndef address_translation
  arg->data = malloc(arg->len);
  ptrace_cpy(pid, arg->data, (void *) reg->arg2, arg->len, "sendto");
#endif

  if (reg->arg5 != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->addrlen = (socklen_t) reg->arg6;
  } else
    arg->addrlen = 0;
}

void get_args_recvfrom(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);

  arg->ret = reg->ret;
  arg->sockfd = (int) reg->arg1;
  arg->len = (int) reg->arg3;
  arg->flags = (int) reg->arg4;

  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  if (reg->arg5 != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(child, &arg->sai, (void *) reg->arg5, sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(child, &arg->sau, (void *) reg->arg5, sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(child, &arg->snl, (void *) reg->arg5, sizeof(struct sockaddr_in), "recvfrom");
  } else
    arg->is_addr = 0;

  arg->dest = (void *) reg->arg2;

  socklen_t len = 0;
  if (reg->arg5 != 0) {         // syscall "recv" doesn't exist on x86_64, it's recvfrom with struct sockaddr=NULL and addrlen=0
    ptrace_cpy(child, &len, (void *) reg->arg6, sizeof(socklen_t), "recvfrom");
  }
  arg->addrlen = len;
}

void get_args_recvmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  pid_t pid = proc->pid;

  arg->sockfd = (int) reg->arg1;
  arg->flags = (int) reg->arg3;
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg2, sizeof(struct msghdr), "recvmsg");

  arg->len = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");
    arg->len += temp.iov_len;
  }
}

void get_args_sendmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  sendmsg_arg_t arg = &(sysarg->sendmsg);
  pid_t pid = proc->pid;

  arg->sockfd = (int) reg->arg1;
  arg->flags = (int) reg->arg3;
  arg->ret = (int) reg->ret;
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg2, sizeof(struct msghdr), "sendmsg");
#ifndef address_translation
  arg->len = 0;
  arg->data = NULL;

  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "sendmsg");
    arg->data = realloc(arg->data, arg->len + temp.iov_len);
    ptrace_cpy(pid, (char *) arg->data + arg->len, temp.iov_base, temp.iov_len, "sendmsg");
    arg->len += temp.iov_len;
  }
#endif
}

void get_args_poll(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  poll_arg_t arg = &(sysarg->poll);
  pid_t child = proc->pid;

  arg->ret = reg->ret;

  void *src = (void *) reg->arg1;
  arg->nbfd = reg->arg2;
  arg->timeout = reg->arg3 / 1000.;     //the timeout is in millisecond

  if (src != 0) {
    arg->fd_list = malloc(arg->nbfd * sizeof(struct pollfd));
    ptrace_cpy(child, arg->fd_list, src, arg->nbfd * sizeof(struct pollfd), "poll");

  } else
    arg->fd_list = NULL;
}

void get_args_pipe(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  pipe_arg_t arg = &(sysarg->pipe);
  arg->ret = reg->ret;
  arg->filedes = malloc(2 * sizeof(int));
  ptrace_cpy(proc->pid, arg->filedes, (void*) reg->arg1, 2 * sizeof(int), "pipe");
}

void get_args_fcntl(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  arg->fd = (int) reg->arg1;
  arg->cmd = (int) reg->arg2;
  //TODO make a real gestion of fcntl arg
  arg->arg = (int) reg->arg3;
  arg->ret = (int) reg->ret;
}

void get_args_read(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  read_arg_t arg = &(sysarg->read);
  arg->fd = reg->arg1;
#ifndef address_translation
  arg->dest = (void *) reg->arg2;
#endif
  arg->ret = reg->ret;
  arg->count = reg->arg3;
}

void get_args_write(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  read_arg_t arg = &(sysarg->read);
  arg->fd = reg->arg1;
  arg->dest = (void *) reg->arg2;
  arg->ret = reg->ret;
  arg->count = reg->arg3;
#ifndef address_translation
  pid_t pid = proc->pid;
  if (socket_registered(proc, arg->fd)) {
    if (socket_network(proc, arg->fd)) {
      arg->data = malloc(arg->count);
      ptrace_cpy(pid, arg->data, (void *) reg->arg2, arg->count, "write");
    }
  }
#endif
}

void get_args_clone(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
	clone_arg_t arg = &(sysarg->clone);
	arg->ret = reg->ret;
  arg->clone_flags = reg->arg1;
  arg->newsp = reg->arg2;
  arg->parent_tid = (void *) reg->arg3;
  arg->child_tid = (void *) reg->arg4;
}

void get_args_execve(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
	execve_arg_t arg = &(sysarg->execve);
	arg->ret = reg->ret;
	arg->ptr_filename = reg->arg1;
	arg->ptr_argv = reg->arg2;
}


//TODO make this function use unified union syscall_arg_u
void sys_build_select(process_descriptor_t * proc, syscall_arg_u * sysarg, int match)
{
  pid_t pid = proc->pid;
  ptrace_restore_syscall(pid, SYS_select, match);
  reg_s r;
  ptrace_get_register(pid, &r);

  select_arg_t arg = &(sysarg->select);

  if (arg->fd_state & SELECT_FDRD_SET) {
    ptrace_poke(pid, (void *) r.arg2, &(arg->fd_read), sizeof(fd_set));
  }
  if (arg->fd_state & SELECT_FDWR_SET) {
    ptrace_poke(pid, (void *) r.arg3, &(arg->fd_write), sizeof(fd_set));
  }
  if (arg->fd_state & SELECT_FDEX_SET) {
    ptrace_poke(pid, (void *) r.arg4, &(arg->fd_except), sizeof(fd_set));
  }
}

void sys_build_recvmsg(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  pid_t pid = proc->pid;
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  ptrace_restore_syscall(pid, SYS_recvmsg, arg->ret);

  int length = arg->ret;
  int global_size = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    if (length < 0)
      break;

    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");

    if (length < temp.iov_len)
      temp.iov_len = length;

    ptrace_poke(pid, arg->msg.msg_iov + i * sizeof(struct iovec), &temp, sizeof(struct iovec));

    ptrace_poke(pid, temp.iov_base, (char *) arg->data + global_size, temp.iov_len);

  }
  free(arg->data);
}

void sys_build_poll(process_descriptor_t * proc, syscall_arg_u * sysarg, int match)
{
  pid_t pid = proc->pid;
  ptrace_restore_syscall(pid, SYS_poll, match);
  reg_s r;
  ptrace_get_register(pid, &r);

  poll_arg_t arg = &(sysarg->poll);
  arg->ret = match;

  if (r.arg1 != 0) {
    ptrace_poke(pid, (void *) r.arg1, arg->fd_list, sizeof(struct pollfd) * arg->nbfd);
  }
}


void sys_translate_accept(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);
  int port = ntohs(arg->sai.sin_port);
  struct infos_socket *is = get_infos_socket(proc, arg->sockfd);

  comm_get_ip_port_accept(is, &(arg->sai));
  msg_host_t host;
  if (arg->sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
    host = proc->host;
  else
    host = get_host_by_ip(arg->sai.sin_addr.s_addr);

  set_real_port(host, ntohs(arg->sai.sin_port), port);
  add_new_translation(port, ntohs(arg->sai.sin_port), arg->sai.sin_addr.s_addr);

  ptrace_poke(pid, (void *) reg.arg2, &(arg->sai), sizeof(struct sockaddr_in));
}

void sys_translate_connect_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  arg->sai.sin_port = htons(get_real_port(proc, arg->sai.sin_addr.s_addr, ntohs(arg->sai.sin_port)));
  arg->sai.sin_addr.s_addr = inet_addr("127.0.0.1");
  XBT_DEBUG("Try to connect on 127.0.0.1:%d", arg->sai.sin_port);
  ptrace_poke(pid, (void *) reg.arg2, &(arg->sai), sizeof(struct sockaddr_in));
}

void sys_translate_connect_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  translate_desc_t *td = get_translation(ntohs(arg->sai.sin_port));
  arg->sai.sin_port = htons(td->port_num);
  arg->sai.sin_addr.s_addr = td->ip;

  XBT_DEBUG("Restore %s:%d", inet_ntoa(arg->sai.sin_addr), td->port_num);
  ptrace_poke(pid, (void *) reg.arg2, &(arg->sai), sizeof(struct sockaddr_in));
}

void sys_translate_sendto_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg5 == 0)
    return;

  struct in_addr in = { arg->sai.sin_addr.s_addr };
  XBT_DEBUG("Translate address %s:%d", inet_ntoa(in), ntohs(arg->sai.sin_port));

  struct sockaddr_in temp = arg->sai;
  int port = get_real_port(proc, temp.sin_addr.s_addr, ntohs(temp.sin_port));
  temp.sin_addr.s_addr = inet_addr("127.0.0.1");
  temp.sin_port = htons(port);
  ptrace_poke(pid, (void *) reg.arg5, &temp, sizeof(struct sockaddr_in));
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

void sys_translate_sendto_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg5 == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(arg->sai.sin_port));
  //struct in_addr in = {td->ip};
  //XBT_DEBUG("Retranslate address 127.0.0.1:%d  -> %s:%d\n", ntohs(temp.sin_port), inet_ntoa(in), td->port_num);
  arg->sai.sin_port = htons(td->port_num);
  arg->sai.sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg.arg5, &(arg->sai), sizeof(struct sockaddr_in));
}

void sys_translate_recvfrom_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg5 == 0)
    return;

  struct sockaddr_in temp = arg->sai;
  int port = get_real_port(proc, temp.sin_addr.s_addr, ntohs(temp.sin_port));
  temp.sin_addr.s_addr = inet_addr("127.0.0.1");
  temp.sin_port = htons(port);
  ptrace_poke(pid, (void *) reg.arg5, &temp, sizeof(struct sockaddr_in));
  arg->sai = temp;
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

void sys_translate_recvfrom_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg5 == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(arg->sai.sin_port));
  //struct in_addr in = {td->ip};
  //XBT_DEBUG("Retranslate address 127.0.0.1:%d  -> %s:%d\n", ntohs(temp.sin_port), inet_ntoa(in), td->port_num);
  arg->sai.sin_port = htons(td->port_num);
  arg->sai.sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg.arg5, &(arg->sai), sizeof(struct sockaddr_in));
}
