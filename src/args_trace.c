/* args_trace -- Retrieve the syscall arguments from registers, and
   build new ones */

/* Copyright (c) 2010-2015. The SimGrid Team. All rights reserved.         */

/* This program is free software; you can redistribute it and/or modify it
 * under the terms of the license (GNU GPLv2) which comes with this package. */

#include <sys/uio.h>

#include <xbt/log.h>

#include "args_trace.h"
#include "sockets.h"
#include "data_utils.h"
#include "simterpose.h"
#include "sysdep.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(ARGS_TRACE, simterpose, "args trace log");

/** @brief retrieve the arguments of bind and connect syscalls */
void get_args_bind_connect(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);

  arg->ret = reg->ret;
  if (arg->ret == -EINPROGRESS) /* EINPROGRESS        115      Operation now in progress */
    arg->ret = 0;

  arg->sockfd = reg->arg[0];
  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  arg->addrlen = (socklen_t) reg->arg[2];
  const char *sysname = "bind ou connect";
  if (domain == 2)              // PF_INET
    ptrace_cpy(child, &arg->sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), sysname);
  if (domain == 1)              // PF_UNIX
    ptrace_cpy(child, &arg->sau, (void *) reg->arg[1], sizeof(struct sockaddr_in), sysname);
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(child, &arg->sau, (void *) reg->arg[1], sizeof(struct sockaddr_in), sysname);
}

/** @brief retrieve the arguments of accept syscall */
void get_args_accept(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  arg->ret = reg->ret;
  arg->sockfd = reg->arg[0];
  XBT_DEBUG("Socket for accepting %lu", reg->arg[0]);

  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  if (domain == 2)              // PF_INET
    ptrace_cpy(child, &arg->sai, (void *) reg->arg[1], sizeof(struct sockaddr_in), "accept");
  if (domain == 1)              // PF_UINX
    ptrace_cpy(child, &arg->sau, (void *) reg->arg[1], sizeof(struct sockaddr_in), "accept");
  if (domain == 16)             // PF_NETLINK
    ptrace_cpy(child, &arg->snl, (void *) reg->arg[1], sizeof(struct sockaddr_in), "accept");

  ptrace_cpy(child, &arg->addrlen, (void *) reg->arg[2], sizeof(socklen_t), "accept");

  arg->addr_dest = (void *) reg->arg[1];
  arg->len_dest = (void *) reg->arg[2];
}

/** @brief retrieve the arguments of listen syscall */
void get_args_listen(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  listen_arg_t arg = &(sysarg->listen);

  arg->sockfd = reg->arg[0];
  arg->backlog = reg->arg[1];
  arg->ret = reg->ret;
}

/** @brief retrieve the arguments of select syscall */
void get_args_select(process_descriptor_t * proc, reg_s * r, syscall_arg_u * sysarg)
{
  select_arg_t arg = &(sysarg->select);
  pid_t child = proc->pid;

  arg->fd_state = 0;
  arg->maxfd = r->arg[0];

  if (r->arg[1] != 0) {
    ptrace_cpy(child, &arg->fd_read, (void *) r->arg[1], sizeof(fd_set), "select");
    arg->fd_state = arg->fd_state | SELECT_FDRD_SET;
  } else
    FD_ZERO(&arg->fd_read);

  if (r->arg[2] != 0) {
    ptrace_cpy(child, &arg->fd_write, (void *) r->arg[2], sizeof(fd_set), "select");
    arg->fd_state = arg->fd_state | SELECT_FDWR_SET;
  } else
    FD_ZERO(&arg->fd_write);

  if (r->arg[3] != 0) {
    ptrace_cpy(child, &arg->fd_except, (void *) r->arg[3], sizeof(fd_set), "select");
    arg->fd_state = arg->fd_state | SELECT_FDEX_SET;
  } else
    FD_ZERO(&arg->fd_except);

  if (r->arg[4] != 0) {
    struct timeval t;
    ptrace_cpy(child, &t, (void *) r->arg[4], sizeof(struct timeval), "select");
    arg->timeout = t.tv_sec + 0.000001 * t.tv_usec;
  } else
    arg->timeout = -1;

  arg->ret = r->ret;
}

/** @brief retrieve the arguments of setsockopt syscall */
void get_args_setsockopt(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  setsockopt_arg_t arg = &(sysarg->setsockopt);
  arg->ret = reg->ret;
  arg->sockfd = reg->arg[0];
  arg->level = reg->arg[1];
  arg->optname = reg->arg[2];
  arg->dest = (void *) reg->arg[3];
  arg->optlen = reg->arg[4]; /* TODO unsigned long -> unsigned int weird */

#ifndef address_translation
  arg->optval = xbt_new0(char, arg->optlen);
  ptrace_cpy(proc->pid, arg->optval, (void *) arg->dest, arg->optlen, "setsockopt");
#endif
}

/** @brief retrieve the arguments of getsockopt syscall */
void get_args_getsockopt(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  arg->ret = reg->ret;
  arg->sockfd = reg->arg[0];
  arg->level = reg->arg[1];
  arg->optname = reg->arg[2];
  arg->dest = (void *) reg->arg[3];
  arg->dest_optlen = (void *) reg->arg[4];

  ptrace_cpy(proc->pid, &arg->optlen, (void *) reg->arg[4], sizeof(socklen_t), "getsockopt");
}

/** @brief retrieve the arguments of sendto syscall */
void get_args_sendto(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  pid_t pid = proc->pid;

  arg->ret = reg->ret;

  arg->sockfd = (int) reg->arg[0];
  arg->len = (int) reg->arg[2];
  arg->flags = (int) reg->arg[3];

  int domain = get_domain_socket(proc, arg->sockfd);
  if (reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(pid, &arg->sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "sendto");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(pid, &arg->sau, (void *) reg->arg[4], sizeof(struct sockaddr_in), "sendto");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(pid, &arg->snl, (void *) reg->arg[4], sizeof(struct sockaddr_in), "sendto");
  } else
    arg->is_addr = 0;

#ifndef address_translation
  arg->data = xbt_new0(char, arg->len);
  ptrace_cpy(pid, arg->data, (void *) reg->arg[1], arg->len, "sendto");
#endif

  if (reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->addrlen = (socklen_t) reg->arg[5];
  } else
    arg->addrlen = 0;
}

/** @brief retrieve the arguments of recvfrom syscall */
void get_args_recvfrom(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);

  arg->ret = reg->ret;
  arg->sockfd = reg->arg[0];
  arg->len = reg->arg[2];
  arg->flags = reg->arg[3];

  int domain = get_domain_socket(proc, arg->sockfd);
  pid_t child = proc->pid;
  if (reg->arg[4] != 0) {         // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->is_addr = 1;
    if (domain == 2)            // PF_INET
      ptrace_cpy(child, &arg->sai, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 1)            // PF_UNIX
      ptrace_cpy(child, &arg->sau, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
    if (domain == 16)           // PF_NETLINK
      ptrace_cpy(child, &arg->snl, (void *) reg->arg[4], sizeof(struct sockaddr_in), "recvfrom");
  } else
    arg->is_addr = 0;

  arg->dest = (void *) reg->arg[1];

  socklen_t len = 0;
  if (reg->arg[4] != 0) {         // syscall "recv" doesn't exist on x86_64, it's recvfrom with struct sockaddr=NULL and addrlen=0
    ptrace_cpy(child, &len, (void *) reg->arg[5], sizeof(socklen_t), "recvfrom");
  }
  arg->addrlen = len;
}

/** @brief retrieve the arguments of recvmsg syscall */
void get_args_recvmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  recvmsg_arg_t arg = &(sysarg->recvmsg);
  pid_t pid = proc->pid;

  arg->sockfd = reg->arg[0];
  arg->flags = reg->arg[2];
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg[1], sizeof(struct msghdr), "recvmsg");

  arg->len = 0;
  int i;
  for (i = 0; i < arg->msg.msg_iovlen; ++i) {
    struct iovec temp;
    ptrace_cpy(pid, &temp, arg->msg.msg_iov + i * sizeof(struct iovec), sizeof(struct iovec), "recvmsg");
    arg->len += temp.iov_len;
  }
}

/** @brief retrieve the arguments of sendmsg syscall */
void get_args_sendmsg(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  sendmsg_arg_t arg = &(sysarg->sendmsg);
  pid_t pid = proc->pid;

  arg->sockfd = reg->arg[0];
  arg->flags = reg->arg[2];
  arg->ret = reg->ret;
  ptrace_cpy(pid, &arg->msg, (void *) reg->arg[1], sizeof(struct msghdr), "sendmsg");
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

/** @brief retrieve the arguments of poll syscall */
void get_args_poll(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  poll_arg_t arg = &(sysarg->poll);
  pid_t child = proc->pid;

  arg->ret = reg->ret;

  void *src = (void *) reg->arg[0];
  arg->nbfd = reg->arg[1];
  arg->timeout = reg->arg[2] / 1000.;     //the timeout is in millisecond

  if (src != 0) {
    arg->fd_list = xbt_new0(struct pollfd, arg->nbfd);
    ptrace_cpy(child, arg->fd_list, src, arg->nbfd * sizeof(struct pollfd), "poll");

  } else
    arg->fd_list = NULL;
}

/** @brief retrieve the arguments of pipe syscall */
void get_args_pipe(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  pipe_arg_t arg = &(sysarg->pipe);
  arg->ret = reg->ret;
  arg->filedes = xbt_new0(int, 2);
  ptrace_cpy(proc->pid, arg->filedes, (void *) reg->arg[0], 2 * sizeof(int), "pipe");
}

/** @brief retrieve the arguments of fcntl syscall */
void get_args_fcntl(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  arg->fd = reg->arg[0];
  arg->cmd = reg->arg[1];
 
  if ((arg->cmd == F_DUPFD) || (arg->cmd == F_DUPFD_CLOEXEC)
      || (arg->cmd == F_SETFD) || (arg->cmd == F_SETFL)
      || (arg->cmd == F_SETOWN))
    arg->arg.cmd_arg = (int) reg->arg[2];

#ifdef __USE_GNU
  if ((arg->cmd == F_SETSIG) || (arg->cmd == F_SETLEASE)
      || (arg->cmd == F_NOTIFY)
      || (arg->cmd == F_SETPIPE_SZ))
    arg->arg.cmd_arg = reg->arg[2];
  if ((arg->cmd == F_GETOWN_EX) || (arg->cmd == F_SETOWN_EX))
    arg->arg.owner = (struct f_owner_ex *) reg->arg[2];
#endif

  if ((arg->cmd == F_GETLK) || (arg->cmd == F_SETLK) || (arg->cmd == F_SETLKW))
    arg->arg.lock = (struct flock *) reg->arg[2];
  
  arg->ret = (int) reg->ret;
}

/** @brief retrieve the arguments of open syscall */
void get_args_open(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  open_arg_t arg = &(sysarg->open);
  arg->ret = reg->ret;
  arg->ptr_filename = reg->arg[0];
  arg->flags = reg->arg[1];
  arg->mode = reg->arg[2]; 
  
  XBT_INFO("on get args open %d\n", proc->pid);
  XBT_INFO("Valeur de retrour on open %lu on reg %lu \n", arg->ret, reg->ret);
  XBT_INFO("Valeur de ptr on open %lu on reg %lu \n", arg->ptr_filename, reg->arg[0]);
  XBT_INFO("Valeur de flags on open %lu on reg %lu \n", arg->flags, reg->arg[1]);
  XBT_INFO("Valeur de mode on open %lu on reg %lu \n", arg->mode, reg->arg[2]);
}

/** @brief retrieve the arguments of read syscall */
void get_args_read(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  read_arg_t arg = &(sysarg->read);
  arg->fd = reg->arg[0];
#ifndef address_translation
  arg->dest = (void *) reg->arg[1];
#endif
  arg->ret = reg->ret;
  arg->count = reg->arg[2];
}

/** @brief retrieve the arguments of write syscall */
void get_args_write(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  write_arg_t arg = &(sysarg->read);
  arg->fd = reg->arg[0];
  arg->dest = (void *) reg->arg[1];
  arg->ret = reg->ret;
  arg->count = reg->arg[2];
#ifndef address_translation
  pid_t pid = proc->pid;
  if (socket_registered(proc, arg->fd)) {
    if (socket_network(proc, arg->fd)) {
      arg->data = xbt_new0(char, arg->count);
      ptrace_cpy(pid, arg->data, (void *) reg->arg[1], arg->count, "write");
    }
  }
#endif
}

/** @brief retrieve the arguments of clone syscall */
void get_args_clone(process_descriptor_t * proc, reg_s * reg, syscall_arg_u * sysarg)
{
  clone_arg_t arg = &(sysarg->clone);
  arg->ret = reg->ret;
  arg->clone_flags = reg->arg[0];
  arg->newsp = reg->arg[1];
  arg->parent_tid = (void *) reg->arg[2];
  arg->child_tid = (void *) reg->arg[3];
}

/** @brief put the arguments we want in the registers of select syscall */
void sys_build_select(process_descriptor_t * proc, syscall_arg_u * sysarg, int match)
{
  //TODO use unified union syscall_arg_u
  pid_t pid = proc->pid;
  ptrace_restore_syscall(pid, SYS_select, match);
  reg_s r;
  ptrace_get_register(pid, &r);

  select_arg_t arg = &(sysarg->select);

  if (arg->fd_state & SELECT_FDRD_SET) {
    ptrace_poke(pid, (void *) r.arg[1], &(arg->fd_read), sizeof(fd_set));
  }
  if (arg->fd_state & SELECT_FDWR_SET) {
    ptrace_poke(pid, (void *) r.arg[2], &(arg->fd_write), sizeof(fd_set));
  }
  if (arg->fd_state & SELECT_FDEX_SET) {
    ptrace_poke(pid, (void *) r.arg[3], &(arg->fd_except), sizeof(fd_set));
  }
}

/** @brief put the message received in the registers of recvmsg syscall */
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

/** @brief put the arguments we want in the registers of poll syscall */
void sys_build_poll(process_descriptor_t * proc, syscall_arg_u * sysarg, int match)
{
  pid_t pid = proc->pid;
  ptrace_restore_syscall(pid, SYS_poll, match);
  reg_s r;
  ptrace_get_register(pid, &r);

  poll_arg_t arg = &(sysarg->poll);
  arg->ret = match;

  if (r.arg[0] != 0) {
    ptrace_poke(pid, (void *) r.arg[0], arg->fd_list, sizeof(struct pollfd) * arg->nbfd);
  }
}


/** @brief translate the port and address of the exiting accept syscall
 *
 * We take the arguments in the registers, which correspond to the
 * real local address and port we obtained. We translate them into
 * global simulated ones and put the result back in the registers, so
 * that the application gets wronged.
 */
void sys_translate_accept_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
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

  ptrace_poke(pid, (void *) reg.arg[1], &(arg->sai), sizeof(struct sockaddr_in));
}

/** @brief translate the port and address of the entering connect syscall
 *
 * We take the arguments in the registers, which correspond to global
 * simulated address and port. We translate them to real local ones,
 * and put the result back in the registers to actually get the
 * connect syscall performed by the kernel.
 */
void sys_translate_connect_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  arg->sai.sin_port = htons(get_real_port(proc, arg->sai.sin_addr.s_addr, ntohs(arg->sai.sin_port)));
  arg->sai.sin_addr.s_addr = inet_addr("127.0.0.1");
  XBT_DEBUG("Try to connect on 127.0.0.1:%d", arg->sai.sin_port);
  ptrace_poke(pid, (void *) reg.arg[1], &(arg->sai), sizeof(struct sockaddr_in));
}

/** @brief translate the port and address of the exiting connect syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we established the connection on. We translate
 * them into global simulated ones and put the result back in the registers,
 * so that the application gets wronged.
 */
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
  ptrace_poke(pid, (void *) reg.arg[1], &(arg->sai), sizeof(struct sockaddr_in));
}

/** @brief translate the port and address of the entering sendto syscall
 *
 * We take the arguments in the registers, which correspond to the global
 * simulated address and port the application wants to send the message to.
 * We translate them to real local ones and put the result back in the
 * registers to actually get the sendto syscall performed by the kernel.
 */
void sys_translate_sendto_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg[4] == 0)
    return;

  struct in_addr in = { arg->sai.sin_addr.s_addr };
  XBT_DEBUG("Translate address %s:%d", inet_ntoa(in), ntohs(arg->sai.sin_port));

  struct sockaddr_in temp = arg->sai;
  int port = get_real_port(proc, temp.sin_addr.s_addr, ntohs(temp.sin_port));
  temp.sin_addr.s_addr = inet_addr("127.0.0.1");
  temp.sin_port = htons(port);
  ptrace_poke(pid, (void *) reg.arg[4], &temp, sizeof(struct sockaddr_in));
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

/** @brief translate the port and address of the exiting sendto syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we sent the message to. We translate them into global
 * simulated ones and put the result back in the registers, so that the
 * application gets wronged.
 */
void sys_translate_sendto_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg[4] == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(arg->sai.sin_port));
  arg->sai.sin_port = htons(td->port_num);
  arg->sai.sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg.arg[4], &(arg->sai), sizeof(struct sockaddr_in));
}

/** @brief translate the port and address of the entering recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the global
 * simulated address and port the application wants to receive the message
 * from. We translate them to real local ones and put the result back in the
 * registers to actually get the recvfrom syscall performed by the kernel.
 */
void sys_translate_recvfrom_in(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg[4] == 0)
    return;

  struct sockaddr_in temp = arg->sai;
  int port = get_real_port(proc, temp.sin_addr.s_addr, ntohs(temp.sin_port));
  temp.sin_addr.s_addr = inet_addr("127.0.0.1");
  temp.sin_port = htons(port);
  ptrace_poke(pid, (void *) reg.arg[4], &temp, sizeof(struct sockaddr_in));
  arg->sai = temp;
  XBT_DEBUG("Using 127.0.0.1:%d", port);
}

/** @brief translate the port and address of the exiting recvfrom syscall
 *
 * We take the arguments in the registers, which correspond to the real
 * local address and port we received the message from. We translate them
 * into global simulated ones and put the result back in the registers, so
 * that the application gets wronged.
 */
void sys_translate_recvfrom_out(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  pid_t pid = proc->pid;

  reg_s reg;
  ptrace_get_register(pid, &reg);

  if (reg.arg[4] == 0)
    return;

  translate_desc_t *td = get_translation(ntohs(arg->sai.sin_port));
  arg->sai.sin_port = htons(td->port_num);
  arg->sai.sin_addr.s_addr = td->ip;
  ptrace_poke(pid, (void *) reg.arg[4], &(arg->sai), sizeof(struct sockaddr_in));
}
