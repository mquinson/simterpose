#include "syscall_process_msg.h"
#include "syscall_data_msg.h"
#include "sysdep.h"
#include "args_trace_msg.h"
#include "data_utils_msg.h"
#include "ptrace_utils_msg.h"
#include "print_syscall_msg.h"
#include "process_descriptor_msg.h"
#include "sockets_msg.h"
#include "simterpose_msg.h"

#include "xbt.h"
#include "xbt/log.h"

#include <time.h>
#include <linux/futex.h>

#define SYSCALL_ARG1 rdi
extern int strace_option;
const char *state_names[7] =
{ "PROCESS_CONTINUE", "PROCESS_DEAD", "PROCESS_GROUP_DEAD", "PROCESS_TASK_FOUND", "PROCESS_NO_TASK_FOUND",
"PROCESS_ON_MEDIATION", "PROCESS_ON_COMPUTATION"
};

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS_MSG, simterpose, "Syscall process log");


static int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc)
{
  XBT_DEBUG("Entering process_send_call");
  send_arg_t arg = &(sysarg->send);
  if (socket_registered(proc, arg->sockfd) != -1) {
    if (!socket_netlink(proc, arg->sockfd)) {
      XBT_DEBUG("%d This is not a netlink socket", arg->sockfd);
   //   compute_computation_time(proc);   // cree la computation task
      struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
      struct infos_socket *s = comm_get_peer(is);


    	XBT_DEBUG(" ----> SEMAPHORES -> sendto: je libère recvfrom en face");
    	MSG_sem_release(s->fd.proc->sem_comm); // Fixme connexions multiples?
    	XBT_DEBUG(" ----> SEMAPHORES -> sendto: recvfrom libéré");

     	*remote_proc = *(s->fd.proc);
    	remote_proc->remote = proc; // pour les semaphores, pour qu'il sache nous débloquer TODO
    	proc->remote = s->fd.proc;

      XBT_DEBUG("%d->%d", arg->sockfd, arg->ret);
      XBT_DEBUG("Sending data(%d) on socket %d", arg->ret, s->fd.fd);
      handle_new_send(is, sysarg);

      msg_task_t task = create_send_communication_task(proc, is, arg->ret, proc->host, s->fd.proc->host);
      XBT_DEBUG("hosts: %s send to %s",  MSG_host_get_name(proc->host), MSG_host_get_name(s->fd.proc->host));
      send_task(s->fd.proc->host, task);

      is->fd.proc->on_simulation = 1;
      return 1;
    }
    return 0;
  } else
    THROW_IMPOSSIBLE;
}

static int syscall_sendmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
#ifndef address_translation
  //  XBT_DEBUG("[%d] sendmsg_in", pid);
  XBT_DEBUG("sendmsg_pre");
  get_args_sendmsg(proc, reg, sysarg);
  process_descriptor_t remote_proc;
  if (process_send_call(proc, sysarg, &remote_proc)){
    ptrace_neutralize_syscall(pid);

    syscall_arg_u *sysarg = &(proc->sysarg);
    sendmsg_arg_t arg = &(sysarg->sendmsg);
    ptrace_restore_syscall(pid, SYS_sendmsg, arg->ret);

    proc->in_syscall = 0;
    if (strace_option)
      print_sendmsg_syscall(proc, sysarg);
    return PROCESS_TASK_FOUND;
  }
#endif
  return *state;
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
	  if (process_send_call(proc, sysarg, &remote_proc)){
			XBT_DEBUG(" ----> SEMAPHORES -> sendmsg: je libère recvmsg en face");
			MSG_sem_release(remote_proc.sem_comm);
			XBT_DEBUG(" ----> SEMAPHORES -> sendmsg: recvmsg libéré");
			XBT_DEBUG(" ----> SEMAPHORES -> sendmsg: j'essaie de prendre sendmsg");
			MSG_sem_acquire(proc->sem_comm);
			XBT_DEBUG(" ----> SEMAPHORES -> sendmsg: sendmsg pris!");
			return PROCESS_TASK_FOUND;
	  }
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
  //  XBT_DEBUG("[%d] sendto_in", pid);
  XBT_DEBUG("sendto_pre");
  get_args_sendto(proc, reg, sysarg);
#ifndef address_translation
  process_descriptor_t remote_proc;
  if (process_send_call(proc, sysarg, &remote_proc)){
	  XBT_DEBUG(" ----> SEMAPHORES -> sendto: j'essaie de prendre sendto");
	MSG_sem_acquire(proc->sem_comm);
	XBT_DEBUG(" ----> SEMAPHORES -> sendto: sendto pris!");
    XBT_DEBUG("process_handle -> PROCESS_TASK_FOUND");
    ptrace_neutralize_syscall(pid);

    sendto_arg_t arg = &(sysarg->sendto);
    ptrace_restore_syscall(pid, SYS_sendto, arg->ret);
    proc->in_syscall = 0;
    if (strace_option)
      print_sendto_syscall(proc, sysarg);
    return PROCESS_TASK_FOUND;
  }
#else
  if (socket_registered(proc, reg->arg1) != -1) {
    if (socket_network(proc, reg->arg1)) {
      sys_translate_sendto_in(proc, sysarg);
    }
  }
#endif
    return *state;
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
    if (process_send_call(proc, sysarg, &remote_proc)){
    	XBT_DEBUG(" ----> SEMAPHORES -> sendto: j'essaie de prendre sendto");
    	MSG_sem_acquire(proc->sem_comm);
    	XBT_DEBUG(" ----> SEMAPHORES -> sendto: sendto pris!");
      return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}

static int process_recv_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  recv_arg_t arg = &(sysarg->recv);
  XBT_DEBUG("Entering process_RECV_call, ret %d", arg->ret);
  if (socket_registered(proc, arg->sockfd) != -1) {
    if (!socket_netlink(proc, arg->sockfd)) {
      //  compute_computation_time(proc);

      //if handle_new_receive return 1, there is a task found
      if (handle_new_receive(proc, sysarg))
        return PROCESS_TASK_FOUND;
      else {
        struct infos_socket *is = get_infos_socket(proc, arg->sockfd);
        int sock_status = socket_get_state(is);
        if (sock_status & SOCKET_CLOSED)
          return RECV_CLOSE;

        return PROCESS_NO_TASK_FOUND;
      }
    }
  } else
    THROW_IMPOSSIBLE;

  return 0;
}

static int process_recv_in_call(process_descriptor_t * proc, int fd)
{
  XBT_DEBUG("Entering process_recv_in_call");
  XBT_DEBUG("Trying to see if socket %d recv something", fd);
  if (proc->fd_list[fd] == NULL)
    return 0;

  if (!socket_network(proc, fd))
#ifndef address_translation
    return 0;
#else
    return 1;
#endif

  int status = comm_get_socket_state(get_infos_socket(proc, fd));
  XBT_DEBUG("socket status %d %d", status, status & SOCKET_READ_OK || status & SOCKET_CLOSED);

  XBT_DEBUG("Leaving process_recv_in_call");
  return (status & SOCKET_READ_OK || status & SOCKET_CLOSED || status & SOCKET_SHUT);
}

static void process_recvmsg_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_recvmsg_out_call");
  sys_build_recvmsg(proc, &(proc->sysarg));
  process_reset_state(proc);
}

static int syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
  //  XBT_DEBUG("[%d] recvmsg_in", pid);
  XBT_DEBUG("recvmsg_pre");
  get_args_recvmsg(proc, reg, sysarg);

  if (!process_recv_in_call(proc, sysarg->recvmsg.sockfd)) {
    if (strace_option)
      print_read_syscall(proc, sysarg);
#ifndef address_translation
    if (socket_registered(proc, sysarg->recvmsg.sockfd))
      if (!socket_network(proc, sysarg->recvmsg.sockfd))
        return PROCESS_CONTINUE;

    int flags = socket_get_flags(proc, reg->arg1);
    if (flags & O_NONBLOCK) {
      sysarg->recvmsg.ret = -EAGAIN;    /* EAGAIN 11 Try again */
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      process_recvmsg_out_call(proc);
    } else {
      proc->state = PROC_RECVMSG;
      proc->mediate_state = 1;
      *state = PROCESS_ON_MEDIATION;
    }
    if (strace_option)
      print_read_syscall(proc, sysarg);
  } else {
    int res = process_recv_call(proc, sysarg);
    if (res == PROCESS_TASK_FOUND) {
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      proc->state = PROC_RECVMSG;
      return PROCESS_TASK_FOUND;
    } else {
      if (res == RECV_CLOSE)
        sysarg->recvfrom.ret = 0;
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      process_recvmsg_out_call(proc);
    }
    if (strace_option)
      print_read_syscall(proc, sysarg);
#else
    int flags = socket_get_flags(proc, reg->arg1);
    if (!(flags & O_NONBLOCK)) {
      proc->state = PROC_RECVMSG;
      *state = PROCESS_ON_MEDIATION;
      proc->mediate_state = 1;
    }
#endif
    if (strace_option)
      print_read_syscall(proc, sysarg);
  }
  return *state;
}

static int syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] recvmsg_out", pid);
  XBT_DEBUG("recvmsg_post");
  get_args_recvmsg(proc, reg, sysarg);
  if (strace_option)
    print_recvmsg_syscall(proc, sysarg);
#ifdef address_translation
  if (reg->ret > 0) {
    if (process_recv_call(proc, sysarg) == PROCESS_TASK_FOUND)
      return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}

static void process_recvfrom_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_RECVFROM_out_call");
  process_reset_state(proc);
  syscall_arg_u *sysarg = &(proc->sysarg);
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  ptrace_restore_syscall(proc->pid, SYS_recvfrom, arg->ret);
  ptrace_poke(proc->pid, (void *) arg->dest, arg->data, arg->ret);
  free(arg->data);
}

static int syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
  // XBT_DEBUG("[%d] RECVFROM_pre", pid);
  XBT_DEBUG("RECVFROM_pre");
  get_args_recvfrom(proc, reg, sysarg);


#ifdef address_translation
  if (socket_registered(proc, reg->arg1) != -1) {
    if (socket_network(proc, reg->arg1)) {
      sys_translate_recvfrom_in(proc, sysarg);
    }
  }
#endif
  // XBT_DEBUG("[%d] Seeing if %d receive something", pid, (int)reg->arg1);
  XBT_DEBUG("Seeing if %d receive something", (int) reg->arg1);

	XBT_DEBUG(" ----> SEMAPHORES -> recvfrom: j'essaie de prendre recvfrom");
	MSG_sem_acquire(proc->sem_comm);
	XBT_DEBUG(" ----> SEMAPHORES -> recvfrom: recvfrom pris!");
	XBT_DEBUG(" ----> SEMAPHORES -> recvfrom: je libère sendto");
	MSG_sem_release(proc->remote->sem_comm); // FIXME: s'il y a plusieurs connexions il y a plusieurs remote
	XBT_DEBUG(" ----> SEMAPHORES -> recvfrom: sendto libéré");

  if (!process_recv_in_call(proc, sysarg->recvfrom.sockfd)) {
#ifndef address_translation
    XBT_DEBUG("recvfrom_pre, full mediation");
    int flags = socket_get_flags(proc, reg->arg1);
    if (flags & O_NONBLOCK) {
      sysarg->recvfrom.ret = -EAGAIN;   /* EAGAIN 11 Try again */
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      process_recvmsg_out_call(proc);
    } else {
      proc->state = PROC_RECVFROM;
      proc->mediate_state = 1;
      *state = PROCESS_ON_MEDIATION;
    }
  } else                        // comment on a ça?
  {
    int res = process_recv_call(proc, sysarg);
    if (res == PROCESS_TASK_FOUND) {
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      proc->state = PROC_RECVFROM;
      return PROCESS_TASK_FOUND;
    } else {
      if (res == RECV_CLOSE)
        sysarg->recvfrom.ret = 0;
      ptrace_neutralize_syscall(pid);
      proc->in_syscall = 0;
      process_recvfrom_out_call(proc);
    }
    if (strace_option)
      print_recvfrom_syscall(proc, sysarg);
#else
    XBT_DEBUG("recvfrom_pre, address translation");
    int flags = socket_get_flags(proc, reg->arg1);
    if (!(flags & O_NONBLOCK)) {
      proc->state = PROC_RECVFROM;
      *state = PROCESS_ON_MEDIATION;
      proc->mediate_state = 1;
    }
#endif
  }
  XBT_DEBUG("recvfrom_pre state = %s", state_names[*state]);
  return *state;
}

static int syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] recvfrom_out", pid);
  XBT_DEBUG("recvfrom_post");
  get_args_recvfrom(proc, reg, sysarg);
  if (strace_option)
    print_recvfrom_syscall(proc, &(proc->sysarg));
#ifdef address_translation
  if (socket_registered(proc, reg->arg1) != -1) {
    if (socket_network(proc, reg->arg1)) {
      sys_translate_recvfrom_out(proc, sysarg);
    }
  }
  if (reg->ret > 0) {
    if (process_recv_call(proc, sysarg) == PROCESS_TASK_FOUND){

  	  if (strace_option)
  	    print_recvfrom_syscall(proc, &(proc->sysarg));
    	return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}

static void process_read_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_read_out_call");
  process_reset_state(proc);

  syscall_arg_u *sysarg = &(proc->sysarg);
  read_arg_t arg = &(sysarg->read);
  ptrace_restore_syscall(proc->pid, SYS_read, arg->ret);
  if (arg->ret > 0) {
    ptrace_poke(proc->pid, (void *) arg->dest, arg->data, arg->ret);
    free(arg->data);
  }
}

static int syscall_read_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
  get_args_read(proc, reg, sysarg);
  if (socket_registered(proc, reg->arg1) != -1) {
    if (!process_recv_in_call(proc, reg->arg1)) {
#ifndef address_translation
      int flags = socket_get_flags(proc, reg->arg1);
      if (flags & O_NONBLOCK) {
        sysarg->read.ret = -EAGAIN;     /* EAGAIN 11 Try again */
        if (strace_option)
          print_read_syscall(proc, sysarg);
        ptrace_neutralize_syscall(proc->pid);
        proc->in_syscall = 0;
        process_read_out_call(proc);
      } else {
        proc->state = PROC_READ;
        proc->mediate_state = 1;
        *state = PROCESS_ON_MEDIATION;
      }
    } else {                    // on a reçu qqchose
      int res = process_recv_call(proc, sysarg);
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_read_syscall(proc, sysarg);
        ptrace_neutralize_syscall(proc->pid);
        proc->in_syscall = 0;
        proc->state = PROC_READ;
        return PROCESS_TASK_FOUND;
      } else {
        if (res == RECV_CLOSE)
          sysarg->read.ret = 0;
        if (strace_option)
          print_read_syscall(proc, sysarg);
        ptrace_neutralize_syscall(proc->pid);
        proc->in_syscall = 0;
        process_read_out_call(proc);
      }
#else
      int flags = socket_get_flags(proc, reg->arg1);
      if (!(flags & O_NONBLOCK)) {
        proc->state = PROC_READ;
        *state = PROCESS_ON_MEDIATION;
        proc->mediate_state = 1;
      }
#endif
    }
  }
  return *state;
}

static int syscall_read_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_read(proc, reg, sysarg);
  if (strace_option)
    print_read_syscall(proc, sysarg);
#ifdef address_translation
  if ((int) reg->ret > 0) {
    if (socket_registered(proc, sysarg->read.fd) != -1) {
      if (process_recv_call(proc, sysarg) == PROCESS_TASK_FOUND)
        return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_write_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
#ifndef address_translation
  // XBT_DEBUG("[%d] write_in", pid);
  XBT_DEBUG(" write_in");
  get_args_write(proc, reg, sysarg);
  if (socket_registered(proc, sysarg->write.fd) != -1) {
	  process_descriptor_t remote_proc;
	  if (process_send_call(proc, sysarg, &remote_proc)){
      ptrace_neutralize_syscall(pid);

      sendto_arg_t arg = &(sysarg->sendto);
      ptrace_restore_syscall(pid, SYS_sendto, arg->ret);
      if (strace_option)
        print_write_syscall(proc, sysarg);
      proc->in_syscall = 0;
      return PROCESS_TASK_FOUND;
    }
  }
#endif
  return *state;
}

static int syscall_write_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  //    XBT_DEBUG("[%d] write_out", pid);
  get_args_write(proc, reg, sysarg);
  if (strace_option)
    print_write_syscall(proc, sysarg);
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

static void syscall_open_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    proc->fd_list[(int) reg->ret] = file_desc;
  }
}

static void process_close_call(process_descriptor_t * proc, int fd)
{
  fd_descriptor_t *file_desc = proc->fd_list[fd];
  if (file_desc->type == FD_SOCKET)
    socket_close(proc, fd);
  else {
    free(file_desc);
    proc->fd_list[fd] = NULL;
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

static int process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
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

  return 0;
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

  }
  process_reset_state(proc);
}

//Returns 0 if nobody wait or the pid of the one who wait
static int process_accept_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_accept_in_call");
  accept_arg_t arg = &(sysarg->accept);

  //We try to find here if there's a connection to accept

 if (comm_has_connect_waiting(get_infos_socket(proc, arg->sockfd))) {
    struct sockaddr_in in;
    process_descriptor_t *conn_proc = comm_accept_connect(get_infos_socket(proc, arg->sockfd), &in);

    arg->sai = in;
    int conn_state = conn_proc->state;
    if (conn_state & PROC_CONNECT) {
      XBT_DEBUG("IF PROC CONNECT");
#ifndef address_translation
      // add_to_sched_list(conn_proc->pid); // TODO: vérifier si ça suffit
      process_reset_state(conn_proc);
#else
      ptrace_resume_process(conn_proc->pid);
      // add_to_sched_list(conn_proc->pid);
      conn_proc->state = PROC_CONNECT_DONE;
#endif
    }
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

	XBT_DEBUG(" ----> SEMAPHORES -> accept (full_mediation): j'ai fini mon accept_out, avant de continuer j'essaie de prendre accept (2e episode)");
	MSG_sem_acquire(proc->sem_conn);
	XBT_DEBUG(" ----> SEMAPHORES -> accept: accept pris! (2e episode)");
#endif

    return conn_proc->pid;
  } else {
    XBT_DEBUG("ELSE");
    proc->state = PROC_ACCEPT;
    return 0;
  }
}

static int syscall_accept_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  XBT_DEBUG("syscall_accept_pre");
  proc->in_syscall = 1;
  *state = 0;
  get_args_accept(proc, reg, sysarg);

  // TODO: trouver comment connaitre celui en face (le mettre dans les infos par celui d'en face? qui lui connait)

	XBT_DEBUG(" ----> SEMAPHORES -> accept: j'essaie de prendre accept");
	MSG_sem_acquire(proc->sem_conn);
	XBT_DEBUG(" ----> SEMAPHORES -> accept: accept pris!");
	XBT_DEBUG(" ----> SEMAPHORES -> accept: je libère connect");
	MSG_sem_release(proc->remote->sem_conn);
	XBT_DEBUG(" ----> SEMAPHORES -> accept: connect libéré");

  process_accept_in_call(proc, sysarg);
  return *state;
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
  // jamais appelé par full mediation
	XBT_DEBUG(" ----> SEMAPHORES -> accept (address_translation): j'ai fini mon accept_out, avant de continuer j'essaie de prendre accept (2e episode)");
	MSG_sem_acquire(proc->sem_conn);
	XBT_DEBUG(" ----> SEMAPHORES -> accept: accept pris! (2e episode)");
}

static int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg, process_descriptor_t * remote_proc)
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

    	*remote_proc = *acc_proc;
    	acc_proc->remote = proc; // pour les semaphores, pour qu'il sache nous débloquer TODO
    	proc->remote = acc_proc;

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

    proc->state = PROC_CONNECT;
    return 1;
#else
    XBT_DEBUG("connect_in full mediation");
    sys_translate_connect_in(proc, sysarg);
    int flags = socket_get_flags(proc, arg->sockfd);
    if (flags & O_NONBLOCK)
      return 0;

    //now mark the process as waiting for conn
    proc->state = PROC_CONNECT;
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
  process_reset_state(proc);
}

static int syscall_connect_pre(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = 0;
  XBT_DEBUG("syscall_connect_pre");
  get_args_bind_connect(proc, reg, sysarg);
  process_descriptor_t remote_proc;
  if (process_connect_in_call(proc, sysarg, &remote_proc)){
	  	// si on n'a pas process_connect_in_call alors la connexion est refusée.
		XBT_DEBUG(" ----> SEMAPHORES -> connect: je libère accept en face");
		MSG_sem_release(remote_proc.sem_conn); // remote proc trouvé non?!
		XBT_DEBUG(" ----> SEMAPHORES -> connect: accept libéré");
		XBT_DEBUG(" ----> SEMAPHORES -> connect: j'essaie de prendre connect");
		MSG_sem_acquire(proc->sem_conn);
		XBT_DEBUG(" ----> SEMAPHORES -> connect: connect pris!");

		int status = 0;
		return process_handle_msg(proc, status);
  }
  else{
	  XBT_DEBUG("process_connect_in_call == 0  <--------- ");
  }
  return *state;
}

static void syscall_connect_post(reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("connect_out");

  get_args_bind_connect(proc, reg, sysarg);
#ifdef address_translation
  process_connect_out_call(proc, sysarg);
  process_reset_state(proc);
#endif
  if (strace_option)
    print_connect_syscall(proc, sysarg);


	XBT_DEBUG(" ----> SEMAPHORES -> connect: j'ai fini mon connect out, je libère accept en face (2e episode)");
	MSG_sem_release(proc->remote->sem_conn); // remote proc trouvé non?!
	XBT_DEBUG(" ----> SEMAPHORES -> connect: accept libéré  (2e episode)");
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
      XBT_WARN("Mediation for exception states on socket are not support yet");
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

  if (proc->in_timeout == PROC_TIMEOUT_EXPIRE) {
    XBT_DEBUG("Timeout for select");

    FD_ZERO(&fd_rd);
    FD_ZERO(&fd_wr);
    FD_ZERO(&fd_ex);
    arg->ret = 0;
    arg->fd_read = fd_rd;
    arg->fd_write = fd_wr;
    arg->fd_except = fd_ex;
    sys_build_select(proc, &(proc->sysarg), 0);
    if (strace_option)
      print_select_syscall(proc, &(proc->sysarg));
    proc->in_timeout = PROC_NO_TIMEOUT;
    return 1;
  }
  return 0;
}

int process_handle_msg(process_descriptor_t * proc, int status)
{
  reg_s arg;
  syscall_arg_u *sysarg = &(proc->sysarg);
  pid_t pid = proc->pid;
  XBT_DEBUG("PROCESS HANDLE");
  while (1) {
    ptrace_get_register(pid, &arg);
    int state;
    int ret;
   // XBT_DEBUG("found syscall: [%d] %s = %ld", pid, syscall_list[arg.reg_orig], arg.ret);

    switch (arg.reg_orig) {
    case SYS_read:
      if (!(proc->in_syscall))
        ret = syscall_read_pre(&arg, sysarg, proc, &state);
      else
        ret = syscall_read_post(&arg, sysarg, proc);
      if (ret)
        return ret;
      break;

    case SYS_write:
      if (!(proc->in_syscall))
        ret = syscall_write_pre(pid, &arg, sysarg, proc, &state);
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
      else {
        proc->in_syscall = 0;
        process_close_call(proc, (int) arg.arg1);
      }
      break;

      // ignore SYS_stat, SYS_fstat, SYS_lstat

      /* case SYS_poll:
         if (!(proc->in_syscall)) {
         ret = syscall_poll_pre(pid, &arg, sysarg, proc, &state);
         if (ret)
         return ret;
         } else {
         proc->in_syscall = 0;
         THROW_IMPOSSIBLE;
         }
         break; */

      // ignore SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
      // SYS_ioctl, SYS_pread64, SYS_pwrite64 , SYS_readv, SYS_writev, SYS_access, SYS_pipe

/*  case SYS_select:
      if (!(proc->in_syscall))
        syscall_select_pre(pid, &arg, sysarg, proc, &state);
      else {
        proc->in_syscall = 0;
        THROW_IMPOSSIBLE;
      }
      break;*/

      // ignore SYS_sched_yield, SYS_mremap, SYS_msync, SYS_mincore, SYS_madvise, SYS_shmget, SYS_shmat, SYS_shmctl
      // SYS_dup, SYS_dup2, SYS_pause, SYS_nanosleep, SYS_getitimer, SYS_alarm, SYS_setitimer, SYS_getpid, SYS_sendfile

    case SYS_socket:
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
      } else
        syscall_socket_post(&arg, sysarg, proc);
      break;

    case SYS_connect:
      if (!(proc->in_syscall)) {
    	  syscall_connect_pre(&arg, sysarg, proc, &state);
        //ret = syscall_connect_pre(&arg, sysarg, proc, &state);
       // if (ret)
       //   return ret;
      } else
        syscall_connect_post(&arg, sysarg, proc);
      break;

    case SYS_accept:
      if (!(proc->in_syscall)) {
        ret = syscall_accept_pre(&arg, sysarg, proc, &state);
        if (ret)
          return ret;
      } else
        syscall_accept_post(&arg, sysarg, proc);
      break;

      case SYS_sendto:
	  if (!(proc->in_syscall))
		ret = syscall_sendto_pre(pid, &arg, sysarg, proc, &state);
	  else
		ret = syscall_sendto_post(pid, &arg, sysarg, proc);
	  if (ret)
		return ret;
	  break;

    case SYS_recvfrom:
	 if (!(proc->in_syscall))
			ret = syscall_recvfrom_pre(pid, &arg, sysarg, proc, &state);
		  else
			ret = syscall_recvfrom_post(pid, &arg, sysarg, proc);
		  if (ret)
			return ret;
      break;

  /*  case SYS_sendmsg:
      get_args_sendmsg(proc, &arg, sysarg);
      print_sendmsg_syscall(proc, sysarg);
      break;

    case SYS_recvmsg:
      get_args_recvmsg(proc, &arg, sysarg);
      print_recvmsg_syscall(proc, sysarg);
      break;
*/
      /*  case SYS_shutdown:
         break; */

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

      /*   case SYS_getpeername:
         break;
       */
      // ignore SYS_socketpair

    case SYS_setsockopt:
      get_args_setsockopt(proc, &arg, sysarg);
      print_setsockopt_syscall(proc, sysarg);
      break;

    case SYS_getsockopt:
      get_args_getsockopt(proc, &arg, sysarg);
      print_getsockopt_syscall(proc, sysarg);
      break;

      // ignore SYS_clone, SYS_fork, SYS_vfork, SYS_execve

      /*  case SYS_exit:
         break; */

      // ignore SYS_wait4, SYS_kill, SYS_uname, SYS_semget, SYS_semop, SYS_semctl, SYS_shmdt, SYS_msgget, SYS_msgsnd, SYS_msgrcv, SYS_msgctl

    case SYS_fcntl:
      get_args_fcntl(proc, &arg, sysarg);
      print_fcntl_syscall(proc, sysarg);
      break;

      // ignore SYS_flock, SYS_fsync, SYS_fdatasync, SYS_truncate, SYS_ftruncate, SYS_getdents
      // ignore SYS_getcwd, SYS_chdir, SYS_fchdir, SYS_rename, SYS_mkdir, SYS_rmdir

      /*  case SYS_creat:
         break;

         // ignore SYS_link, SYS_unlink, SYS_symlink, SYS_readlink, SYS_chmod, SYS_fchmod, SYS_chown, SYS_fchown, SYS_lchown, SYS_umask

         case SYS_gettimeofday:
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

      /* case SYS_time:
         break;

         // ignore SYS_futex, SYS_sched_setaffinity, SYS_sched_getaffinity, SYS_set_thread_area, SYS_io_setup, SYS_io_destroy, SYS_io_getevents,
         // SYS_io_submit, SYS_io_cancel, SYS_get_thread_area, SYS_lookup_dcookie, SYS_epoll_create, SYS_epoll_ctl_old,
         // SYS_epoll_wait_old, SYS_remap_file_pages, SYS_getdents64, SYS_set_tid_address, SYS_restart_syscall, SYS_semtimedop,
         // SYS_fadvise64, SYS_timer_create, SYS_timer_settime, SYS_timer_gettime, SYS_timer_getoverrun, SYS_timer_delete, SYS_clock_settime

         case SYS_clock_gettime:
         break;

         // ignore SYS_clock_getres, SYS_clock_nanosleep

         case SYS_exit_group:
         break; */

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
      XBT_DEBUG("Unhandled syscall: [%d] %s = %ld", pid, syscall_list[arg.reg_orig], arg.ret);
      if (!(proc->in_syscall))
        proc->in_syscall = 1;
      else
        proc->in_syscall = 0;
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

int process_handle_mediate(process_descriptor_t * proc)
{
  XBT_DEBUG("PROCESS HANDLE MEDIATE");
  int state = proc->state;

  xbt_assert(proc->in_syscall);
  xbt_assert(proc->mediate_state);

  if (state & PROC_RECVFROM) {
    XBT_DEBUG("mediate recvfrom_in");
    //TODO here

    if (process_recv_in_call(proc, proc->sysarg.recvfrom.sockfd)) {
#ifndef address_translation
      pid_t pid = proc->pid;
      int res = process_recv_call(proc, &(proc->sysarg));
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_recvfrom_syscall(proc, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->mediate_state = 0;
        return PROCESS_TASK_FOUND;
      } else if (res == RECV_CLOSE) {
        if (strace_option)
          print_recvfrom_syscall(proc, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;   // TODO vérifier pourquoi on passe pas mediate_state à zéro, comment on gère le cas de la socket fermée dans active?
        return process_handle_active(proc);
      }
#else
      proc->mediate_state = 0;
      process_reset_state(proc);
      return process_handle_active(proc);
#endif
    }
  }

  else if (state & PROC_READ) {
    if (process_recv_in_call(proc, proc->sysarg.recvfrom.sockfd)) {
#ifndef address_translation
      pid_t pid = proc->pid;
      int res = process_recv_call(proc, &(proc->sysarg));
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_recvfrom_syscall(proc, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->mediate_state = 0;
        return PROCESS_TASK_FOUND;
      } else if (res == RECV_CLOSE) {
        if (strace_option)
          print_recvfrom_syscall(proc, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;   // TODO vérifier pourquoi on passe pas mediate_state à zéro
        return process_handle_active(proc);
      }
#else
      proc->mediate_state = 0;
      process_reset_state(proc);
      return process_handle_active(proc);
#endif
    }
  }

  else if (state & PROC_RECVMSG) {

    if (process_recv_in_call(proc, proc->sysarg.recvmsg.sockfd)) {
#ifndef address_translation
      pid_t pid = proc->pid;
      int res = process_recv_call(proc, &(proc->sysarg));
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_recvfrom_syscall(proc, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->mediate_state = 0;
        return PROCESS_TASK_FOUND;
      } else if (res == RECV_CLOSE) {
        if (strace_option)
          print_recvfrom_syscall(proc, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;   // TODO vérifier pourquoi on passe pas mediate_state à zéro
        return process_handle_active(proc);
      }
#else
      proc->mediate_state = 0;
      process_reset_state(proc);
      return process_handle_active(proc);
#endif
    }
  }
  return PROCESS_ON_MEDIATION;
}

int process_handle_active(process_descriptor_t * proc)
{
  XBT_DEBUG("PROCESS HANDLE ACTIVE");
  int status;
  pid_t pid = proc->pid;
  int proc_state = proc->state;
  xbt_assert(!(proc->mediate_state));   // TODO: vérifier. c'est vrai sauf si on vient de handle_mediate et que la socket a été fermée

//TODO
 /* if (proc_state & PROC_SELECT) {
    //if the select match changment we have to run the child
    if (process_select_call(proc)) {
      if (proc->in_timeout)
        FES_remove_timeout(pid);
      process_reset_state(proc);
    } else
      return PROCESS_ON_MEDIATION;
  } else if (proc_state & PROC_POLL) {
    if (process_poll_call(proc)) {
      if (proc->in_timeout)
        FES_remove_timeout(pid);
      process_reset_state(proc);
    } else
      return PROCESS_ON_MEDIATION;
  } else */  if ((proc_state & PROC_RECVFROM) && !(proc->in_syscall)) // en full quand la socket est fermée
    process_recvfrom_out_call(proc);

  else if ((proc_state & PROC_READ) && !(proc->in_syscall))
    process_read_out_call(proc);

  else if ((proc_state == PROC_RECVFROM) && (proc->in_syscall))// en full translation
#ifndef address_translation
    THROW_IMPOSSIBLE;
#else
    if (process_recv_in_call(proc, proc->sysarg.recv.sockfd))
      process_reset_state(proc);
    else
      return PROCESS_ON_MEDIATION;
#endif

  else if ((proc_state == PROC_READ) && (proc->in_syscall))
#ifndef address_translation
    THROW_IMPOSSIBLE;
#else
    if (process_recv_in_call(proc, proc->sysarg.recv.sockfd))
      process_reset_state(proc);
    else
      return PROCESS_ON_MEDIATION;
#endif


  else if ((proc_state == PROC_RECVMSG) && (proc->in_syscall))
#ifndef address_translation
    THROW_IMPOSSIBLE;
#else
    if (process_recv_in_call(proc, proc->sysarg.recv.sockfd))
      process_reset_state(proc);
    else
      return PROCESS_ON_MEDIATION;
#endif

  else if ((proc_state & PROC_RECVMSG) && !(proc->in_syscall))
    process_recvmsg_out_call(proc);

  ptrace_resume_process(pid);
  if (waitpid(pid, &status, 0) < 0)
    xbt_die(" [%d] waitpid %s %d\n", pid, strerror(errno), errno);

  return process_handle_msg(proc, status);
}
