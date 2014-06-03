#include "syscall_process.h"
#include "syscall_data.h"
#include "insert_trace.h"
#include "sockets.h"
#include "simterpose.h"
#include "data_utils.h"
#include "ptrace_utils.h"
#include "process_descriptor.h"
#include "args_trace.h"
#include "task.h"
#include "xbt.h"
#include "simdag/simdag.h"
#include "xbt/log.h"
#include "communication.h"
#include "print_syscall.h"

#include <time.h>
#include <linux/futex.h>

#define SYSCALL_ARG1 rdi
extern int strace_option;
const char *state_names[7] = {  "PROCESS_CONTINUE", "PROCESS_DEAD", "PROCESS_GROUP_DEAD", "PROCESS_TASK_FOUND", "PROCESS_NO_TASK_FOUND",
  "PROCESS_ON_MEDIATION", "PROCESS_ON_COMPUTATION"
};

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, SIMTERPOSE, "Syscall process log");

int process_accept_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg);
int process_recv_in_call(process_descriptor_t * proc, int fd);
void process_recvfrom_out_call(process_descriptor_t * proc);
void process_read_out_call(process_descriptor_t * proc);
void process_recvmsg_out_call(process_descriptor_t * proc);
void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg);

//TODO test the possibility to remove incomplete checking
//There is no need to return value because send always bring a task
static int process_send_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  pid_t pid = proc->pid;
  XBT_DEBUG("Entering process_send_call");
  send_arg_t arg = &(sysarg->send);
  if (socket_registered(pid, arg->sockfd) != -1) {
    if (!socket_netlink(pid, arg->sockfd)) {
      XBT_DEBUG("%d This is not a netlink socket", arg->sockfd);
      compute_computation_time(proc);   // cree la computation task
      struct infos_socket *is = get_infos_socket(pid, arg->sockfd);
      struct infos_socket *s = comm_get_peer(is);
      //        XBT_DEBUG("[%d] %d->%d", pid, arg->sockfd, arg->ret);
      XBT_DEBUG("%d->%d", arg->sockfd, arg->ret);
      XBT_DEBUG("Sending data(%d) on socket %d", arg->ret, s->fd.fd);
      int peer_stat = s->fd.proc->state;
      if (peer_stat == PROC_SELECT || peer_stat == PROC_POLL || ((peer_stat == PROC_RECV) && (s->fd.proc->in_syscall)))
        add_to_sched_list(s->fd.proc->pid);

      handle_new_send(is, sysarg);

      //  SD_task_t task = create_send_communication_task(pid, is, arg->ret);

      //  schedule_comm_task(is->fd.proc->host, s->fd.proc->host, task);
      create_and_schedule_communication_task(proc, is, arg->ret, is->fd.proc->host, s->fd.proc->host);
      is->fd.proc->on_simulation = 1;
      return 1;
    }
    return 0;
  } else
    THROW_IMPOSSIBLE;
}

static int process_recv_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  pid_t pid = proc->pid;
  recv_arg_t arg = &(sysarg->recv);
  XBT_DEBUG("Entering process_RECV_call, ret %d", arg->ret);
  if (socket_registered(pid, arg->sockfd) != -1) {
    if (!socket_netlink(pid, arg->sockfd)) {
      compute_computation_time(proc);

      //if handle_new_receive return 1, there is a task found
      if (handle_new_receive(pid, sysarg))
        return PROCESS_TASK_FOUND;
      else {
        struct infos_socket *is = get_infos_socket(pid, arg->sockfd);
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

static int process_select_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_select_call");
  pid_t pid = proc->pid;
  select_arg_t arg = &(proc->sysarg.select);
  int i;

  fd_set fd_rd, fd_wr, fd_ex;

  fd_rd = arg->fd_read;
  fd_wr = arg->fd_write;
  fd_ex = arg->fd_except;

  int match = 0;

  for (i = 0; i < arg->maxfd; ++i) {
    struct infos_socket *is = get_infos_socket(pid, i);
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
    sys_build_select(pid, match);
    if (strace_option)
      print_select_syscall(pid, &(proc->sysarg));
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
    sys_build_select(pid, 0);
    if (strace_option)
      print_select_syscall(pid, &(proc->sysarg));
    proc->in_timeout = PROC_NO_TIMEOUT;
    return 1;
  }
  return 0;
}


static int process_poll_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering poll %lf \n", SD_get_clock());
  poll_arg_t arg = (poll_arg_t) & (proc->sysarg.poll);
  pid_t pid = proc->pid;

  int match = 0;
  int i;

  for (i = 0; i < arg->nbfd; ++i) {
    struct pollfd *temp = &(arg->fd_list[i]);

    struct infos_socket *is = get_infos_socket(pid, temp->fd);
    if (is == NULL)
      continue;
    else {
      int sock_status = socket_get_state(is);
      XBT_DEBUG("%d-> %d\n", temp->fd, sock_status);
      if (temp->events & POLLIN) {
        if (sock_status & SOCKET_READ_OK || sock_status & SOCKET_CLOSED) {
          temp->revents = temp->revents | POLLIN;
          ++match;
        } else {
          temp->revents = temp->revents & ~POLLIN;
        }
      } else if (temp->events & POLLOUT) {
        XBT_DEBUG("POLLOUT\n");
        if (sock_status & SOCKET_WR_NBLK) {
          temp->revents = temp->revents | POLLOUT;
          ++match;
        } else {
          temp->revents = temp->revents & ~POLLOUT;
        }
      } else
        XBT_WARN("Mediation different than POLLIN are not handle for poll\n");
    }
  }
  if (match > 0) {
    XBT_DEBUG("Result for poll\n");
    sys_build_poll(pid, match);
    if (strace_option)
      print_poll_syscall(pid, &(proc->sysarg));
    free(proc->sysarg.poll.fd_list);
    return match;
  }
  if (proc->in_timeout == PROC_TIMEOUT_EXPIRE) {
    XBT_DEBUG("Time out on poll\n");
    sys_build_poll(pid, 0);
    if (strace_option)
      print_poll_syscall(pid, &(proc->sysarg));
    free(proc->sysarg.poll.fd_list);
    proc->in_timeout = PROC_NO_TIMEOUT;
    return 1;
  }
  return match;
}

static void process_getpeername_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  getpeername_arg_t arg = &(sysarg->getpeername);
  pid_t pid = proc->pid;

  if (socket_registered(pid, arg->sockfd)) {
    if (socket_network(pid, arg->sockfd)) {
      struct infos_socket *is = get_infos_socket(pid, arg->sockfd);
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
        print_getpeername_syscall(pid, sysarg);
    }
  }
}


int process_handle_active(process_descriptor_t * proc)
{
  XBT_DEBUG("PROCESS HANDLE ACTIVE");
  int status;
  pid_t pid = proc->pid;
  int proc_state = proc->state;

  if (proc_state & PROC_SELECT) {
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
  } else if (proc_state & PROC_CONNECT) {
    return PROCESS_ON_MEDIATION;
  }
#ifdef address_translation
  else if (proc_state & PROC_CONNECT_DONE) {
    waitpid(pid, &status, 0);
    return process_handle(proc, status);
  }
#endif
  else if ((proc_state & PROC_ACCEPT) && (proc->in_syscall)) {
    pid_t conn_pid = process_accept_in_call(proc, &proc->sysarg);
    if (conn_pid)
      add_to_sched_list(conn_pid);      //We have to add conn_pid to the schedule list
    else
      return PROCESS_ON_MEDIATION;
  } else if ((proc_state & PROC_RECVFROM) && !(proc->in_syscall))
    process_recvfrom_out_call(proc);

  else if ((proc_state & PROC_READ) && !(proc->in_syscall))
    process_read_out_call(proc);

  else if ((proc_state == PROC_RECVFROM) && (proc->in_syscall))
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

  return process_handle(proc, status);
}


int process_recv_in_call(process_descriptor_t * proc, int fd)
{
  XBT_DEBUG("Entering process_recv_in_call");
  pid_t pid = proc->pid;
  // XBT_DEBUG("[%d]Trying to see if socket %d recv something", pid, fd);
  XBT_DEBUG("Trying to see if socket %d recv something", fd);
  if (proc->fd_list[fd] == NULL)
    return 0;

  if (!socket_network(pid, fd))
#ifndef address_translation
    return 0;
#else
    return 1;
#endif

  int status = comm_get_socket_state(get_infos_socket(pid, fd));
  XBT_DEBUG("socket status %d %d", status, status & SOCKET_READ_OK || status & SOCKET_CLOSED);

  XBT_DEBUG("Leaving process_recv_in_call");
  return (status & SOCKET_READ_OK || status & SOCKET_CLOSED || status & SOCKET_SHUT);
}

void process_recvfrom_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_RECVFROM_out_call");
  pid_t pid = proc->pid;
  //   recvfrom_arg_t arg = &(proc->sysarg.recvfrom);
  //   XBT_DEBUG("[%d]Try to see if socket %d recv something", pid, fd);
  //   if(proc->fd_list[arg->sockfd]==NULL)
  //     return;
  //   
  //   if(!socket_network(pid, arg->sockfd))
  //     return;

  process_reset_state(proc);
  syscall_arg_u *sysarg = &(proc->sysarg);
  recvfrom_arg_t arg = &(sysarg->recvfrom);
  if (strace_option)
    print_recvfrom_syscall(pid, &(proc->sysarg));
  ptrace_restore_syscall(pid, SYS_recvfrom, arg->ret);
  ptrace_poke(pid, (void *) arg->dest, arg->data, arg->ret);
  free(arg->data);
}

void process_read_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_read_out_call");
  process_reset_state(proc);
  pid_t pid = proc->pid;

  syscall_arg_u *sysarg = &(proc->sysarg);
  read_arg_t arg = &(sysarg->read);
  ptrace_restore_syscall(pid, SYS_read, arg->ret);
  if (arg->ret > 0) {
    ptrace_poke(pid, (void *) arg->dest, arg->data, arg->ret);
    free(arg->data);
  }
}

void process_recvmsg_out_call(process_descriptor_t * proc)
{
  XBT_DEBUG("Entering process_recvmsg_out_call");
  pid_t pid = proc->pid;
  sys_build_recvmsg(pid, &(proc->sysarg));
  process_reset_state(proc);
}


//Return 0 if nobody wait or the pid of the one who wait
int process_accept_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_accept_in_call");
  accept_arg_t arg = &(sysarg->accept);
  pid_t pid = proc->pid;
  //We try to find here if there's a connection to accept
  if (comm_has_connect_waiting(get_infos_socket(pid, arg->sockfd))) {
    struct sockaddr_in in;
    pid_t conn_pid = comm_accept_connect(get_infos_socket(pid, arg->sockfd), &in);
    arg->sai = in;

    //     struct in_addr in2 = {arg->sai.sin_addr.s_addr};
    //     XBT_DEBUG("Accept connection from %s:%d\n", inet_ntoa(in2), arg->sai.sin_port);
    process_descriptor_t *conn_proc = process_get_descriptor(conn_pid);

    int conn_state = conn_proc->state;
    if (conn_state & PROC_CONNECT) {
#ifndef address_translation
      add_to_sched_list(conn_pid);
      process_reset_state(conn_proc);
#else
      ptrace_resume_process(conn_pid);
      add_to_sched_list(conn_pid);
      conn_proc->state = PROC_CONNECT_DONE;
#endif
    }
#ifndef address_translation
    //Now we rebuild the syscall.
    int new_fd = ptrace_record_socket(pid);

    arg->ret = new_fd;
    ptrace_neutralize_syscall(pid);
    proc->in_syscall = 0;

    accept_arg_t arg = &(sysarg->accept);
    ptrace_restore_syscall(pid, SYS_accept, arg->ret);

    ptrace_poke(pid, arg->addr_dest, &(arg->sai), sizeof(struct sockaddr_in));
    //   ptrace_poke(pid, arg->len_dest, &(arg->addrlen), sizeof(socklen_t));

    process_accept_out_call(proc, sysarg);
    if (strace_option)
      print_accept_syscall(pid, sysarg);
#endif

    return conn_pid;
  } else {
    proc->state = PROC_ACCEPT;
    return 0;
  }
}

void process_accept_out_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  XBT_DEBUG(" CONNEXION: process_accept_out_call");
  accept_arg_t arg = &(sysarg->accept);
  pid_t pid = proc->pid;

  if (arg->ret >= 0) {
    int domain = get_domain_socket(pid, arg->sockfd);
    int protocol = get_protocol_socket(pid, arg->sockfd);

    struct infos_socket *is = register_socket(pid, arg->ret, domain, protocol);
#ifdef address_translation
    sys_translate_accept(pid, sysarg);
#endif
    comm_join_on_accept(is, pid, arg->sockfd);

    struct infos_socket *s = get_infos_socket(pid, arg->sockfd);
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

    set_localaddr_port_socket(pid, arg->ret, inet_ntoa(in), s->port_local);

  }
  process_reset_state(proc);
}

static void process_shutdown_call(pid_t pid, syscall_arg_u * sysarg)
{
  shutdown_arg_t arg = &(sysarg->shutdown);
  struct infos_socket *is = get_infos_socket(pid, arg->fd);
  if (is == NULL)
    return;
  comm_shutdown(is);
}

/*static int process_clone_call(process_descriptor_t * proc, reg_s * arg)
{
  unsigned long tid = arg->ret;
  unsigned long flags = arg->arg1;

  //Now create new process in model
  process_clone(tid, proc->pid, flags);

  //Now add it to the launching time table to be the next process to be launch
  FES_schedule_now(tid);

  int status;

  //wait for clone
  waitpid(tid, &status, 0);
  ptrace_resume_process(tid);
  //place process to te first call after clone
  waitpid(tid, &status, 0);
  process_get_descriptor(tid)->in_syscall = 1;

  return 0;
}*/


static int process_connect_in_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  XBT_DEBUG(" CONNEXION: process_connect_in_call");
  pid_t pid = proc->pid;
  int domain = get_domain_socket(pid, arg->sockfd);

  if (domain == 2)              //PF_INET
  {
    struct sockaddr_in *sai = &(arg->sai);

    SD_workstation_t host;
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
    int acc_pid = comm_ask_connect(host, ntohs(sai->sin_port), pid, arg->sockfd, device);

    //if the processus waiting for connection, we add it to schedule list
    if (acc_pid) {
      process_descriptor_t *acc_proc = process_get_descriptor(acc_pid);
      int status = acc_proc->state;
      if (status == PROC_ACCEPT || status == PROC_SELECT || status == PROC_POLL)
        add_to_sched_list(acc_pid);
      // #ifndef address_translation
      //Now attribute ip and port to the socket.
      int port = get_random_port(proc->host);

      XBT_DEBUG("New socket %s:%d", inet_ntoa(in), port);
      set_localaddr_port_socket(pid, arg->sockfd, inet_ntoa(in), port);
      register_port(proc->host, port);
      // #endif
      XBT_DEBUG("Free port found on host %s (%s:%d)", SD_workstation_get_name(proc->host), inet_ntoa(in), port);
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
    int flags = socket_get_flags(pid, arg->sockfd);
    if (flags & O_NONBLOCK)
      arg->ret = -EINPROGRESS;  /* EINPROGRESS  115      Operation now in progress */
    else
      arg->ret = 0;

    ptrace_neutralize_syscall(pid);
    proc->in_syscall = 0;
    connect_arg_t arg = &(sysarg->connect);
    ptrace_restore_syscall(pid, SYS_connect, arg->ret);

    //now mark the process as waiting for conn

    if (flags & O_NONBLOCK)
      return 0;

    proc->state = PROC_CONNECT;
    return 1;
#else
    sys_translate_connect_in(pid, sysarg);
    int flags = socket_get_flags(pid, arg->sockfd);
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
  pid_t pid = proc->pid;
  connect_arg_t arg = &(sysarg->connect);

  int domain = get_domain_socket(pid, arg->sockfd);
  if (domain == 2 && arg->ret >= 0) {
    struct infos_socket *is = get_infos_socket(pid, arg->sockfd);

    sys_translate_connect_out(pid, sysarg);
    int port = socket_get_local_port(pid, arg->sockfd);
    set_real_port(proc->host, is->port_local, ntohs(port));
    add_new_translation(ntohs(port), is->port_local, get_ip_of_host(proc->host));
  }
#endif
  process_reset_state(proc);
}

static int process_bind_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  bind_arg_t arg = &(sysarg->bind);
  pid_t pid = proc->pid;
  if (socket_registered(pid, arg->sockfd)) {
    if (socket_network(pid, arg->sockfd)) {

      if (!is_port_in_use(proc->host, ntohs(arg->sai.sin_port))) {
        XBT_DEBUG("Port %d is free", ntohs(arg->sai.sin_port));
        register_port(proc->host, ntohs(arg->sai.sin_port));

        struct infos_socket *is = get_infos_socket(pid, arg->sockfd);
        int device = 0;
        if (arg->sai.sin_addr.s_addr == INADDR_ANY)
          device = (PORT_LOCAL | PORT_REMOTE);
        else if (arg->sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
          device = PORT_LOCAL;
        else
          device = PORT_REMOTE;

        set_port_on_binding(proc->host, ntohs(arg->sai.sin_port), is, device);

        is->binded = 1;

        set_localaddr_port_socket(pid, arg->sockfd, inet_ntoa(arg->sai.sin_addr), ntohs(arg->sai.sin_port));
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

static int process_socket_call(pid_t pid, syscall_arg_u * arg)
{
  socket_arg_t sock = &(arg->socket);
  if (sock->ret > 0)
    register_socket(pid, sock->ret, sock->domain, sock->protocol);
  return 0;
}

static void process_setsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  setsockopt_arg_t arg = &(sysarg->setsockopt);
  pid_t pid = proc->pid;
  //TODO really handle setsockopt that currently raise a warning
  arg->ret = 0;

  if (arg->optname == SO_REUSEADDR)
    socket_set_option(pid, arg->sockfd, SOCK_OPT_REUSEADDR, *((int *) arg->optval));
  else
    XBT_WARN("Option non supported by Simterpose.");

  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_setsockopt, arg->ret);

  proc->in_syscall = 0;
}


static void process_getsockopt_syscall(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  pid_t pid = proc->pid;

  arg->ret = 0;
  if (arg->optname == SO_REUSEADDR) {
    arg->optlen = sizeof(int);
    arg->optval = malloc(arg->optlen);
    *((int *) arg->optval) = socket_get_option(pid, arg->sockfd, SOCK_OPT_REUSEADDR);
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


static int process_listen_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  //TODO make gestion of back_log
  listen_arg_t arg = &(sysarg->listen);
  pid_t pid = proc->pid;
  struct infos_socket *is = get_infos_socket(pid, arg->sockfd);
  comm_t comm = comm_new(is);
  comm_set_listen(comm);

#ifndef address_translation
  arg->ret = 0;
  ptrace_neutralize_syscall(pid);
  arg = &(sysarg->listen);
  ptrace_restore_syscall(pid, SYS_listen, arg->ret);
  proc->in_syscall = 0;
#endif

  return 0;
}

static void process_fcntl_call(process_descriptor_t * proc, syscall_arg_u * sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  pid_t pid = proc->pid;

  switch (arg->cmd) {
  case F_SETFL:
    socket_set_flags(pid, arg->fd, arg->arg);
    return;
    break;

  default:
    return;
    break;
  }
#ifndef address_translation
  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_fcntl, arg->ret);
  proc->in_syscall = 0;
#endif
}

static void process_close_call(process_descriptor_t * proc, int fd)
{
  fd_descriptor_t *file_desc = proc->fd_list[fd];
  if (file_desc->type == FD_SOCKET)
    socket_close(proc->pid, fd);
  else {
    free(file_desc);
    proc->fd_list[fd] = NULL;
  }
}


int process_handle_mediate(process_descriptor_t * proc)
{
  XBT_DEBUG("PROCESS HANDLE MEDIATE");
  int state = proc->state;
  xbt_assert(proc->in_syscall); //FIXME: simplify

  if ((state & PROC_RECVFROM) && (proc->in_syscall)) {
    XBT_DEBUG("mediate recvfrom_in");
    if (process_recv_in_call(proc, proc->sysarg.recvfrom.sockfd)) {
#ifndef address_translation
      pid_t pid = proc->pid;
      int res = process_recv_call(proc, &(proc->sysarg));
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_recvfrom_syscall(pid, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->mediate_state = 0;
        return PROCESS_TASK_FOUND;
      } else if (res == RECV_CLOSE) {
        if (strace_option)
          print_recvfrom_syscall(pid, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        return process_handle_active(proc);
      }
#else
      proc->mediate_state = 0;
      process_reset_state(proc);
      return process_handle_active(proc);
#endif
    }
  }

  else if ((state & PROC_READ) && (proc->in_syscall)) {
    if (process_recv_in_call(proc, proc->sysarg.recvfrom.sockfd)) {
#ifndef address_translation
      pid_t pid = proc->pid;
      int res = process_recv_call(proc, &(proc->sysarg));
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_recvfrom_syscall(pid, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->mediate_state = 0;
        return PROCESS_TASK_FOUND;
      } else if (res == RECV_CLOSE) {
        if (strace_option)
          print_recvfrom_syscall(pid, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        return process_handle_active(proc);
      }
#else
      proc->mediate_state = 0;
      process_reset_state(proc);
      return process_handle_active(proc);
#endif
    }
  }

  else if ((state & PROC_RECVMSG) && (proc->in_syscall)) {

    if (process_recv_in_call(proc, proc->sysarg.recvmsg.sockfd)) {
#ifndef address_translation
      pid_t pid = proc->pid;
      int res = process_recv_call(proc, &(proc->sysarg));
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_recvfrom_syscall(pid, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->mediate_state = 0;
        return PROCESS_TASK_FOUND;
      } else if (res == RECV_CLOSE) {
        if (strace_option)
          print_recvfrom_syscall(pid, &(proc->sysarg));
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
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

////// pre and post gestion of syscalls //////

/**
 * called by each syscall at the end of "pre" state
 * to verify if we need to start a computation task
 */
static int syscall_pre(pid_t pid, process_descriptor_t * proc, int *state) // FIXME: can we kill that *state?
{
  if (compute_computation_time(proc)) {
    //if we have computation to simulate
    schedule_computation_task(proc);
    proc->on_simulation = 1;
    *state = PROCESS_ON_COMPUTATION;
  }
  if (*state >= 0)
    return *state;
  return PROCESS_CONTINUE;
}

static int syscall_read_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  get_args_read(pid, reg, sysarg);
  if (socket_registered(pid, reg->arg1) != -1) {
    if (!process_recv_in_call(proc, reg->arg1)) {
#ifndef address_translation
      int flags = socket_get_flags(pid, reg->arg1);
      if (flags & O_NONBLOCK) {
        sysarg->read.ret = -EAGAIN;     /* EAGAIN 11 Try again */
        if (strace_option)
          print_read_syscall(pid, sysarg);
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        process_read_out_call(proc);
      } else {
        proc->state = PROC_READ;
        proc->mediate_state = 1;
        *state = PROCESS_ON_MEDIATION;
      }
    } else {
      int res = process_recv_call(proc, sysarg);
      if (res == PROCESS_TASK_FOUND) {
        if (strace_option)
          print_read_syscall(pid, sysarg);
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        proc->state = PROC_READ;
        return PROCESS_TASK_FOUND;
      } else {
        if (res == RECV_CLOSE)
          sysarg->read.ret = 0;
        if (strace_option)
          print_read_syscall(pid, sysarg);
        ptrace_neutralize_syscall(pid);
        proc->in_syscall = 0;
        process_read_out_call(proc);
      }
#else
      int flags = socket_get_flags(pid, reg->arg1);
      if (!(flags & O_NONBLOCK)) {
        proc->state = PROC_READ;
        *state = PROCESS_ON_MEDIATION;
        proc->mediate_state = 1;
      }
#endif
    }
  }
  return syscall_pre(pid, proc, state);
}

static int syscall_read_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_read(pid, reg, sysarg);
  if (strace_option)
    print_read_syscall(pid, sysarg);
#ifdef address_translation
  if ((int) reg->ret > 0) {
    if (socket_registered(pid, sysarg->read.fd) != -1) {
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
  *state = -1;
#ifndef address_translation
  // XBT_DEBUG("[%d] write_in", pid);
  XBT_DEBUG(" write_in");
  get_args_write(pid, reg, sysarg);
  if (socket_registered(pid, sysarg->write.fd) != -1) {
    if (process_send_call(proc, sysarg)) {
      ptrace_neutralize_syscall(pid);

      sendto_arg_t arg = &(sysarg->sendto);
      ptrace_restore_syscall(pid, SYS_sendto, arg->ret);
      if (strace_option)
        print_write_syscall(pid, sysarg);
      proc->in_syscall = 0;
      return PROCESS_TASK_FOUND;
    }
  }
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_write_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  //    XBT_DEBUG("[%d] write_out", pid);
  get_args_write(pid, reg, sysarg);
  if (strace_option)
    print_write_syscall(pid, sysarg);
#ifdef address_translation
  if ((int) reg->ret > 0) {
    if (socket_registered(pid, sysarg->write.fd) != -1) {
      if (process_send_call(proc, sysarg))
        return PROCESS_TASK_FOUND;
    }
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_poll_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  get_args_poll(pid, reg, sysarg);
  if (strace_option)
    print_poll_syscall(pid, sysarg);
  if (sysarg->poll.timeout >= 0)
    FES_push_timeout(pid, sysarg->poll.timeout + SD_get_clock());
  else
    proc->in_timeout = 1;
  ptrace_neutralize_syscall(pid);
  proc->in_syscall = 0;
  proc->state = PROC_POLL;
  *state = PROCESS_ON_MEDIATION;
  return syscall_pre(pid, proc, state);
}

static int syscall_exit_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  ptrace_detach_process(pid);
  return PROCESS_DEAD;
}

static int syscall_time_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  time_arg_t arg = &(sysarg->time);
  arg->ret = reg->ret;
  ptrace_neutralize_syscall(pid);
  sysarg->time.ret = get_simulated_timestamp(); // (time_t)25; //
  if (strace_option)
    print_time_syscall(pid, sysarg);
  ptrace_restore_syscall(pid, SYS_time, arg->ret);
  proc->in_syscall = 0;
  return syscall_pre(pid, proc, state);
}

static int syscall_gettimeofday_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc,
                                    int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  gettimeofday_arg_t arg = &(sysarg->gettimeofday);
  arg->ret = reg->ret;
  arg->tv = (void *) reg->arg1;

  if (strace_option)
    print_gettimeofday_syscall(pid, sysarg);
  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_gettimeofday, arg->ret);

  struct timeval tv;
  tv.tv_sec = get_simulated_timestamp();
  tv.tv_usec = 0;
  ptrace_poke(pid, arg->tv, &(tv), sizeof(struct timeval));

  proc->in_syscall = 0;
  return syscall_pre(pid, proc, state);
}

static int syscall_clock_gettime_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc,
                                     int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  clockgettime_arg_t arg = &(sysarg->clockgettime);
  arg->ret = reg->ret;
  arg->tp = (void *) reg->arg2;
  ptrace_neutralize_syscall(pid);
  ptrace_restore_syscall(pid, SYS_clock_gettime, arg->ret);

  struct timespec tp;
  tp.tv_sec = get_simulated_timestamp();
  tp.tv_nsec = 0;
  ptrace_poke(pid, arg->tp, &(tp), sizeof(struct timespec));

  proc->in_syscall = 0;
  return syscall_pre(pid, proc, state);
}

static int syscall_getpeername_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc,
                                   int *state)
{
  proc->in_syscall = 1;
  *state = -1;

  getpeername_arg_t arg = &(sysarg->getpeername);
  arg->ret = reg->ret;
  arg->sockfd = reg->arg1;
  arg->sockaddr_dest = (void *) reg->arg2;
  arg->len_dest = (void *) reg->arg3;
  ptrace_cpy(pid, &(arg->len), arg->len_dest, sizeof(socklen_t), "getpeername");

  process_getpeername_call(proc, sysarg);
  return syscall_pre(pid, proc, state);
}

static int syscall_listen_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
#ifndef address_translation
  //  XBT_DEBUG("[%d] listen_in", pid);
  XBT_DEBUG("listen_in");
  get_args_listen(pid, reg, sysarg);
  process_listen_call(proc, sysarg);
  if (strace_option)
    print_listen_syscall(pid, sysarg);
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_listen_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("[%d] listen_out", pid);
#ifdef address_translation
  get_args_listen(pid, reg, sysarg);
  process_listen_call(proc, sysarg);
  if (strace_option)
    print_listen_syscall(pid, sysarg);
  return PROCESS_CONTINUE;
#else
  THROW_IMPOSSIBLE;
#endif
}

static int syscall_bind_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  //    XBT_DEBUG("[%d] bind_in ", pid);
  XBT_DEBUG("bind_in ");
  get_args_bind_connect(pid, 0, reg, sysarg);
  process_bind_call(proc, sysarg);
  if (strace_option)
    print_bind_syscall(pid, sysarg);
  return syscall_pre(pid, proc, state);
}

static int syscall_bind_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] bind_out", pid);
  XBT_DEBUG("bind_out");
  get_args_bind_connect(pid, 0, reg, sysarg);
  if (strace_option)
    print_bind_syscall(pid, sysarg);
  return PROCESS_CONTINUE;
}

static int syscall_connect_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  //    XBT_DEBUG("[%d] connect_in", pid);
  XBT_DEBUG("connect_in");
  get_args_bind_connect(pid, 0, reg, sysarg);
  if (process_connect_in_call(proc, sysarg))
    *state = PROCESS_ON_MEDIATION;
  return syscall_pre(pid, proc, state);
}

static int syscall_connect_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  //    XBT_DEBUG("[%d] connect_out", pid);
  XBT_DEBUG("connect_out");

  get_args_bind_connect(pid, 1, reg, sysarg);
#ifdef address_translation
  process_connect_out_call(proc, sysarg);
  process_reset_state(proc);
#endif
  if (strace_option)
    print_connect_syscall(pid, sysarg);
  return PROCESS_CONTINUE;
}

static int syscall_accept_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  //    XBT_DEBUG("[%d] accept_in", pid);
  XBT_DEBUG("accept_in");
  get_args_accept(pid, reg, sysarg);
  pid_t conn_pid = process_accept_in_call(proc, sysarg);
  if (!conn_pid)
    *state = PROCESS_ON_MEDIATION;
  return syscall_pre(pid, proc, state);
}

static int syscall_accept_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  XBT_DEBUG("[%d] accept_out", pid);
  get_args_accept(pid, reg, sysarg);
#ifdef address_translation
  process_accept_out_call(proc, sysarg);
#endif
  if (strace_option)
    print_accept_syscall(pid, sysarg);
  return PROCESS_CONTINUE;
}

static int syscall_getsockopt_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc,
                                  int *state)
{
  proc->in_syscall = 1;
  *state = -1;
#ifndef address_translation
  get_args_getsockopt(pid, reg, sysarg);
  process_getsockopt_syscall(proc, sysarg);
  if (strace_option)
    print_getsockopt_syscall(pid, sysarg);
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_getsockopt_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_getsockopt(pid, reg, sysarg);
  if (strace_option)
    print_getsockopt_syscall(pid, sysarg);
  return PROCESS_CONTINUE;
}

static int syscall_setsockopt_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc,
                                  int *state)
{
  proc->in_syscall = 1;
  *state = -1;
#ifndef address_translation
  get_args_setsockopt(pid, reg, sysarg);
  process_setsockopt_syscall(proc, sysarg);
  if (strace_option)
    print_setsockopt_syscall(pid, sysarg);
  free(sysarg->setsockopt.optval);
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_setsockopt_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_setsockopt(pid, reg, sysarg);
  if (strace_option)
    print_setsockopt_syscall(pid, sysarg);
  return PROCESS_CONTINUE;
}

static int syscall_fcntl_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
#ifndef address_translation
  get_args_fcntl(pid, reg, sysarg);
  if (strace_option)
    print_fcntl_syscall(pid, sysarg);
  process_fcntl_call(proc, sysarg);
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_fcntl_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  get_args_fcntl(pid, reg, sysarg);
  if (strace_option)
    print_fcntl_syscall(pid, sysarg);
#ifdef address_translation
  process_fcntl_call(proc, sysarg);
#endif
  return PROCESS_CONTINUE;
}

static int syscall_select_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  get_args_select(pid, reg, sysarg);
  if (strace_option)
    print_select_syscall(pid, sysarg);
  if (sysarg->select.timeout >= 0)
    FES_push_timeout(pid, sysarg->select.timeout + SD_get_clock());
  else
    proc->in_timeout = 1;
  ptrace_neutralize_syscall(pid);
  proc->in_syscall = 0;
  proc->state = PROC_SELECT;
  *state = PROCESS_ON_MEDIATION;
  return syscall_pre(pid, proc, state);
}

static int syscall_recvfrom_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  // XBT_DEBUG("[%d] RECVFROM_in", pid);
  XBT_DEBUG("RECVFROM_in");
  get_args_recvfrom(pid, reg, sysarg);
#ifdef address_translation
  if (socket_registered(pid, reg->arg1) != -1) {
    if (socket_network(pid, reg->arg1)) {
      sys_translate_recvfrom_in(pid, sysarg);
    }
  }
#endif
  // XBT_DEBUG("[%d] Seeing if %d receive something", pid, (int)reg->arg1);
  XBT_DEBUG("Seeing if %d receive something", (int) reg->arg1);
  if (!process_recv_in_call(proc, sysarg->recvfrom.sockfd)) {
#ifndef address_translation
    XBT_DEBUG("recvfrom_in, full mediation");
    int flags = socket_get_flags(pid, reg->arg1);
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
      print_recvfrom_syscall(pid, sysarg);
#else
    XBT_DEBUG("recvfrom_in, address translation");
    int flags = socket_get_flags(pid, reg->arg1);
    if (!(flags & O_NONBLOCK)) {
      proc->state = PROC_RECVFROM;
      *state = PROCESS_ON_MEDIATION;
      proc->mediate_state = 1;
    }
#endif
  }
  return syscall_pre(pid, proc, state);
}

static int syscall_recvfrom_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] recvfrom_out", pid);
  XBT_DEBUG("recvfrom_out");
  get_args_recvfrom(pid, reg, sysarg);
#ifdef address_translation
  if (socket_registered(pid, reg->arg1) != -1) {
    if (socket_network(pid, reg->arg1)) {
      sys_translate_recvfrom_out(pid, sysarg);
    }
  }
  if (reg->ret > 0) {
    if (process_recv_call(proc, sysarg) == PROCESS_TASK_FOUND)
      return PROCESS_TASK_FOUND;
  }
#endif
  if (strace_option)
    print_recvfrom_syscall(pid, &(proc->sysarg));
  return PROCESS_CONTINUE;
}

static int syscall_sendmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
#ifndef address_translation
  //  XBT_DEBUG("[%d] sendmsg_in", pid);
  XBT_DEBUG("sendmsg_in");
  get_args_sendmsg(pid, reg, sysarg);
  if (process_send_call(proc, sysarg)) {
    ptrace_neutralize_syscall(pid);

    syscall_arg_u *sysarg = &(proc->sysarg);
    sendmsg_arg_t arg = &(sysarg->sendmsg);
    ptrace_restore_syscall(pid, SYS_sendmsg, arg->ret);

    proc->in_syscall = 0;
    if (strace_option)
      print_sendmsg_syscall(pid, sysarg);
    return PROCESS_TASK_FOUND;
  }
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_sendmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] sendmsg_out", pid);
  XBT_DEBUG("sendmsg_out");
  get_args_sendmsg(pid, reg, sysarg);
  if (strace_option)
    print_sendmsg_syscall(pid, sysarg);
#ifdef address_translation
  if (reg->ret > 0) {
    if (process_send_call(proc, sysarg))
      return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_recvmsg_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  //  XBT_DEBUG("[%d] recvmsg_in", pid);
  XBT_DEBUG("recvmsg_in");
  get_args_recvmsg(pid, reg, sysarg);

  if (!process_recv_in_call(proc, sysarg->recvmsg.sockfd)) {
    if (strace_option)
      print_read_syscall(pid, sysarg);
#ifndef address_translation
    if (socket_registered(pid, sysarg->recvmsg.sockfd))
      if (!socket_network(pid, sysarg->recvmsg.sockfd))
        return PROCESS_CONTINUE;

    int flags = socket_get_flags(pid, reg->arg1);
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
      print_read_syscall(pid, sysarg);
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
      print_read_syscall(pid, sysarg);
#else
    int flags = socket_get_flags(pid, reg->arg1);
    if (!(flags & O_NONBLOCK)) {
      proc->state = PROC_RECVMSG;
      *state = PROCESS_ON_MEDIATION;
      proc->mediate_state = 1;
    }
#endif
    if (strace_option)
      print_read_syscall(pid, sysarg);
  }
  return syscall_pre(pid, proc, state);
}

static int syscall_recvmsg_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] recvmsg_out", pid);
  XBT_DEBUG("recvmsg_out");
  get_args_recvmsg(pid, reg, sysarg);
  if (strace_option)
    print_recvmsg_syscall(pid, sysarg);
#ifdef address_translation
  if (reg->ret > 0) {
    if (process_recv_call(proc, sysarg) == PROCESS_TASK_FOUND)
      return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_sendto_pre(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc, int *state)
{
  proc->in_syscall = 1;
  *state = -1;
  //  XBT_DEBUG("[%d] sendto_in", pid);
  XBT_DEBUG("sendto_in");
  get_args_sendto(pid, reg, sysarg);
#ifndef address_translation
  if (process_send_call(proc, sysarg)) {
    XBT_DEBUG("process_handle -> PROCESS_TASK_FOUND");
    ptrace_neutralize_syscall(pid);

    sendto_arg_t arg = &(sysarg->sendto);
    ptrace_restore_syscall(pid, SYS_sendto, arg->ret);
    proc->in_syscall = 0;
    if (strace_option)
      print_sendto_syscall(pid, sysarg);
    return PROCESS_TASK_FOUND;
  }
#else
  if (socket_registered(pid, reg->arg1) != -1) {
    if (socket_network(pid, reg->arg1)) {
      sys_translate_sendto_in(pid, sysarg);
    }
  }
#endif
  return syscall_pre(pid, proc, state);
}

static int syscall_sendto_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  // XBT_DEBUG("[%d] sendto_out", pid);
  XBT_DEBUG("sendto_out");
  get_args_sendto(pid, reg, sysarg);
  if (strace_option)
    print_sendto_syscall(pid, sysarg);
#ifdef address_translation

  if (socket_registered(pid, reg->arg1) != -1) {
    if (socket_network(pid, reg->arg1)) {
      sys_translate_sendto_out(pid, sysarg);
    }
  }
  if ((int) reg->ret > 0) {
    if (process_send_call(proc, sysarg))
      return PROCESS_TASK_FOUND;
  }
#endif
  return PROCESS_CONTINUE;
}

static int syscall_open_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  //           printf("[%d] open(\"...\",", pid);
  //           switch (reg->arg2) {
  //             case 0: printf("O_RDONLY"); break;
  //             case 1: printf("O_WRONLY"); break;
  //             case 2: printf("O_RDWR"); break;
  //             default :printf("no_flags");break;
  //           }    
  //           printf(") = %ld\n", reg->ret);
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    proc->fd_list[(int) reg->ret] = file_desc;
  }
  return PROCESS_CONTINUE;
}

static int syscall_creat_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  if ((int) reg->ret >= 0) {
    fd_descriptor_t *file_desc = malloc(sizeof(fd_descriptor_t));
    file_desc->fd = (int) reg->ret;
    file_desc->proc = proc;
    file_desc->type = FD_CLASSIC;
    proc->fd_list[(int) reg->ret] = file_desc;
  }
  return PROCESS_CONTINUE;
}

static int syscall_socket_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;

  socket_arg_t arg = &sysarg->socket;
  arg->ret = reg->ret;
  arg->domain = (int) reg->arg1;
  arg->type = (int) reg->arg2;
  arg->protocol = (int) reg->arg3;

  if (strace_option)
    print_socket_syscall(pid, sysarg);
  process_socket_call(pid, sysarg);
  return PROCESS_CONTINUE;
}

static int syscall_shutdown_post(pid_t pid, reg_s * reg, syscall_arg_u * sysarg, process_descriptor_t * proc)
{
  proc->in_syscall = 0;
  shutdown_arg_t arg = &(sysarg->shutdown);
  arg->fd = reg->arg1;
  arg->how = reg->arg2;
  arg->ret = reg->ret;

  if (strace_option)
    print_shutdown_syscall(pid, sysarg);
  process_shutdown_call(pid, sysarg);
  return PROCESS_CONTINUE;
}


/** @brief Handle all syscalls of the tracked pid until it does a blocking action.
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

int process_handle(process_descriptor_t * proc, int status)
{
  reg_s arg;
  syscall_arg_u *sysarg = &(proc->sysarg);
  pid_t pid = proc->pid;
  XBT_DEBUG("PROCESS HANDLE");
  while (1) {
    ptrace_get_register(pid, &arg);
    int state;
    int ret;
    switch (arg.reg_orig) {

    case SYS_read:
      if (!(proc->in_syscall))
        ret = syscall_read_pre(pid, &arg, sysarg, proc, &state);
      else
        ret = syscall_read_post(pid, &arg, sysarg, proc);
      if (ret != PROCESS_CONTINUE)
        return ret;
      break;

    case SYS_write:
      if (!(proc->in_syscall))
        ret = syscall_write_pre(pid, &arg, sysarg, proc, &state);
      else
        ret = syscall_write_post(pid, &arg, sysarg, proc);
      if (ret != PROCESS_CONTINUE)
        return ret;
      break;

    case SYS_open:
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
        state = -1;
        ret = syscall_pre(pid, proc, &state); // FIXME: simplify the ret and the state
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_open_post(pid, &arg, sysarg, proc);
      break;

    case SYS_close:
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
        state = -1;
        ret = syscall_pre(pid, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else {
        proc->in_syscall = 0;
        //XBT_DEBUG("[%d] close(%ld) = %ld",pid, arg.arg1,arg.ret);
        process_close_call(proc, (int) arg.arg1);
      }
      break;

      // ignore SYS_stat, SYS_fstat, SYS_lstat

    case SYS_poll:
      if (!(proc->in_syscall)) {
        ret = syscall_poll_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else {
        proc->in_syscall = 0;
        THROW_IMPOSSIBLE;
      }
      break;

      // ignore SYS_lseek, SYS_mmap, SYS_mprotect, SYS_munmap, SYS_rt_sigaction, SYS_rt_sigprocmask, SYS_rt_sigreturn,
      // SYS_ioctl, SYS_pread64, SYS_pwrite64 , SYS_readv, SYS_writev, SYS_access, SYS_pipe

    case SYS_select:
      if (!(proc->in_syscall))
        syscall_select_pre(pid, &arg, sysarg, proc, &state);
      else {
        proc->in_syscall = 0;
        THROW_IMPOSSIBLE;
      }
      break;

      // ignore SYS_sched_yield, SYS_mremap, SYS_msync, SYS_mincore, SYS_madvise, SYS_shmget, SYS_shmat, SYS_shmctl
      // SYS_dup, SYS_dup2, SYS_pause, SYS_nanosleep, SYS_getitimer, SYS_alarm, SYS_setitimer, SYS_getpid, SYS_sendfile

    case SYS_socket:
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
        state = -1;
        ret = syscall_pre(pid, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_socket_post(pid, &arg, sysarg, proc);
      break;

    case SYS_connect:
      if (!(proc->in_syscall)) {
        ret = syscall_connect_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_connect_post(pid, &arg, sysarg, proc);
      break;

    case SYS_accept:
      if (!(proc->in_syscall)) {
        ret = syscall_accept_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_accept_post(pid, &arg, sysarg, proc);
      break;

    case SYS_sendto:
      if (!(proc->in_syscall))
        ret = syscall_sendto_pre(pid, &arg, sysarg, proc, &state);
      else
        ret = syscall_sendto_post(pid, &arg, sysarg, proc);
      if (ret != PROCESS_CONTINUE)
        return ret;
      break;

    case SYS_recvfrom:
      if (!(proc->in_syscall))
        ret = syscall_recvfrom_pre(pid, &arg, sysarg, proc, &state);
      else
        ret = syscall_recvfrom_post(pid, &arg, sysarg, proc);
      if (ret != PROCESS_CONTINUE)
        return ret;
      break;

    case SYS_sendmsg:
      if (!(proc->in_syscall))
        ret = syscall_sendmsg_pre(pid, &arg, sysarg, proc, &state);
      else
        ret = syscall_sendmsg_post(pid, &arg, sysarg, proc);
      if (ret != PROCESS_CONTINUE)
        return ret;
      break;

    case SYS_recvmsg:
      if (!(proc->in_syscall))
        ret = syscall_recvmsg_pre(pid, &arg, sysarg, proc, &state);
      else
        ret = syscall_recvmsg_post(pid, &arg, sysarg, proc);
      if (ret != PROCESS_CONTINUE)
        return ret;
      break;

    case SYS_shutdown:
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
        state = -1;
        ret = syscall_pre(pid, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_shutdown_post(pid, &arg, sysarg, proc);
      break;

    case SYS_bind:
      if (!(proc->in_syscall)) {
        int ret = syscall_bind_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else {
        syscall_bind_post(pid, &arg, sysarg, proc);
      }
      break;

    case SYS_listen:
      if (!(proc->in_syscall)) {
        ret = syscall_listen_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_listen_post(pid, &arg, sysarg, proc);
      break;

      // ignore SYS_getsockname

    case SYS_getpeername:
      if (!(proc->in_syscall)) {
        ret = syscall_getpeername_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        proc->in_syscall = 0;
      break;

      // ignore SYS_socketpair

    case SYS_setsockopt:
      if (!(proc->in_syscall)) {
        ret = syscall_setsockopt_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_setsockopt_post(pid, &arg, sysarg, proc);
      break;

    case SYS_getsockopt:
      if (!(proc->in_syscall)) {
        ret = syscall_getsockopt_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_getsockopt_post(pid, &arg, sysarg, proc);
      break;

      // ignore SYS_clone, SYS_fork, SYS_vfork, SYS_execve

    case SYS_exit:
      if (!(proc->in_syscall)) {
        XBT_DEBUG("exit(%ld) called", arg.arg1);
        return syscall_exit_pre(pid, &arg, sysarg, proc, &state);
      } else
        proc->in_syscall = 0;
      break;

      // ignore SYS_wait4, SYS_kill, SYS_uname, SYS_semget, SYS_semop, SYS_semctl, SYS_shmdt, SYS_msgget, SYS_msgsnd, SYS_msgrcv, SYS_msgctl

    case SYS_fcntl:
      if (!(proc->in_syscall)) {
        ret = syscall_fcntl_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_fcntl_post(pid, &arg, sysarg, proc);
      break;

      // ignore SYS_flock, SYS_fsync, SYS_fdatasync, SYS_truncate, SYS_ftruncate, SYS_getdents
      // ignore SYS_getcwd, SYS_chdir, SYS_fchdir, SYS_rename, SYS_mkdir, SYS_rmdir

    case SYS_creat:
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
        state = -1;
        ret = syscall_pre(pid, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        syscall_creat_post(pid, &arg, sysarg, proc);
      break;

      // ignore SYS_link, SYS_unlink, SYS_symlink, SYS_readlink, SYS_chmod, SYS_fchmod, SYS_chown, SYS_fchown, SYS_lchown, SYS_umask

    case SYS_gettimeofday:
      if (!(proc->in_syscall)) {
        int ret = syscall_gettimeofday_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else {
        proc->in_syscall = 0;
      }
      break;

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

    case SYS_time:
      if (!(proc->in_syscall)) {
        int ret = syscall_time_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else {
        proc->in_syscall = 0;
      }
      break;

      // ignore SYS_futex, SYS_sched_setaffinity, SYS_sched_getaffinity, SYS_set_thread_area, SYS_io_setup, SYS_io_destroy, SYS_io_getevents,
      // SYS_io_submit, SYS_io_cancel, SYS_get_thread_area, SYS_lookup_dcookie, SYS_epoll_create, SYS_epoll_ctl_old,
      // SYS_epoll_wait_old, SYS_remap_file_pages, SYS_getdents64, SYS_set_tid_address, SYS_restart_syscall, SYS_semtimedop,
      // SYS_fadvise64, SYS_timer_create, SYS_timer_settime, SYS_timer_gettime, SYS_timer_getoverrun, SYS_timer_delete, SYS_clock_settime

    case SYS_clock_gettime:
      if (!(proc->in_syscall)) {
        ret = syscall_clock_gettime_pre(pid, &arg, sysarg, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        proc->in_syscall = 0;
      break;

      // ignore SYS_clock_getres, SYS_clock_nanosleep

    case SYS_exit_group:
      if (!(proc->in_syscall)) {
        XBT_DEBUG("exit_group(%ld) called", arg.arg1);
        return syscall_exit_pre(pid, &arg, sysarg, proc, &state);
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
      XBT_INFO("Ignoring unhandled syscall (%ld) %s = %ld", arg.reg_orig, syscall_list[arg.reg_orig], arg.ret);
      if (!(proc->in_syscall)) {
        proc->in_syscall = 1;
        state = -1;
        ret = syscall_pre(pid, proc, &state);
        if (ret != PROCESS_CONTINUE)
          return ret;
      } else
        proc->in_syscall = 0;
      break;
    }

    // Step the traced process
    ptrace_resume_process(pid);
    waitpid(pid, &status, 0);
  }                             // while(1)

  THROW_IMPOSSIBLE;             //There's no way to quit the loop
  return 0;
}
