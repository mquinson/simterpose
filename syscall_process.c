#include "syscall_process.h"
#include "syscall_data.h"
#include "insert_trace.h"
#include "sockets.h"
#include "run_trace.h"
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
#include "syscall_list.h"

#include <time.h>
#include <linux/futex.h>

#define SYSCALL_ARG1 rdi
//#define DEBUG

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, ST, "Syscall process log");

int process_accept_in_call(pid_t pid, syscall_arg_u* sysarg);
int process_recv_in_call(int pid, int fd);
void process_recvfrom_out_call(int pid);
void process_read_out_call(pid_t pid);
void process_recvmsg_out_call(pid_t pid);
void process_accept_out_call(pid_t pid, syscall_arg_u* sysarg);



//TODO test the possibility to remove incomplete checking
//There is no need to return value because send always bring a task
int process_send_call(int pid, syscall_arg_u* sysarg)
{
  send_arg_t arg = &(sysarg->send);
  if (socket_registered(pid,arg->sockfd) != -1) {
    if (!socket_netlink(pid,arg->sockfd))
    {
	XBT_DEBUG("%d This is not a netlink socket", arg->sockfd);
      calculate_computation_time(pid);
      struct infos_socket *is = get_infos_socket(pid,arg->sockfd);
      struct infos_socket *s = comm_get_peer(is);
	XBT_DEBUG("[%d] %d->%d", pid, arg->sockfd, arg->ret);
	XBT_DEBUG("Sending data(%d) on socket %d", arg->ret, s->fd.fd);
      int peer_stat = process_get_state(s->fd.proc);
      if(peer_stat == PROC_SELECT || peer_stat == PROC_POLL || peer_stat == PROC_RECV_IN)
        add_to_sched_list(s->fd.proc->pid);
      
      handle_new_send(is,  sysarg);

      SD_task_t task = create_send_communication_task(pid, is, arg->ret);

      schedule_comm_task(is->fd.proc->station, s->fd.proc->station, task);
      is->fd.proc->on_simulation = 1;
      return 1;
    }
    return 0;
  }
  else 
    THROW_IMPOSSIBLE;
}

int process_recv_call(int pid, syscall_arg_u* sysarg)
{

  recv_arg_t arg = &(sysarg->recv);
	XBT_DEBUG("Entering process recv call %d", arg->ret);
  if (socket_registered(pid,arg->sockfd) != -1) {
    if (!socket_netlink(pid,arg->sockfd))
    {
      calculate_computation_time(pid);
      
      //if handle_new_receive return 1, there is a task found
      if(handle_new_receive(pid, sysarg))
        return PROCESS_TASK_FOUND;
      else
      {
        struct infos_socket* is = get_infos_socket(pid, arg->sockfd);
        int sock_status = socket_get_state(is);
        if(sock_status & SOCKET_CLOSED)
          return RECV_CLOSE;
        
        return PROCESS_NO_TASK_FOUND;
      }
    }
  }
  else
    THROW_IMPOSSIBLE;
  
  return 0;
}

int process_fork_call(int pid)
{
  THROW_UNIMPLEMENTED;
  return 1;
}


int process_select_call(pid_t pid)
{
	XBT_DEBUG("Entering select");
  process_descriptor *proc= process_get_descriptor(pid);
  select_arg_t arg = &(proc->sysarg.select);
  int i;
  
  fd_set fd_rd, fd_wr, fd_ex;
  
  fd_rd = arg->fd_read;
  fd_wr = arg->fd_write;
  fd_ex = arg->fd_except;
  
  int match = 0;
  
  for(i=0 ; i < arg->maxfd ; ++i)
  {
    struct infos_socket* is = get_infos_socket(pid, i);
    //if i is NULL that means that i is not a socket
    if(is == NULL)
    {
      FD_CLR(i, &(fd_rd));
      FD_CLR(i, &(fd_wr));
      continue;
    }

    int sock_status = socket_get_state(is);
    if(FD_ISSET(i, &(fd_rd)))
    {
      if(sock_status & SOCKET_READ_OK || sock_status & SOCKET_CLOSED || sock_status & SOCKET_SHUT)
        ++match;
      else
        FD_CLR(i, &(fd_rd));
    }
    if(FD_ISSET(i, &(fd_wr)))
    {
      if(sock_status & SOCKET_WR_NBLK && !(sock_status & SOCKET_CLOSED) && !(sock_status & SOCKET_SHUT))
        ++match;
      else
        FD_CLR(i, &(fd_wr));
    }
    if(FD_ISSET(i, &(fd_ex)))
    {
      XBT_WARN("Mediation for exception states on socket are not support yet");
    }
  }
  if(match > 0)
  {
	XBT_DEBUG("match for select");
    arg->fd_read = fd_rd;
    arg->fd_write = fd_wr;
    arg->fd_except = fd_ex;
    arg->ret = match;
    sys_build_select(pid, match);
#ifdef DEBUG
   	print_select_syscall(pid, &(proc->sysarg));
#endif
    return match;
  }
  
  if(proc->in_timeout == PROC_TIMEOUT_EXPIRE)
  {
	XBT_DEBUG("Timeout for select");
    
    FD_ZERO(&fd_rd);
    FD_ZERO(&fd_wr);
    FD_ZERO(&fd_ex);
    arg->ret=0;
    arg->fd_read = fd_rd;
    arg->fd_write = fd_wr;
    arg->fd_except = fd_ex;
    sys_build_select(pid, 0);
#ifdef DEBUG
	print_select_syscall(pid, &(proc->sysarg));
#endif
    proc->in_timeout = PROC_NO_TIMEOUT;
    return 1;
  }
  return 0;
}


int process_poll_call(pid_t pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
  
	XBT_DEBUG("Entering poll %lf %p\n", SD_get_clock(), proc->timeout);
  poll_arg_t arg = (poll_arg_t)&(proc->sysarg.poll);
  
  int match=0;
  int i;
  
  for(i=0; i < arg->nbfd; ++i)
  {
    struct pollfd *temp = &(arg->fd_list[i]);
    
    struct infos_socket *is = get_infos_socket(pid, temp->fd);
    if(is == NULL)
      continue;
    else
    {
      int sock_status = socket_get_state(is);
	XBT_DEBUG( "%d-> %d\n", temp->fd, sock_status);
      if(temp->events & POLLIN)
      {
        if(sock_status & SOCKET_READ_OK || sock_status & SOCKET_CLOSED)
        {
          temp->revents = temp->revents | POLLIN;
          ++match;
        }
        else
        {
          temp->revents = temp->revents & ~POLLIN;
        }
      }
      else if(temp->events & POLLOUT)
      {
	XBT_DEBUG("POLLOUT\n");
        if(sock_status & SOCKET_WR_NBLK)
        {
          temp->revents = temp->revents | POLLOUT;
          ++match;
        }
        else
        {
          temp->revents = temp->revents & ~POLLOUT;
        }
      }
      else
        XBT_WARN("Mediation different than POLLIN are not handle for poll\n");
    }
  }
  if(match > 0)
  {
	XBT_DEBUG("Result for poll\n");
    sys_build_poll(pid, match);
#ifdef DEBUG
	print_poll_syscall(pid, &(proc->sysarg));
#endif
    free(proc->sysarg.poll.fd_list);
    return match;
  }
  if(proc->in_timeout == PROC_TIMEOUT_EXPIRE)
  {
	XBT_DEBUG("Time out on poll\n");
    sys_build_poll(pid, 0);
#ifdef DEBUG
	print_poll_syscall(pid, &(proc->sysarg));
#endif
    free(proc->sysarg.poll.fd_list);
    proc->in_timeout = PROC_NO_TIMEOUT;
    return 1;
  }
  return match;
}

void process_getpeername_call(pid_t pid, syscall_arg_u *sysarg)
{
  getpeername_arg_t arg = &(sysarg->getpeername);
  
  if(socket_registered(pid, arg->sockfd))
  {
    if(socket_network(pid, arg->sockfd))
    {
      struct infos_socket *is = get_infos_socket(pid,arg->sockfd);
      struct sockaddr_in in;
      socklen_t size=0;
      if(!comm_getpeername(is, &in, &size))
      {
        if(size < arg->len)
          arg->len = size;
        arg->in = in;
        arg->ret=0;
      }
      else
        arg->ret=-107;
      
      ptrace_neutralize_syscall(pid);
      process_set_out_syscall(process_get_descriptor(pid));
      sys_build_getpeername(pid, sysarg);
#ifdef DEBUG
	print_getpeername_syscall(pid, sysarg);
#endif
    }
  }
}


int process_handle_active(pid_t pid)
{
  int status;
  process_descriptor* proc = process_get_descriptor(pid);
  int proc_state = process_get_state(proc);
  
  if(proc_state & PROC_SELECT)
  {
    //if the select match changment we have to run the child
    if(process_select_call(pid))
    {
      if(proc->timeout != NULL)
        remove_timeout(pid);
      process_reset_state(proc);
    }
    else
      return PROCESS_ON_MEDIATION;
  }
  else if(proc_state & PROC_POLL)
  {
    if(process_poll_call(pid))
    {
      if(proc->timeout != NULL)
        remove_timeout(pid);
      process_reset_state(proc);
    }
    else
      return PROCESS_ON_MEDIATION;
  }
  else if(proc_state & PROC_CONNECT)
  {
    return PROCESS_ON_MEDIATION;
  }
#ifdef address_translation
  else if(proc_state & PROC_CONNECT_DONE)
  {
    waitpid(pid, &status, 0);
    return process_handle(pid, status);
  }
#endif
  else if(proc_state & PROC_ACCEPT_IN)
  {
    pid_t conn_pid = process_accept_in_call(pid, &proc->sysarg);
    if(conn_pid)
      add_to_sched_list(conn_pid); //We have to add conn_pid to the schedule list
    else
      return PROCESS_ON_MEDIATION;
  }
  else if(proc_state & PROC_RECVFROM_OUT)
    process_recvfrom_out_call(pid);
  
  else if(proc_state & PROC_READ_OUT)
    process_read_out_call(pid);
  
  else if(proc_state == PROC_RECVFROM_IN)
#ifndef address_translation
    THROW_IMPOSSIBLE;
#else
    if(process_recv_in_call(pid, proc->sysarg.recv.sockfd))
      process_reset_state(proc);
    else
      return PROCESS_ON_MEDIATION;
#endif

  else if(proc_state == PROC_READ_IN)
#ifndef address_translation
    THROW_IMPOSSIBLE;
#else
    if(process_recv_in_call(pid, proc->sysarg.recv.sockfd))
      process_reset_state(proc);
    else
      return PROCESS_ON_MEDIATION;
#endif
    
  
  else if(proc_state == PROC_RECVMSG_IN)
#ifndef address_translation
    THROW_IMPOSSIBLE;
#else
    if(process_recv_in_call(pid, proc->sysarg.recv.sockfd))
      process_reset_state(proc);
    else
      return PROCESS_ON_MEDIATION;
#endif
    

  else if(proc_state & PROC_RECVMSG_OUT)
    process_recvmsg_out_call(pid);
  
  ptrace_resume_process(pid);
  
  if(waitpid(pid, &status, 0) < 0)
  {
    XBT_ERROR(" [%d] waitpid %s %d\n", pid, strerror(errno), errno);
    exit(1);
  }
  return process_handle( pid, status);
}


int process_recv_in_call(int pid, int fd)
{
  process_descriptor *proc = process_get_descriptor(pid);
	XBT_DEBUG("[%d]Trying to see if socket %d recv something", pid, fd);
  if(proc->fd_list[fd]==NULL)
    return 0;
  
  if(!socket_network(pid, fd))
#ifndef address_translation
    return 0;
#else
    return 1;
#endif

  int status = comm_get_socket_state(get_infos_socket(pid, fd));
	XBT_DEBUG("socket status %d %d", status, status & SOCKET_READ_OK || status & SOCKET_CLOSED);
  return (status & SOCKET_READ_OK || status & SOCKET_CLOSED || status & SOCKET_SHUT);
}

void process_recvfrom_out_call(int pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
//   recvfrom_arg_t arg = &(proc->sysarg.recvfrom);
  //   XBT_ERROR("[%d]Try to see if socket %d recv something\n", pid, fd);
//   if(proc->fd_list[arg->sockfd]==NULL)
//     return;
//   
//   if(!socket_network(pid, arg->sockfd))
//     return;
  
  process_reset_state(proc);
//   print_recvfrom_syscall(pid, &(proc->sysarg));
  sys_build_recvfrom(pid, &(proc->sysarg));
  
}

void process_read_out_call(pid_t pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
//   read_arg_t arg = &(proc->sysarg.read);
  process_reset_state(proc);
  sys_build_read(pid, &(proc->sysarg));
}

void process_recvmsg_out_call(pid_t pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
  sys_build_recvmsg(pid, &(proc->sysarg));
  process_reset_state(proc);
}


//Return 0 if nobody wait or the pid of the one who wait
int process_accept_in_call(pid_t pid, syscall_arg_u* sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  process_descriptor* proc = process_get_descriptor(pid);
  //We try to find here if there's a connection to accept
  if(comm_has_connect_waiting(get_infos_socket(pid, arg->sockfd)))
  {
    struct sockaddr_in in;
    pid_t conn_pid = comm_accept_connect(get_infos_socket(pid, arg->sockfd), &in);
    arg->sai = in;
    
//     struct in_addr in2 = {arg->sai.sin_addr.s_addr};
//     XBT_DEBUG("Accept connection from %s:%d\n", inet_ntoa(in2), arg->sai.sin_port);
    process_descriptor* conn_proc = process_get_descriptor(conn_pid);
    
    int conn_state = process_get_state(conn_proc);
    if(conn_state & PROC_CONNECT)
    {
#ifndef address_translation
      add_to_sched_list(conn_pid);
      process_reset_state(conn_proc);
#else
      ptrace_resume_process(conn_pid);
      add_to_sched_list(conn_pid);
      process_set_state(conn_proc, PROC_CONNECT_DONE);
#endif
    }
    
#ifndef address_translation
    //Now we rebuild the syscall.
    int new_fd = ptrace_record_socket(pid);

    arg->ret = new_fd;
    ptrace_neutralize_syscall(pid);
    process_set_out_syscall(proc);
    sys_build_accept(pid, sysarg);
    
    process_accept_out_call(pid, sysarg);
//     print_accept_syscall(pid, sysarg);
#endif
    
    return conn_pid;
  }
  else
  {
    process_set_state(proc, PROC_ACCEPT_IN);
    return 0;
  }
}

void process_accept_out_call(pid_t pid, syscall_arg_u* sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  
  process_descriptor *proc = process_get_descriptor(pid);
  if(arg->ret >= 0)
  {
    int domain = get_domain_socket(pid, arg->sockfd);
    int protocol=get_protocol_socket(pid, arg->sockfd);
    
    struct infos_socket* is = register_socket(pid, arg->ret, domain, protocol);
#ifdef address_translation
    sys_translate_accept(pid, sysarg);
#endif
    comm_join_on_accept(is, pid, arg->sockfd);
    
    struct infos_socket *s = get_infos_socket(pid, arg->sockfd);
    register_port(proc->station, s->port_local);
    
    struct in_addr in;
    if(s->ip_local == 0)
    {
      struct infos_socket *temp = is->comm->info[0].socket;

      if(temp->ip_local == inet_addr("127.0.0.1"))
        in.s_addr = inet_addr("127.0.0.1");
      else
        in.s_addr = get_ip_of_station(proc->station);
    }
    else
      in.s_addr = s->ip_local;
    
    set_localaddr_port_socket(pid, arg->ret, inet_ntoa(in), s->port_local);
    
  }
  
  process_reset_state(proc);
}

void process_shutdown_call(pid_t pid, syscall_arg_u* sysarg)
{
  shutdown_arg_t arg = &(sysarg->shutdown);
  struct infos_socket *is = get_infos_socket(pid, arg->fd);
  if(is == NULL)
    return;
  comm_shutdown(is);
}


int process_handle_idle(pid_t pid)
{
	XBT_DEBUG("Handle idling process %d\n", pid);
  int status;
  if(waitpid(pid, &status, WNOHANG))
    return process_handle( pid, status);
  else
    return PROCESS_IDLE_STATE;
}

// int process_clone_call(pid_t pid, reg_s *arg)
// {
//   unsigned long tid = arg->ret;
//   unsigned long flags = arg->arg1;
//   
//   //Now create new process in model
//   process_clone(tid, pid, flags);
//   
//   //Now add it to the launching time table to be the next process to be launch
//   set_next_launchment(tid);
//   
//   int status;
//   
//   //wait for clone
//   waitpid(tid, &status, 0);
//   ptrace_resume_process(tid);
//   //place process to te first call after clone
//   waitpid(tid, &status, 0);
//   process_set_in_syscall(tid);
//   
//   return 0;
// }


int process_connect_in_call(pid_t pid, syscall_arg_u *sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  int domain = get_domain_socket(pid, arg->sockfd);
  
  if(domain == 2)//PF_INET
  {
    process_descriptor *proc = process_get_descriptor(pid);
    struct sockaddr_in *sai = &(arg->sai);
    
    SD_workstation_t station;
    int device;
    struct in_addr in;
    
    if(sai->sin_addr.s_addr == inet_addr("127.0.0.1"))
    {
      in.s_addr = inet_addr("127.0.0.1");
      device = PORT_LOCAL;
      station = proc->station;
    }
    else
    {
      in.s_addr = get_ip_of_station(proc->station);
      device = PORT_REMOTE;
      station = get_station_by_ip(sai->sin_addr.s_addr);
      if(station == NULL)
      {
        arg->ret = -ECONNREFUSED;
      ptrace_neutralize_syscall(pid);
      process_set_out_syscall(process_get_descriptor(pid));
      sys_build_connect(pid, sysarg);
      return 0;
      }
    }
    
    //We ask for a connection on the socket
    int acc_pid = comm_ask_connect(station, ntohs(sai->sin_port), pid, arg->sockfd, device);
    
    //if the processus waiting for connection, we add it to schedule list
    if(acc_pid)
    {
      process_descriptor *acc_proc = process_get_descriptor(acc_pid);
      int status = process_get_state(acc_proc);
      if(status == PROC_ACCEPT_IN || status == PROC_SELECT || status == PROC_POLL)
        add_to_sched_list(acc_pid);
// #ifndef address_translation
      //Now attribute ip and port to the socket.
      int port = get_random_port(proc->station);
      
	XBT_DEBUG("New socket %s:%d", inet_ntoa(in), port);
      set_localaddr_port_socket(pid, arg->sockfd, inet_ntoa(in), port);
      register_port(proc->station, port);
// #endif
	XBT_DEBUG("Free port found on station %s (%s:%d)",SD_workstation_get_name(proc->station), inet_ntoa(in),  port);
    }
    else
    {
	XBT_DEBUG("No peer found");
      arg->ret = -ECONNREFUSED;
      ptrace_neutralize_syscall(pid);
      process_set_out_syscall(process_get_descriptor(pid));
      sys_build_connect(pid, sysarg);
      return 0;
    }
#ifndef address_translation
    //Now we try to see if the socket is blocking of not
    int flags = socket_get_flags(pid, arg->sockfd);
    if(flags & O_NONBLOCK)
      arg->ret = -115;
    else
      arg->ret = 0;
      
    ptrace_neutralize_syscall(pid);
    process_set_out_syscall(process_get_descriptor(pid));
    sys_build_connect(pid, sysarg);
    //now mark the process as waiting for conn
    
    if(flags & O_NONBLOCK)
      return 0;

    process_set_state(proc, PROC_CONNECT);
    return 1;
#else
    sys_translate_connect_in(pid, sysarg);
    int flags = socket_get_flags(pid, arg->sockfd);
    if(flags & O_NONBLOCK)
      return 0;
    
    //now mark the process as waiting for conn
      process_set_state(proc, PROC_CONNECT);
      return 1;
#endif
  }
  else
    return 0;
}

void process_connect_out_call(pid_t pid, syscall_arg_u *sysarg)
{
  process_descriptor *proc = process_get_descriptor(pid);
#ifdef address_translation
  connect_arg_t arg = &(sysarg->connect);
  
  int domain = get_domain_socket(pid, arg->sockfd);
  if(domain ==2 && arg->ret >= 0)
  {
    struct infos_socket* is = get_infos_socket(pid, arg->sockfd);
    
    sys_translate_connect_out(pid, sysarg);
    int port = socket_get_local_port(pid, arg->sockfd);
    set_real_port(proc->station, is->port_local, ntohs(port));
    add_new_translation(ntohs(port), is->port_local, get_ip_of_station(proc->station));
  }
#endif
  process_reset_state(proc);
}

int process_bind_call(pid_t pid, syscall_arg_u *sysarg)
{
  bind_arg_t arg = &(sysarg->bind);

  if(socket_registered(pid, arg->sockfd))
  {
    if(socket_network(pid, arg->sockfd))
    {

      process_descriptor *proc = process_get_descriptor(pid);

      if(!is_port_in_use(proc->station, ntohs(arg->sai.sin_port)))
      {
	XBT_DEBUG("Port %d is free", ntohs(arg->sai.sin_port));
        register_port(proc->station, ntohs(arg->sai.sin_port));
        
        struct infos_socket *is = get_infos_socket(pid, arg->sockfd);
        int device=0;
        if(arg->sai.sin_addr.s_addr == INADDR_ANY)
          device = (PORT_LOCAL | PORT_REMOTE);
        else if(arg->sai.sin_addr.s_addr == inet_addr("127.0.0.1"))
          device = PORT_LOCAL;
        else
          device = PORT_REMOTE;

        set_port_on_binding(proc->station, ntohs(arg->sai.sin_port), is, device);
        
        is->binded = 1;
        
        set_localaddr_port_socket(pid,arg->sockfd,inet_ntoa(arg->sai.sin_addr),ntohs(arg->sai.sin_port));
        arg->ret=0;
#ifdef address_translation
        int port = ptrace_find_free_binding_port(pid);
	XBT_DEBUG("Free port found %d", port);
        process_set_out_syscall(proc);
        set_real_port(proc->station, ntohs(arg->sai.sin_port), port);
        add_new_translation(port, ntohs(arg->sai.sin_port), get_ip_of_station(proc->station));
        return 0;
#endif
      }
      else
      {
	XBT_DEBUG("Port %d isn't free", ntohs(arg->sai.sin_port));
        arg->ret=-98;
        ptrace_neutralize_syscall(pid);
        sys_build_bind(pid, sysarg);
        process_set_out_syscall(process_get_descriptor(pid));
        return 0;
      }
#ifndef address_translation
      ptrace_neutralize_syscall(pid);
      sys_build_bind(pid, sysarg);
      process_set_out_syscall(process_get_descriptor(pid));
#endif
    }
  }
  return 0;
}

int process_socket_call(pid_t pid, syscall_arg_u *arg)
{
  socket_arg_t sock = &(arg->socket);
  if (sock->ret>0) 
    register_socket(pid,sock->ret,sock->domain,sock->protocol);
  return 0;
}

void process_setsockopt_syscall(pid_t pid, syscall_arg_u *sysarg)
{
  setsockopt_arg_t arg = &(sysarg->setsockopt);
  //TODO real gestion of setsockopt with warn
  arg->ret=0;
 
  if(arg->optname == SO_REUSEADDR)
    socket_set_option(pid, arg->sockfd, SOCK_OPT_REUSEADDR, *((int*)arg->optval));
  else
    XBT_WARN("Option non supported by Simterpose.");
  
  
  ptrace_neutralize_syscall(pid);
  sys_build_setsockopt(pid, sysarg);
  process_set_out_syscall(process_get_descriptor(pid));
}


void process_getsockopt_syscall(pid_t pid, syscall_arg_u *sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  
  arg->ret = 0;
  if(arg->optname == SO_REUSEADDR)
  {
    arg->optlen = sizeof(int);
    arg->optval = malloc(arg->optlen);
    *((int*)arg->optval)=socket_get_option(pid, arg->sockfd, SOCK_OPT_REUSEADDR);
  }
  else
  {
    XBT_WARN("Option non supported by Simterpose.");
    arg->optlen = 0;
    arg->optval = NULL;
  }
  
  ptrace_neutralize_syscall(pid);
  sys_build_getsockopt(pid, sysarg);
  free(arg->optval);
  process_set_out_syscall(process_get_descriptor(pid));
}


int process_listen_call(pid_t pid, syscall_arg_u* sysarg)
{
  //TODO make gestion of back_log
  listen_arg_t arg = &(sysarg->listen);
  struct infos_socket* is = get_infos_socket(pid, arg->sockfd);
  comm_t comm = comm_new(is);
  comm_set_listen(comm);
  
#ifndef address_translation
  arg->ret=0;
  ptrace_neutralize_syscall(pid);
  sys_build_listen(pid, sysarg);
  process_set_out_syscall(process_get_descriptor(pid));
#endif
  
  return 0;
}

void process_fcntl_call(pid_t pid, syscall_arg_u* sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  
  switch(arg->cmd)
  {
    case F_SETFL:
      socket_set_flags(pid, arg->fd , arg->arg);
      return;
      break;
    
    default:
      return;
      break;
  }
#ifndef address_translation
  ptrace_neutralize_syscall(pid);
  sys_build_fcntl(pid, sysarg);
  process_set_out_syscall(process_get_descriptor(pid));
#endif
}

void process_close_call(pid_t pid, int fd)
{
  process_descriptor *proc = process_get_descriptor(pid);
  fd_s *file_desc = proc->fd_list[fd];
  if(file_desc->type == FD_SOCKET)
    socket_close(pid, fd);
  else
  {
    free(file_desc);
    proc->fd_list[fd] = NULL;
  }
}



int process_handle_mediate(pid_t pid)
{
	XBT_DEBUG("process_handle_mediate");
  process_descriptor *proc = process_get_descriptor(pid);
  int state = process_get_state(proc);
  
  if(state & PROC_RECVFROM_IN)
  {
	XBT_DEBUG("receive_mediate");
    if(process_recv_in_call(pid, proc->sysarg.recvfrom.sockfd))
    {
#ifndef address_translation
      int res = process_recv_call(pid, &(proc->sysarg));
      if(res == PROCESS_TASK_FOUND)
      {
#ifdef DEBUG
	print_recvfrom_syscall(pid, &(proc->sysarg));
#endif
        ptrace_neutralize_syscall(pid);
        process_set_out_syscall(proc);
        process_end_mediation(proc);
        return PROCESS_TASK_FOUND;
      }
      else if(res == RECV_CLOSE)
      {
#ifdef DEBUG
	print_recvfrom_syscall(pid, &(proc->sysarg));
#endif
        ptrace_neutralize_syscall(pid);
        process_set_out_syscall(proc);
        return process_handle_active(pid);
      }
#else
        process_end_mediation(proc);
        process_reset_state(proc);
        return process_handle_active(pid);
#endif
    }
  }
  
  else if(state & PROC_READ_IN)
  {
    if(process_recv_in_call(pid, proc->sysarg.recvfrom.sockfd))
    {
#ifndef address_translation
      int res = process_recv_call(pid, &(proc->sysarg));
      if(res == PROCESS_TASK_FOUND)
      {
#ifdef DEBUG
	print_recvfrom_syscall(pid, &(proc->sysarg));
#endif
        ptrace_neutralize_syscall(pid);
        process_set_out_syscall(proc);
        process_end_mediation(proc);
        return PROCESS_TASK_FOUND;
      }
      else if(res == RECV_CLOSE)
      {
#ifdef DEBUG
        print_recvfrom_syscall(pid, &(proc->sysarg));
#endif
        ptrace_neutralize_syscall(pid);
        process_set_out_syscall(proc);
        return process_handle_active(pid);
      }
#else
      process_end_mediation(proc);
      process_reset_state(proc);
      return process_handle_active(pid);
#endif
    }
  }
  
  else if(state & PROC_RECVMSG_IN)
  {

    if(process_recv_in_call(pid, proc->sysarg.recvmsg.sockfd))
    {
#ifndef address_translation
      int res = process_recv_call(pid, &(proc->sysarg));
      if(res == PROCESS_TASK_FOUND)
      {
#ifdef DEBUG
	print_recvfrom_syscall(pid, &(proc->sysarg));
#endif
        ptrace_neutralize_syscall(pid);
        process_set_out_syscall(proc);
        process_end_mediation(proc);
        return PROCESS_TASK_FOUND;
      }
      else if(res == RECV_CLOSE)
      {
#ifdef DEBUG
	print_recvfrom_syscall(pid, &(proc->sysarg));
#endif
        ptrace_neutralize_syscall(pid);
        process_set_out_syscall(proc);
        return process_handle_active(pid);
      }
#else
      process_end_mediation(proc);
      process_reset_state(proc);
      return process_handle_active(pid);
#endif
    }
  }
  
  return PROCESS_ON_MEDIATION;
}



int process_handle(pid_t pid, int stat)
{

  int status = stat;
  reg_s arg;
  process_descriptor *proc = process_get_descriptor(pid);
  syscall_arg_u *sysarg = &(proc->sysarg);
  while(1)
  {
    if (process_in_syscall(proc)==0) {
      process_set_in_syscall(proc);

      ptrace_get_register(pid, &arg);
XBT_DEBUG("New in %s", syscall_list[arg.reg_orig]);
      
      int state = -1;
      switch(arg.reg_orig){
        case SYS_read:
        {
          get_args_read(pid, &arg, sysarg);
          if (socket_registered(pid, arg.arg1) != -1) {
            if(!process_recv_in_call(pid, arg.arg1))
            {
#ifndef address_translation
              int flags = socket_get_flags(pid, arg.arg1);
              if(flags & O_NONBLOCK)
              {
                sysarg->read.ret=-11;
//                 print_read_syscall(pid, sysarg);
                ptrace_neutralize_syscall(pid);
                process_set_out_syscall(proc);
                process_read_out_call(pid);
              }
              else
              {
                process_set_state(proc, PROC_READ);
                process_on_mediation(proc);
                state = PROCESS_ON_MEDIATION;
              }
            }
            else
            {
              int res = process_recv_call(pid, sysarg);
              if(res == PROCESS_TASK_FOUND)
              {
//                 print_read_syscall(pid, sysarg);
                ptrace_neutralize_syscall(pid);
                process_set_out_syscall(proc);
                process_set_state(proc, PROC_READ);
                return PROCESS_TASK_FOUND;
              }
              else
              {
                if( res == RECV_CLOSE)
                  sysarg->read.ret=0;
//                 print_read_syscall(pid, sysarg);
                ptrace_neutralize_syscall(pid);
                process_set_out_syscall(proc);
                process_read_out_call(pid);
              }
#else 
              int flags = socket_get_flags(pid, arg.arg1);
              if(!(flags & O_NONBLOCK))
              {
                process_set_state(proc, PROC_READ);
                state =  PROCESS_ON_MEDIATION;
                process_on_mediation(proc);
              }
              
#endif
            }
          }
        }
        break;

#ifndef address_translation
        case SYS_write:
          get_args_write(pid, &arg, sysarg);
          if (socket_registered(pid, sysarg->write.fd) != -1) {
            if(process_send_call(pid, sysarg))
            {
              ptrace_neutralize_syscall(pid);
              sys_build_sendto(pid, sysarg);
//               print_write_syscall(pid, sysarg);
              process_set_out_syscall(proc);
              return PROCESS_TASK_FOUND;
            }
          }
          break;
#endif
          
        case SYS_poll:
        {
          get_args_poll(pid, &arg, sysarg);
//           print_poll_syscall(pid, sysarg);
          process_descriptor* proc = process_get_descriptor(pid);
          if(sysarg->poll.timeout >=0)
            add_timeout(pid, sysarg->poll.timeout + SD_get_clock());
          else
            proc->in_timeout = 1;
          ptrace_neutralize_syscall(pid);
          process_set_out_syscall(proc);
          process_set_state(proc, PROC_POLL);
          state =  PROCESS_ON_MEDIATION;
        }
        break;
        
        case SYS_exit_group:
        {
	XBT_DEBUG("[%d] exit_group(%ld) called",pid, arg.arg1);
          ptrace_detach_process(pid);
          return PROCESS_DEAD;
        }
        break;
        
        case SYS_exit:
        {
	XBT_DEBUG("[%d] exit(%ld) called", pid, arg.arg1);
          ptrace_detach_process(pid);
          return PROCESS_DEAD;
        }
        break;
        
        case SYS_time:
	  get_args_time(pid, &arg, sysarg);
	  //	  print_time_syscall(pid, sysarg);
          ptrace_neutralize_syscall(pid);
          sysarg->time.ret = get_simulated_timestamp(); // (time_t)25; //
          sys_build_time(pid, sysarg);
	  process_set_out_syscall(proc);
          break;

      case SYS_gettimeofday:

	get_args_gettimeofday(pid, &arg, sysarg);
	//	print_gettimeofday_syscall(pid, sysarg);
	ptrace_neutralize_syscall(pid);
	sys_build_gettimeofday(pid, sysarg);
	process_set_out_syscall(proc);
	break;	

        case SYS_futex:
        {
	XBT_DEBUG("[%d] futex_in %p %d", pid, (void*)arg.arg4, arg.arg2 == FUTEX_WAIT);
          //TODO add real gestion of timeout
          if(arg.arg2 == FUTEX_WAIT)
          {
            ptrace_resume_process(pid);
            return PROCESS_IDLE_STATE;
          }
        }
        break;
        
        
        case SYS_getpeername:
          get_args_getpeername(pid, &arg, sysarg);
          process_getpeername_call(pid, sysarg);
          break;
          
          
#ifndef address_translation
        case SYS_listen:
          get_args_listen(pid, &arg, sysarg);
          process_listen_call(pid, sysarg);
//           print_listen_syscall(pid, sysarg);
          break;
#endif
          
// #ifndef address_translation
        case SYS_bind:
	XBT_DEBUG("[%d] bind", pid);
          get_args_bind_connect(pid, 0, &arg, sysarg);
          process_bind_call(pid, sysarg);    
#ifdef DEBUG     
	print_bind_syscall(pid, sysarg);
#endif
          break;
// #endif
        
        case SYS_connect:
        {
	XBT_DEBUG("New connection");
	XBT_DEBUG("[%d] connect_in", pid);
          get_args_bind_connect(pid, 0, &arg, sysarg);
#ifdef DEBUG
           print_connect_syscall(pid, sysarg);
#endif
          if(process_connect_in_call(pid, sysarg))
            state = PROCESS_ON_MEDIATION;
        }
        break;
        
        case SYS_accept:
        {
	XBT_DEBUG("[%d] accept_in", pid);
          get_args_accept(pid, &arg, sysarg);
#ifdef DEBUG
           print_accept_syscall(pid, sysarg);
#endif
          pid_t conn_pid = process_accept_in_call(pid, sysarg);
          if(!conn_pid)
            state =  PROCESS_ON_MEDIATION;
        }
        break;
        
#ifndef address_translation
        case SYS_getsockopt:
          get_args_getsockopt(pid, &arg, sysarg);
          process_getsockopt_syscall(pid, sysarg);
//           print_getsockopt_syscall(pid, sysarg);
          break;
#endif
         
#ifndef address_translation
        case SYS_setsockopt:
          get_args_setsockopt(pid, &arg, sysarg);
          process_setsockopt_syscall(pid, sysarg);
//           print_setsockopt_syscall(pid, sysarg);
          free(sysarg->setsockopt.optval);
          break;
#endif
        
#ifndef address_translation
        case SYS_fcntl:
          get_args_fcntl(pid, &arg, sysarg);
//           print_fcntl_syscall(pid, sysarg);
          process_fcntl_call(pid, sysarg);
          break;
#endif
          
        case SYS_select:
        {
          get_args_select(pid,&arg, sysarg);
//           print_select_syscall(pid, sysarg);
          process_descriptor* proc = process_get_descriptor(pid);
          if(sysarg->select.timeout >=0)
            add_timeout(pid, sysarg->select.timeout + SD_get_clock());
          else
            proc->in_timeout = 1;
          ptrace_neutralize_syscall(pid);
          process_set_out_syscall(proc);
          process_set_state(proc, PROC_SELECT);
          state =  PROCESS_ON_MEDIATION;
        }
        break;
        
        case SYS_recvfrom:
        {
	XBT_DEBUG("recvfrom_in");
          get_args_recvfrom(pid, &arg, sysarg);
#ifdef address_translation
          if (socket_registered(pid, arg.arg1) != -1) {
            if(socket_network(pid, arg.arg1))
            {
              sys_translate_recvfrom_in(pid, sysarg);
            }
          } 
#endif
  //        XBT_ERROR("[%d] Seeing if %d receive something\n", pid, (int)arg.arg1);
          if(!process_recv_in_call(pid, sysarg->recvfrom.sockfd))
          {
#ifndef address_translation
            int flags = socket_get_flags(pid, arg.arg1);
            if(flags & O_NONBLOCK)
            {
              sysarg->recvfrom.ret=-11;
//               print_recvfrom_syscall(pid, sysarg);
              ptrace_neutralize_syscall(pid);
              process_set_out_syscall(proc);
              process_recvmsg_out_call(pid);
            }
            else
            {
              process_set_state(proc, PROC_RECVFROM);
              process_on_mediation(proc);
              state = PROCESS_ON_MEDIATION;
            }
          }
          else
          {
            int res = process_recv_call(pid, sysarg);
            if(res == PROCESS_TASK_FOUND)
            {
              ptrace_neutralize_syscall(pid);
              process_set_out_syscall(proc);
              process_set_state(proc, PROC_RECVFROM);
              return PROCESS_TASK_FOUND;
            }
            else
            {
              if(res == RECV_CLOSE)
                sysarg->recvfrom.ret=0;
//               print_recvfrom_syscall(pid, sysarg);
              ptrace_neutralize_syscall(pid);
              process_set_out_syscall(proc);
              process_recvfrom_out_call(pid);
            }
#else
            int flags = socket_get_flags(pid, arg.arg1);
            if(!(flags & O_NONBLOCK))
            {
              process_set_state(proc, PROC_RECVFROM);
              state = PROCESS_ON_MEDIATION;
              process_on_mediation(proc);
            }
            
#endif
          }
        }
        break;
        
#ifndef address_translation
        case SYS_sendmsg:
          get_args_sendmsg(pid, &arg, sysarg);
          if(process_send_call(pid, sysarg))
          {
            ptrace_neutralize_syscall(pid);
            sys_build_sendmsg(pid, sysarg);
//             print_sendmsg_syscall(pid, sysarg);
            process_set_out_syscall(proc);
            return PROCESS_TASK_FOUND;
          }
          break;
#endif
        
        case SYS_recvmsg:
        {
          get_args_recvmsg(pid, &arg, sysarg);
          
          if(!process_recv_in_call(pid, sysarg->recvmsg.sockfd))
          {
#ifndef address_translation
            if(socket_registered(pid, sysarg->recvmsg.sockfd))
              if(!socket_network(pid, sysarg->recvmsg.sockfd))
                break;
            
            int flags = socket_get_flags(pid, arg.arg1);
            if(flags & O_NONBLOCK)
            {
              sysarg->recvmsg.ret=-11;
//               print_read_syscall(pid, sysarg);
              ptrace_neutralize_syscall(pid);
              process_set_out_syscall(proc);
              process_recvmsg_out_call(pid);
            }
            else
            {
              process_set_state(proc, PROC_RECVMSG);
              process_on_mediation(proc);
              state = PROCESS_ON_MEDIATION;
            }
          }
          else
          {
            int res = process_recv_call(pid, sysarg);
            if(res == PROCESS_TASK_FOUND)
            {
              ptrace_neutralize_syscall(pid);
              process_set_out_syscall(proc);
              process_set_state(proc, PROC_RECVMSG);
              return PROCESS_TASK_FOUND;
            }
            else
            {
              if(res == RECV_CLOSE)
                sysarg->recvfrom.ret=0;
//               print_read_syscall(pid, sysarg);
              ptrace_neutralize_syscall(pid);
              process_set_out_syscall(proc);
              process_recvmsg_out_call(pid);
            }
#else
            int flags = socket_get_flags(pid, arg.arg1);
            if(!(flags & O_NONBLOCK))
            {
              process_set_state(proc, PROC_RECVMSG);
              state = PROCESS_ON_MEDIATION;
              process_on_mediation(proc);
            }
#endif
          
          }
        }
        break;
        
        case SYS_sendto:
          get_args_sendto(pid, &arg, sysarg);
#ifndef address_translation
          if(process_send_call(pid, sysarg))
          {

	XBT_DEBUG("process_handle -> PROCESS_TASK_FOUND");
            ptrace_neutralize_syscall(pid);
            sys_build_sendto(pid, sysarg);
#ifdef DEBUG
            print_sendto_syscall(pid, sysarg);
#endif
            process_set_out_syscall(proc);
            return PROCESS_TASK_FOUND;
          }
          print_sendto_syscall(pid, sysarg);
#else
          if (socket_registered(pid, arg.arg1) != -1) {
            if(socket_network(pid, arg.arg1))
            {
              sys_translate_sendto_in(pid, sysarg);
            }
          }
#endif
          break;
      }
      //No verify if we have compuation task to simulate.
      if(calculate_computation_time(pid))
      {
        //if we have computation to simulate
        schedule_computation_task(pid);
        process_on_simulation(proc, 1);
        state = PROCESS_ON_COMPUTATION;
      }
      if(state >= 0)
        return state;
    }
    else
    {
      process_set_out_syscall(proc);
      ptrace_get_register(pid, &arg);
      switch (arg.reg_orig) {
        
        case SYS_write:
          get_args_write(pid, &arg, sysarg);
//           print_write_syscall(pid, sysarg);
#ifdef address_translation
          if((int)arg.ret > 0)
          {
            if (socket_registered(pid, sysarg->write.fd) != -1) {
              if(process_send_call(pid, sysarg))
                return PROCESS_TASK_FOUND;
            }
          }
  
#endif
          break;

        case SYS_read:
          get_args_read(pid, &arg, sysarg);
//           print_read_syscall(pid, sysarg);
#ifdef address_translation
          if((int)arg.ret > 0)
          {
            if (socket_registered(pid, sysarg->read.fd) != -1) {
              if(process_recv_call(pid, sysarg) == PROCESS_TASK_FOUND)
                return PROCESS_TASK_FOUND;
            }
          }
#endif
          break;

        case SYS_fork: 
          THROW_UNIMPLEMENTED;//Fork are not handle yet
          break;
          
        case SYS_poll:
          THROW_IMPOSSIBLE;
          break;
          
        case SYS_open:
        {
//           printf("[%d] open(\"...\",", pid);
//           switch (arg.arg2) {
//             case 0: printf("O_RDONLY"); break;
//             case 1: printf("O_WRONLY"); break;
//             case 2: printf("O_RDWR"); break;
//             default :printf("no_flags");break;
//           }    
//           printf(") = %ld\n", arg.ret);
          if((int)arg.ret >= 0)
          {
            fd_s *file_desc = malloc(sizeof(fd_s));
            file_desc->fd=(int)arg.ret;
            file_desc->proc=proc;
            file_desc->type = FD_CLASSIC;
            proc->fd_list[(int)arg.ret]=file_desc;
          }
        }
        break;
        
        case SYS_creat:
        {
          if((int)arg.ret >= 0)
          {
            fd_s *file_desc = malloc(sizeof(fd_s));
            file_desc->fd=(int)arg.ret;
            file_desc->proc=proc;
            file_desc->type = FD_CLASSIC;
            proc->fd_list[(int)arg.ret]=file_desc;
          }
        }
        break;
        
        case SYS_clone:
          THROW_UNIMPLEMENTED;
          if(arg.ret < MAX_PID)
          {
            process_clone_call(pid, &arg);
            return PROCESS_IDLE_STATE;
          }
          else
            process_set_in_syscall(proc);
          break;
          
        case SYS_close: 
	//XBT_DEBUG("[%d] close(%ld) = %ld",pid, arg.arg1,arg.ret);
          process_close_call(pid, (int)arg.arg1);
          break;
          
        case SYS_dup:
		XBT_DEBUG("[%d] dup(%ld) = %ld",pid,arg.arg1,arg.ret);
	THROW_UNIMPLEMENTED; //Dup are not handle yet
          break;
          
        case SYS_dup2:
	XBT_DEBUG("[%d] dup2(%ld, %ld) = %ld", pid, arg.arg1, arg.arg2, arg.ret);
	//    THROW_UNIMPLEMENTED; //Dup are not handle yet
          break;
          
        case SYS_execve:
	XBT_DEBUG("[%d] execve called", pid);
          THROW_UNIMPLEMENTED; //
          break;
              
              
        case SYS_fcntl:
          get_args_fcntl(pid, &arg, sysarg);
#ifdef DEBUG
	print_fcntl_syscall(pid, sysarg);
#endif
#ifdef address_translation
          process_fcntl_call(pid, sysarg);
#endif
          break;
          
          
        case SYS_select: 
          THROW_IMPOSSIBLE;
          break;
          
        case SYS_socket: 
          get_args_socket(pid, &arg, sysarg);
#ifdef DEBUG
	print_socket_syscall(pid, sysarg);
#endif
          process_socket_call(pid, sysarg);
          break;
          
        case SYS_bind:
          get_args_bind_connect(pid, 0, &arg, sysarg);
#ifdef DEBUG
	print_bind_syscall(pid, sysarg);
#endif
          break;
          
        case SYS_connect:
          get_args_bind_connect(pid, 1, &arg, sysarg);
#ifdef DEBUG
	print_connect_syscall(pid, sysarg);
#endif
#ifdef address_translation
          process_connect_out_call(pid, sysarg);
          process_reset_state(proc);
#endif
          break;
          
        case SYS_accept:
          get_args_accept(pid, &arg, sysarg);
#ifdef address_translation
          process_accept_out_call(pid, sysarg);
#endif
#ifdef DEBUG
	print_accept_syscall(pid, sysarg);
#endif
          break;
          
        case SYS_listen:
#ifdef address_translation
          get_args_listen(pid, &arg, sysarg);
          process_listen_call(pid, sysarg);
//           print_listen_syscall(pid, sysarg);
#else
          THROW_IMPOSSIBLE;
#endif
          break;
              
        case SYS_sendto:
          get_args_sendto(pid, &arg, sysarg);
//           print_sendto_syscall(pid, sysarg);
#ifdef address_translation
          
          if (socket_registered(pid, arg.arg1) != -1) {
            if(socket_network(pid, arg.arg1))
            {
              sys_translate_sendto_out(pid, sysarg);
            }
          }
          if((int)arg.ret > 0)
          {
            if(process_send_call(pid, sysarg))
              return PROCESS_TASK_FOUND;
          }
#endif
          break;
          
        case SYS_recvfrom:
          get_args_recvfrom(pid, &arg, sysarg);
//           print_recvfrom_syscall(pid, sysarg);
#ifdef address_translation
          
          if (socket_registered(pid, arg.arg1) != -1) {
            if(socket_network(pid, arg.arg1))
            {
              sys_translate_recvfrom_out(pid, sysarg);
            }
          }
          if(arg.ret > 0)
          {
            if(process_recv_call(pid, sysarg) == PROCESS_TASK_FOUND)
              return PROCESS_TASK_FOUND;
          }
#endif
          break;
          
        case SYS_sendmsg:
          get_args_sendmsg(pid, &arg, sysarg);
//           print_sendmsg_syscall(pid, sysarg);
#ifdef address_translation
          if(arg.ret > 0)
          {
            if(process_send_call(pid, sysarg))
              return PROCESS_TASK_FOUND;
          }
#endif
          break;
          
        case SYS_recvmsg:
          get_args_recvmsg(pid, &arg, sysarg);
//           print_recvmsg_syscall(pid, sysarg);
#ifdef address_translation
          if(arg.ret > 0)
          {
          if(process_recv_call(pid, sysarg) == PROCESS_TASK_FOUND)
            return PROCESS_TASK_FOUND;
          }
#endif
          break;
          
        case SYS_shutdown:
          get_args_shutdown(pid, &arg, sysarg);
//           print_shutdown_syscall(pid, sysarg);
          process_shutdown_call(pid, sysarg);
          break;
              
        case SYS_getsockopt:
          get_args_getsockopt(pid, &arg, sysarg);
//           print_getsockopt_syscall(pid, sysarg);
          break;
          
        case SYS_setsockopt:
          get_args_setsockopt(pid, &arg, sysarg);
//           print_setsockopt_syscall(pid, sysarg);
          break;
                
        
        default :
	//XBT_DEBUG("[%d] Unhandle syscall (%ld) %s = %ld", pid,arg.reg_orig, syscall_list[arg.reg_orig], arg.ret);
          break;
            
      }
    }
	//XBT_DEBUG("Resume syscall");
    ptrace_resume_process(pid);
    
    //waitpid sur le fils
    waitpid(pid, &status, 0);
  }
  
  THROW_IMPOSSIBLE; //There's no way to quit the loop
  
  return 0;
}
