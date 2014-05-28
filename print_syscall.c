#include "print_syscall.h"
#include "sysdep.h"
#include "sockets.h"
#include "simterpose.h"

#include <stdio.h>


void print_accept_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  accept_arg_t arg = &(sysarg->accept);

  int domain = get_domain_socket(pid, arg->sockfd);
  // fprintf(stderr,"[%d] accept(", pid);
  fprintf(stderr, "accept(");

  fprintf(stderr, "%d, ", arg->sockfd);

  if (domain == 2) {            // PF_INET
    fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
            inet_ntoa(arg->sai.sin_addr));
  } else if (domain == 1) {     //PF_UNIX
    fprintf(stderr, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
  } else if (domain == 16) {    //PF_NETLINK
    fprintf(stderr, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
  } else {
    fprintf(stderr, "{sockaddr unknown}, ");
  }

  fprintf(stderr, "%d", arg->addrlen);
  fprintf(stderr, ") = %d\n", arg->ret);
}


void print_connect_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  connect_arg_t arg = &(sysarg->connect);

  int domain = get_domain_socket(pid, arg->sockfd);

  // fprintf(stderr,"[%d] connect(", pid);
  fprintf(stderr, "connect(");
  fprintf(stderr, "%d, ", arg->sockfd);

  if (domain == 2) {
    fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
            inet_ntoa(arg->sai.sin_addr));
  } else if (domain == 1) {     //PF_UNIX
    fprintf(stderr, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
  } else if (domain == 16) {    //PF_NETLINK
    fprintf(stderr, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
  } else {
    fprintf(stderr, "{sockaddr unknown}, ");
  }
  fprintf(stderr, "%d", arg->addrlen);
  fprintf(stderr, ") = %d\n", arg->ret);
}


void print_bind_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  bind_arg_t arg = &(sysarg->bind);
  int domain = get_domain_socket(pid, arg->sockfd);

  // fprintf(stderr,"[%d] bind(", pid);
  fprintf(stderr, "bind(");
  fprintf(stderr, "%d, ", arg->sockfd);

  if (domain == 2) {
    fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
            inet_ntoa(arg->sai.sin_addr));
  } else if (domain == 1) {     //PF_UNIX
    fprintf(stderr, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
  } else if (domain == 16) {    //PF_NETLINK
    fprintf(stderr, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
  } else {
    fprintf(stderr, "{sockaddr unknown}, ");
  }
  fprintf(stderr, "%d", arg->addrlen);
  fprintf(stderr, ") = %d\n", arg->ret);
}



void print_socket_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  socket_arg_t arg = &(sysarg->socket);

  // fprintf(stderr,"[%d] socket(",pid);
  fprintf(stderr, "socket(");
  switch (arg->domain) {
  case 0:
    fprintf(stderr, "PF_UNSPEC, ");
    break;
  case 1:
    fprintf(stderr, "PF_UNIX, ");
    break;
  case 2:
    fprintf(stderr, "PF_INET, ");
    switch (arg->type) {
    case 1:
      fprintf(stderr, "SOCK_STREAM, ");
      break;
    case 2:
      fprintf(stderr, "SOCK_DGRAM, ");
      break;
    case 3:
      fprintf(stderr, "SOCK_RAW, ");
      break;
    case 4:
      fprintf(stderr, "SOCK_RDM, ");
      break;
    case 5:
      fprintf(stderr, "SOCK_SEQPACKET, ");
      break;
    case 6:
      fprintf(stderr, "SOCK_DCCP, ");
      break;
    case 10:
      fprintf(stderr, "SOCK_PACKET, ");
      break;
    default:
      fprintf(stderr, "TYPE UNKNOWN (%d), ", arg->type);
      break;
    }
    switch (arg->protocol) {
    case 0:
      fprintf(stderr, "IPPROTO_IP");
      break;
    case 1:
      fprintf(stderr, "IPPROTO_ICMP");
      break;
    case 2:
      fprintf(stderr, "IPPROTO_IGMP");
      break;
    case 3:
      fprintf(stderr, "IPPROTO_GGP");
      break;
    case 6:
      fprintf(stderr, "IPPROTO_TCP");
      break;
    case 17:
      fprintf(stderr, "IPPROTO_UDP");
      break;
    case 132:
      fprintf(stderr, "IPPROTO_STCP");
      break;
    case 255:
      fprintf(stderr, "IPPROTO_RAW");
      break;
    default:
      fprintf(stderr, "PROTOCOL UNKNOWN (%d)", arg->protocol);
      break;
    }
    break;
  case 16:
    fprintf(stderr, "PF_NETLINK, ");
    switch (arg->type) {
    case 1:
      fprintf(stderr, "SOCK_STREAM, ");
      break;
    case 2:
      fprintf(stderr, "SOCK_DGRAM, ");
      break;
    case 3:
      fprintf(stderr, "SOCK_RAW, ");
      break;
    case 4:
      fprintf(stderr, "SOCK_RDM, ");
      break;
    case 5:
      fprintf(stderr, "SOCK_SEQPACKET, ");
      break;
    case 6:
      fprintf(stderr, "SOCK_DCCP, ");
      break;
    case 10:
      fprintf(stderr, "SOCK_PACKET, ");
      break;
    default:
      fprintf(stderr, "TYPE UNKNOWN (%d), ", arg->type);
      break;
    }
    switch (arg->protocol) {
    case 0:
      fprintf(stderr, "NETLINK_ROUTE");
      break;
    case 1:
      fprintf(stderr, "NETLINK_UNUSED");
      break;
    case 2:
      fprintf(stderr, "NETLINK_USERSOCK");
      break;
    case 3:
      fprintf(stderr, "NETLINK_FIREWALL");
      break;
    case 4:
      fprintf(stderr, "NETLINK_INET_DIAG");
      break;
    default:
      fprintf(stderr, "PROTOCOL UNKNOWN (%d)", arg->protocol);
      break;
    }
    break;
  default:
    fprintf(stderr, "DOMAIN UNKNOWN (%d), ", arg->domain);
    break;
  }
  fprintf(stderr, ") = %d\n", arg->ret);
}


void print_getsockopt_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  // fprintf(stderr,"[%d] getsockopt(", pid);
  fprintf(stderr, "getsockopt(");
  fprintf(stderr, "%d, ", arg->sockfd);

  switch (arg->level) {
  case 0:
    fprintf(stderr, "SOL_IP, ");
    switch (arg->optname) {
    case 1:
      fprintf(stderr, "IP_TOS, ");
      break;
    case 2:
      fprintf(stderr, "IP_TTL, ");
      break;
    case 3:
      fprintf(stderr, "IP_HDRINCL, ");
      break;
    case 4:
      fprintf(stderr, "IP_OPTIONS, ");
      break;
    case 6:
      fprintf(stderr, "IP_RECVOPTS, ");
      break;
    default:
      fprintf(stderr, "OPTION UNKNOWN (%d), ", arg->optname);
      break;
    }
    break;
  case 1:
    fprintf(stderr, "SOL_SOCKET, ");
    switch (arg->optname) {
    case 1:
      fprintf(stderr, "SO_DEBUG, ");
      break;
    case 2:
      fprintf(stderr, "SO_REUSEADDR, ");
      break;
    case 3:
      fprintf(stderr, "SO_TYPE, ");
      break;
    case 4:
      fprintf(stderr, "SO_ERROR, ");
      break;
    case 5:
      fprintf(stderr, "SO_DONTROUTE, ");
      break;
    case 6:
      fprintf(stderr, "SO_BROADCAST, ");
      break;
    case 7:
      fprintf(stderr, "SO_SNDBUF, ");
      break;
    case 8:
      fprintf(stderr, "SO_RCVBUF, ");
      break;
    case 9:
      fprintf(stderr, "SO_SNDBUFFORCE, ");
      break;
    case 10:
      fprintf(stderr, "SO_RCVBUFFORCE, ");
      break;
    case 11:
      fprintf(stderr, "SO_NO_CHECK, ");
      break;
    case 12:
      fprintf(stderr, "SO_PRIORITY, ");
      break;
    case 13:
      fprintf(stderr, "SO_LINGER, ");
      break;
    case 14:
      fprintf(stderr, "SO_BSDCOMPAT, ");
      break;
    case 15:
      fprintf(stderr, "SO_REUSEPORT, ");
      break;
    default:
      fprintf(stderr, "OPTION UNKNOWN (%d), ", arg->optname);
      break;
    }
    break;
  case 41:
    fprintf(stderr, "SOL_IPV6, ");
    break;
  case 58:
    fprintf(stderr, "SOL_ICMPV6, ");
    break;
  default:
    fprintf(stderr, "PROTOCOL UNKNOWN (%d), ", arg->level);
    break;
  }

  fprintf(stderr, "%d ) = ", arg->optlen);

  fprintf(stderr, "%d\n", (int) arg->ret);
}

void print_setsockopt_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  getsockopt_arg_t arg = &(sysarg->setsockopt);
  // fprintf(stderr,"[%d] setsockopt(", pid);
  fprintf(stderr, "setsockopt(");
  fprintf(stderr, "%d, ", arg->sockfd);

  switch (arg->level) {
  case 0:
    fprintf(stderr, "SOL_IP, ");
    switch (arg->optname) {
    case 1:
      fprintf(stderr, "IP_TOS, ");
      break;
    case 2:
      fprintf(stderr, "IP_TTL, ");
      break;
    case 3:
      fprintf(stderr, "IP_HDRINCL, ");
      break;
    case 4:
      fprintf(stderr, "IP_OPTIONS, ");
      break;
    case 6:
      fprintf(stderr, "IP_RECVOPTS, ");
      break;
    default:
      fprintf(stderr, "OPTION UNKNOWN (%d), ", arg->optname);
      break;
    }
    break;
  case 1:
    fprintf(stderr, "SOL_SOCKET, ");
    switch (arg->optname) {
    case 1:
      fprintf(stderr, "SO_DEBUG, ");
      break;
    case 2:
      fprintf(stderr, "SO_REUSEADDR, ");
      break;
    case 3:
      fprintf(stderr, "SO_TYPE, ");
      break;
    case 4:
      fprintf(stderr, "SO_ERROR, ");
      break;
    case 5:
      fprintf(stderr, "SO_DONTROUTE, ");
      break;
    case 6:
      fprintf(stderr, "SO_BROADCAST, ");
      break;
    case 7:
      fprintf(stderr, "SO_SNDBUF, ");
      break;
    case 8:
      fprintf(stderr, "SO_RCVBUF, ");
      break;
    case 9:
      fprintf(stderr, "SO_SNDBUFFORCE, ");
      break;
    case 10:
      fprintf(stderr, "SO_RCVBUFFORCE, ");
      break;
    case 11:
      fprintf(stderr, "SO_NO_CHECK, ");
      break;
    case 12:
      fprintf(stderr, "SO_PRIORITY, ");
      break;
    case 13:
      fprintf(stderr, "SO_LINGER, ");
      break;
    case 14:
      fprintf(stderr, "SO_BSDCOMPAT, ");
      break;
    case 15:
      fprintf(stderr, "SO_REUSEPORT, ");
      break;
    default:
      fprintf(stderr, "OPTION UNKNOWN (%d), ", arg->optname);
      break;
    }
    break;
  case 41:
    fprintf(stderr, "SOL_IPV6, ");
    break;
  case 58:
    fprintf(stderr, "SOL_ICMPV6, ");
    break;
  default:
    fprintf(stderr, "PROTOCOL UNKNOWN (%d), ", arg->level);
    break;
  }

  fprintf(stderr, "%d ) = ", arg->optlen);

  fprintf(stderr, "%d\n", (int) arg->ret);
}

void print_listen_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  listen_arg_t arg = &(sysarg->listen);

  fprintf(stderr, "listen(");
  //  fprintf(stderr,"[%d] listen(", pid);
  fprintf(stderr, "%d, ", arg->sockfd);
  fprintf(stderr, "%d ", arg->backlog);
  fprintf(stderr, ") = %d\n", arg->ret);
}

static void print_flags_send(int flags)
{
  if (flags & MSG_CONFIRM)
    fprintf(stderr, " MSG_CONFIRM |");
  if (flags & MSG_DONTROUTE)
    fprintf(stderr, " MSG_DONTROUTE |");
  if (flags & MSG_DONTWAIT)
    fprintf(stderr, " MSG_DONTWAIT |");
  if (flags & MSG_EOR)
    fprintf(stderr, " MSG_EOR |");
  if (flags & MSG_MORE)
    fprintf(stderr, " MSG_MORE |");
  if (flags & MSG_NOSIGNAL)
    fprintf(stderr, " MSG_NOSIGNAL |");
  if (flags & MSG_OOB)
    fprintf(stderr, " MSG_OOB |");
  fprintf(stderr, ", ");
}


static void print_flags_recv(int flags)
{
  if (flags & MSG_DONTWAIT)
    fprintf(stderr, " MSG_DONTWAIT |");
  if (flags & MSG_ERRQUEUE)
    fprintf(stderr, " MSG_ERRQUEUE |");
  if (flags & MSG_PEEK)
    fprintf(stderr, " MSG_PEEK |");
  if (flags & MSG_OOB)
    fprintf(stderr, " MSG_OOB |");
  if (flags & MSG_TRUNC)
    fprintf(stderr, " MSG_TRUNC |");
  if (flags & MSG_WAITALL)
    fprintf(stderr, " MSG_WAITALL |");
  fprintf(stderr, ", ");
}


void print_recv_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  recv_arg_t arg = &(sysarg->recv);
  // fprintf(stderr,"[%d] recv(", pid);
  fprintf(stderr, "recv(");

  fprintf(stderr, "%d, ", arg->sockfd);
  fprintf(stderr, "%d ", (int) arg->len);

  if (arg->flags > 0) {
    print_flags_recv(arg->flags);
  } else
    fprintf(stderr, "0, ");

  fprintf(stderr, ") = %d\n", arg->ret);
}

void print_send_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  recv_arg_t arg = &(sysarg->send);
  // fprintf(stderr,"[%d] send( ", pid);
  fprintf(stderr, "send( ");

  fprintf(stderr, "%d, ", arg->sockfd);
  fprintf(stderr, "%d ", (int) arg->len);

  if (arg->flags > 0) {
    print_flags_send(arg->flags);
  } else
    fprintf(stderr, "0, ");

  fprintf(stderr, ") = %d\n", arg->ret);
}

void print_sendto_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  int domain = get_domain_socket(pid, arg->sockfd);

  // fprintf(stderr,"[%d] sendto(", pid);
  fprintf(stderr, "sendto(");
#ifndef address_translation
  char buff[200];
  if (arg->len < 200) {
    memcpy(buff, arg->data, arg->len);
    buff[arg->ret] = '\0';
    fprintf(stderr, "%d, \"%s\" , %d, ", arg->sockfd, buff, arg->len);
  } else {
    memcpy(buff, arg->data, 200);
    buff[199] = '\0';
    fprintf(stderr, "%d, \"%s...\" , %d, ", arg->sockfd, buff, arg->len);
  }
#else
  fprintf(stderr, "%d, \"...\" , %d, ", arg->sockfd, arg->len);
#endif
  if (arg->flags > 0) {
    print_flags_send(arg->flags);
  } else
    fprintf(stderr, "0, ");

  if (domain == 2) {            // PF_INET
    if (arg->is_addr) {
      fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
              inet_ntoa(arg->sai.sin_addr));
    } else
      fprintf(stderr, "NULL, ");
  } else if (domain == 1) {     //PF_UNIX
    if (arg->is_addr) {
      fprintf(stderr, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
    } else
      fprintf(stderr, "NULL, ");

  } else if (domain == 16) {    //PF_NETLINK
    if (arg->is_addr) {
      fprintf(stderr, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
    } else
      fprintf(stderr, "NULL, ");
  } else {
    fprintf(stderr, "{sockaddr unknown}, ");
  }

  fprintf(stderr, "%d", (int) arg->addrlen);

  fprintf(stderr, ") = %d\n", arg->ret);
}

void print_recvfrom_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  int domain = get_domain_socket(pid, arg->sockfd);

  // fprintf(stderr,"[%d] recvfrom(", pid);
  fprintf(stderr, "recvfrom(");
#ifndef address_translation
  if (arg->ret) {
    char buff[500];
    if (arg->ret <= 500) {
      memcpy(buff, arg->data, arg->ret);
      buff[arg->ret] = '\0';
      fprintf(stderr, "%d, \"%s\" , %d, ", arg->sockfd, buff, arg->len);
    } else {
      memcpy(buff, arg->data, 500);
      buff[499] = '\0';
      fprintf(stderr, "%d, \"%s...\" , %d, ", arg->sockfd, buff, arg->len);
    }

    if (arg->flags > 0) {
      print_flags_send(arg->flags);
    } else
      fprintf(stderr, "0, ");
  } else
    fprintf(stderr, "%d, \"\" , %d, ", arg->sockfd, arg->len);
#else
  fprintf(stderr, "%d, \"...\" , %d, ", arg->sockfd, arg->len);
#endif

  if (domain == 2) {            // PF_INET
    if (arg->is_addr) {
      fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", ntohs(arg->sai.sin_port),
              inet_ntoa(arg->sai.sin_addr));
    } else
      fprintf(stderr, "NULL, ");
  } else if (domain == 1) {     //PF_UNIX
    if (arg->is_addr) {
      fprintf(stderr, "{sa_family=AF_UNIX, sun_path=\"%s\"}, ", arg->sau.sun_path);
    } else
      fprintf(stderr, "NULL, ");

  } else if (domain == 16) {    //PF_NETLINK
    if (arg->is_addr) {
      fprintf(stderr, "{sa_family=AF_NETLINK, pid=%d, groups=%u}, ", arg->snl.nl_pid, arg->snl.nl_groups);
    } else
      fprintf(stderr, "NULL, ");
  } else {
    fprintf(stderr, "{sockaddr unknown}, ");
  }

  fprintf(stderr, "%d", (int) arg->addrlen);

  fprintf(stderr, ") = %d\n", arg->ret);
}

void print_recvmsg_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  recvmsg_arg_t arg = &(sysarg->sendmsg);

  //  fprintf(stderr,"[%d] recvmsg(", pid);
  fprintf(stderr, "recvmsg(");
  fprintf(stderr, "%d, ", arg->sockfd);

  fprintf(stderr, ", {msg_namelen=%d, msg_iovlen=%d, msg_controllen=%d, msg_flags=%d}, ", (int) arg->msg.msg_namelen,
          (int) arg->msg.msg_iovlen, (int) arg->msg.msg_controllen, arg->msg.msg_flags);

  if (arg->flags > 0) {
    print_flags_recv(arg->flags);
  } else
    fprintf(stderr, "0 ");

  fprintf(stderr, ") = %d\n", arg->ret);
}

void print_sendmsg_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  recvmsg_arg_t arg = &(sysarg->sendmsg);

  //  fprintf(stderr,"[%d] sendmsg(", pid);
  fprintf(stderr, "sendmsg(");
  fprintf(stderr, "%d, ", arg->sockfd);
#ifndef address_translation
  char buff[20];
  if (arg->len < 20) {
    memcpy(buff, arg->data, arg->len);
    fprintf(stderr, ", {msg_namelen=%d, msg_iovlen=%d, \"%s\", msg_controllen=%d, msg_flags=%d}, ",
            (int) arg->msg.msg_namelen, (int) arg->msg.msg_iovlen, buff, (int) arg->msg.msg_controllen,
            arg->msg.msg_flags);
  } else {
    memcpy(buff, arg->data, 20);
    buff[19] = '\0';

    fprintf(stderr, ", {msg_namelen=%d, msg_iovlen=%d, \"%s...\", msg_controllen=%d, msg_flags=%d}, ",
            (int) arg->msg.msg_namelen, (int) arg->msg.msg_iovlen, buff, (int) arg->msg.msg_controllen,
            arg->msg.msg_flags);
  }
#else
  fprintf(stderr, ", {msg_namelen=%d, msg_iovlen=%d, \"...\", msg_controllen=%d, msg_flags=%d}, ",
          (int) arg->msg.msg_namelen, (int) arg->msg.msg_iovlen, (int) arg->msg.msg_controllen, arg->msg.msg_flags);
#endif

  if (arg->flags > 0) {
    print_flags_recv(arg->flags);
  } else
    fprintf(stderr, "0 ");

  fprintf(stderr, ") = %d\n", arg->ret);
}



static void get_events_poll(short events)
{
  fprintf(stderr, "events=");
  if ((events & POLLIN) != 0)
    fprintf(stderr, "POLLIN |");
  if ((events & POLLPRI) != 0)
    fprintf(stderr, "POLLPRI |");
  if ((events & POLLOUT) != 0)
    fprintf(stderr, "POLLOUT |");
  if ((events & POLLERR) != 0)
    fprintf(stderr, "POLLERR |");
  if ((events & POLLHUP) != 0)
    fprintf(stderr, "POLLHUP |");
  if ((events & POLLNVAL) != 0)
    fprintf(stderr, "POLLNVAL |");
}

static void get_revents_poll(short revents)
{
  fprintf(stderr, ", revents=");
  if ((revents & POLLIN) != 0)
    fprintf(stderr, "POLLIN |");
  if ((revents & POLLPRI) != 0)
    fprintf(stderr, "POLLPRI |");
  if ((revents & POLLOUT) != 0)
    fprintf(stderr, "POLLOUT |");
  if ((revents & POLLERR) != 0)
    fprintf(stderr, "POLLERR |");
  if ((revents & POLLHUP) != 0)
    fprintf(stderr, "POLLHUP |");
  if ((revents & POLLNVAL) != 0)
    fprintf(stderr, "POLLNVAL |");
  fprintf(stderr, "} ");
}

static void disp_pollfd(struct pollfd *fds, int nfds)
{
  int i;
  for (i = 0; i < nfds - 1; i++) {
    fprintf(stderr, "{fd=%d, ", fds[i].fd);
    get_events_poll(fds[i].events);
    get_revents_poll(fds[i].revents);
    if (i > 3) {
      fprintf(stderr, " ... }");
      break;
    }
  }
  if (nfds < 3) {
    fprintf(stderr, "{fd=%d, ", fds[nfds - 1].fd);
    get_events_poll(fds[nfds - 1].events);
    get_revents_poll(fds[nfds - 1].revents);
  }

}

void print_poll_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  poll_arg_t arg = &(sysarg->poll);

  fprintf(stderr, "poll([");
  // fprintf(stderr,"[%d] poll([",pid);
  if (arg->fd_list != NULL)
    disp_pollfd(arg->fd_list, arg->nbfd);
  else
    fprintf(stderr, "NULL");
  fprintf(stderr, " ]");
  fprintf(stderr, "%lf) = %d\n", arg->timeout, arg->ret);
}

static void disp_fd(fd_set * fd)
{
  int i;
  fprintf(stderr, "[ ");
  for (i = 0; i < FD_SETSIZE; i++) {
    if (FD_ISSET(i, fd)) {
      fprintf(stderr, "%d ", i);
    }
  }
  fprintf(stderr, "]");
}

void print_select_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  select_arg_t arg = &(sysarg->select);
  // fprintf(stderr,"[%d] select(%d,", pid, arg->maxfd);
  fprintf(stderr, "select(%d,", arg->maxfd);

  if (arg->fd_state & SELECT_FDRD_SET)
    disp_fd(&arg->fd_read);
  else
    fprintf(stderr, "NULL");
  fprintf(stderr, ", ");
  if (arg->fd_state & SELECT_FDWR_SET)
    disp_fd(&arg->fd_write);
  else
    fprintf(stderr, "NULL");
  fprintf(stderr, ", ");
  if (arg->fd_state & SELECT_FDEX_SET)
    disp_fd(&arg->fd_except);
  else
    fprintf(stderr, "NULL");
  fprintf(stderr, ", ");

  fprintf(stderr, "%lf) = %d\n", arg->timeout, arg->ret);


}

void print_fcntl_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  //  fprintf(stderr,"[%d] fcntl( %d, ", pid, arg->fd);
  fprintf(stderr, "fcntl( %d, ", arg->fd);
  switch (arg->cmd) {
  case F_DUPFD:
    fprintf(stderr, "F_DUPFD");
    break;

  case F_DUPFD_CLOEXEC:
    fprintf(stderr, "F_DUPFD_CLOEXEC");
    break;

  case F_GETFD:
    fprintf(stderr, "F_GETFD");
    break;

  case F_SETFD:
    fprintf(stderr, "F_SETFD");
    break;

  case F_GETFL:
    fprintf(stderr, "F_GETFL");
    break;

  case F_SETFL:
    fprintf(stderr, "F_SETFL");
    break;

  case F_SETLK:
    fprintf(stderr, "F_SETLK");
    break;

  case F_SETLKW:
    fprintf(stderr, "F_SETLKW");
    break;

  case F_GETLK:
    fprintf(stderr, "F_GETLK");
    break;

  default:
    fprintf(stderr, "Unknown command");
    break;
  }
  fprintf(stderr, " , %d) = %d\n", arg->arg, arg->ret);
}

void print_read_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  read_arg_t arg = &(sysarg->read);
  //  fprintf(stderr,"[%d] read(%d, \"...\", %d) = %d\n", pid, arg->fd, arg->count, arg->ret);
  fprintf(stderr, "read(%d, \"...\", %d) = %d\n", arg->fd, arg->count, arg->ret);
}

void print_write_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  write_arg_t arg = &(sysarg->read);
  //  fprintf(stderr,"[%d] write(%d, \"...\", %d) = %d\n", pid, arg->fd, arg->count, arg->ret);
  fprintf(stderr, "write(%d, \"...\", %d) = %d\n", arg->fd, arg->count, arg->ret);
}

static void print_shutdown_option(int how)
{
  switch (how) {
  case 0:
    fprintf(stderr, "SHUT_RD");
    break;
  case 1:
    fprintf(stderr, "SHUT_WR");
    break;
  case 2:
    fprintf(stderr, "SHUT_RDWR");
    break;
  }
}

void print_shutdown_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  shutdown_arg_t arg = &(sysarg->shutdown);
  //  fprintf(stderr,"[%d] shutdown (%d, ", pid, arg->fd);
  fprintf(stderr, "shutdown (%d, ", arg->fd);
  print_shutdown_option(arg->how);
  fprintf(stderr, ") = %d\n", arg->ret);
}


void print_getpeername_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  getpeername_arg_t arg = &(sysarg->getpeername);
  //  fprintf(stderr,"[%d] getpeername (%d, ", pid, arg->sockfd);
  fprintf(stderr, "getpeername (%d, ", arg->sockfd);
  fprintf(stderr, "{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ", arg->in.sin_port,
          inet_ntoa(arg->in.sin_addr));
  fprintf(stderr, "%d ) = %d\n", arg->len, arg->ret);
}

void print_time_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  time_arg_t arg = &(sysarg->time);
  //fprintf(stderr,"[%d] time = %ld\n", pid, arg->ret);
  fprintf(stderr, "time = %ld\n", arg->ret);
}

void print_gettimeofday_syscall(pid_t pid, syscall_arg_u * sysarg)
{
  //gettimeofday_arg_t arg = &(sysarg->gettimeofday);
  //  fprintf(stderr,"[%d] gettimeofday, tv = %ld\n", pid, arg->tv);
  //fprintf(stderr, "gettimeofday, tv = %ld\n", arg->tv);
  THROW_UNIMPLEMENTED;
}
