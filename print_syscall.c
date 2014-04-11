#include "print_syscall.h"
#include "sysdep.h"
#include "sockets.h"
#include "run_trace.h"

#include <stdio.h>


void print_accept_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  
  int domain = get_domain_socket(pid,arg->sockfd);
  printf("[%d] accept(", pid);
  
  printf("%d, ",arg->sockfd);
  
  if (domain == 2 ) { // PF_INET
    printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",ntohs(arg->sai.sin_port),inet_ntoa(arg->sai.sin_addr));
  }
  else if (domain == 1) { //PF_UNIX
    printf("{sa_family=AF_UNIX, sun_path=\"%s\"}, ",arg->sau.sun_path);
  }
  else if (domain == 16) { //PF_NETLINK
    printf("{sa_family=AF_NETLINK, pid=%d, groups=%u}, ",arg->snl.nl_pid, arg->snl.nl_groups);
  } 
  else {
    printf("{sockaddr unknown}, ");
  }
  
  printf("%d",arg->addrlen);
  printf(") = %d\n", arg->ret);
}


void print_connect_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  connect_arg_t arg = &(sysarg->connect);
  
  int domain = get_domain_socket(pid,arg->sockfd);
  
  printf("[%d] connect(", pid);
  printf("%d, ",arg->sockfd);
  
  if (domain == 2 ) {
    printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",ntohs(arg->sai.sin_port),inet_ntoa(arg->sai.sin_addr));
  }
  else if (domain == 1) { //PF_UNIX
    printf("{sa_family=AF_UNIX, sun_path=\"%s\"}, ",arg->sau.sun_path);
  }
  else if (domain == 16) { //PF_NETLINK
    printf("{sa_family=AF_NETLINK, pid=%d, groups=%u}, ",arg->snl.nl_pid, arg->snl.nl_groups);
  } 
  else{
    printf("{sockaddr unknown}, ");
  }
  printf("%d",arg->addrlen);
  printf(") = %d\n", arg->ret);
}


void print_bind_syscall(pid_t pid, syscall_arg_u *sysarg)
{
  bind_arg_t arg = &(sysarg->bind);
  int domain = get_domain_socket(pid,arg->sockfd);
  
  printf("[%d] bind(", pid);
  printf("%d, ",arg->sockfd);
  
  if (domain == 2 ) {
    printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",ntohs(arg->sai.sin_port),inet_ntoa(arg->sai.sin_addr));
  }
  else if (domain == 1) { //PF_UNIX
    printf("{sa_family=AF_UNIX, sun_path=\"%s\"}, ",arg->sau.sun_path);
  }
  else if (domain == 16) { //PF_NETLINK
    printf("{sa_family=AF_NETLINK, pid=%d, groups=%u}, ",arg->snl.nl_pid, arg->snl.nl_groups);
  } 
  else{
    printf("{sockaddr unknown}, ");
  }
  printf("%d",arg->addrlen);
  printf(") = %d\n", arg->ret);
}



void print_socket_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  socket_arg_t arg = &(sysarg->socket);
  
  printf("[%d] socket(",pid);
  switch (arg->domain) {
    case 0: printf("PF_UNSPEC, "); break;
    case 1: printf("PF_UNIX, "); break;
    case 2: 
      printf("PF_INET, ");
      switch (arg->type) {
        case 1: printf("SOCK_STREAM, "); break;
        case 2: printf("SOCK_DGRAM, "); break;
        case 3: printf("SOCK_RAW, "); break;
        case 4: printf("SOCK_RDM, "); break;
        case 5: printf("SOCK_SEQPACKET, "); break;
        case 6: printf("SOCK_DCCP, "); break;
        case 10: printf("SOCK_PACKET, "); break;
        default : printf("TYPE UNKNOWN (%d), ",arg->type); break;
      }
      switch (arg->protocol) {
        case 0: printf("IPPROTO_IP"); break;
        case 1: printf("IPPROTO_ICMP"); break;
        case 2: printf("IPPROTO_IGMP"); break;
        case 3: printf("IPPROTO_GGP"); break;
        case 6: printf("IPPROTO_TCP"); break;
        case 17: printf("IPPROTO_UDP"); break;
        case 132: printf("IPPROTO_STCP"); break;
        case 255: printf("IPPROTO_RAW"); break;
        default : printf("PROTOCOL UNKNOWN (%d)", arg->protocol); break;
      }  
      break;
    case 16 : 
      printf("PF_NETLINK, ");
      switch (arg->type) {
        case 1: printf("SOCK_STREAM, "); break;
        case 2: printf("SOCK_DGRAM, "); break;
        case 3: printf("SOCK_RAW, "); break;
        case 4: printf("SOCK_RDM, "); break;
        case 5: printf("SOCK_SEQPACKET, "); break;
        case 6: printf("SOCK_DCCP, "); break;
        case 10: printf("SOCK_PACKET, "); break;
        default : printf("TYPE UNKNOWN (%d), ",arg->type); break;
      }
      switch (arg->protocol) {
        case 0: printf("NETLINK_ROUTE"); break;
        case 1: printf("NETLINK_UNUSED"); break;
        case 2: printf("NETLINK_USERSOCK"); break;
        case 3: printf("NETLINK_FIREWALL"); break;
        case 4: printf("NETLINK_INET_DIAG"); break;
        default : printf("PROTOCOL UNKNOWN (%d)", arg->protocol); break;
      }  
      break;
    default :
      printf("DOMAIN UNKNOWN (%d), ",arg->domain); break;
  }
  printf(") = %d\n", arg->ret);
}


void print_getsockopt_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  getsockopt_arg_t arg = &(sysarg->getsockopt);
  printf("[%d] getsockopt(", pid);
  printf("%d, ",arg->sockfd);
  
  switch (arg->level) {
    case 0:
      printf("SOL_IP, ");
      switch (arg->optname) {
        case 1: printf("IP_TOS, "); break; 
        case 2: printf("IP_TTL, "); break; 
        case 3: printf("IP_HDRINCL, "); break; 
        case 4: printf("IP_OPTIONS, "); break;
        case 6: printf("IP_RECVOPTS, "); break; 
        default: printf("OPTION UNKNOWN (%d), ", arg->optname); break; 
      }
      break;
        case 1 :
          printf("SOL_SOCKET, "); 
          switch (arg->optname) {
            case 1: printf("SO_DEBUG, "); break;
            case 2: printf("SO_REUSEADDR, "); break;
            case 3: printf("SO_TYPE, "); break;
            case 4: printf("SO_ERROR, "); break;
            case 5: printf("SO_DONTROUTE, "); break;
            case 6: printf("SO_BROADCAST, "); break;
            case 7: printf("SO_SNDBUF, "); break;
            case 8: printf("SO_RCVBUF, "); break;
            case 9: printf("SO_SNDBUFFORCE, "); break;
            case 10: printf("SO_RCVBUFFORCE, "); break;
            case 11: printf("SO_NO_CHECK, "); break;
            case 12: printf("SO_PRIORITY, "); break;
            case 13: printf("SO_LINGER, "); break;
            case 14: printf("SO_BSDCOMPAT, "); break;
            case 15: printf("SO_REUSEPORT, "); break;
            default: printf("OPTION UNKNOWN (%d), ", arg->optname); break; 
          }
          break;
            case 41: printf("SOL_IPV6, "); break;
            case 58: printf("SOL_ICMPV6, "); break;
            default: printf("PROTOCOL UNKNOWN (%d), ",arg->level); break;
  }
  
  printf("%d ) = ", arg->optlen);
  
  printf("%d\n", (int)arg->ret);
}

void print_setsockopt_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  getsockopt_arg_t arg = &(sysarg->setsockopt);
  printf("[%d] setsockopt(", pid);
  printf("%d, ",arg->sockfd);
  
  switch (arg->level) {
    case 0:
      printf("SOL_IP, ");
      switch (arg->optname) {
        case 1: printf("IP_TOS, "); break; 
        case 2: printf("IP_TTL, "); break; 
        case 3: printf("IP_HDRINCL, "); break; 
        case 4: printf("IP_OPTIONS, "); break;
        case 6: printf("IP_RECVOPTS, "); break; 
        default: printf("OPTION UNKNOWN (%d), ", arg->optname); break; 
      }
      break;
        case 1 :
          printf("SOL_SOCKET, "); 
          switch (arg->optname) {
            case 1: printf("SO_DEBUG, "); break;
            case 2: printf("SO_REUSEADDR, "); break;
            case 3: printf("SO_TYPE, "); break;
            case 4: printf("SO_ERROR, "); break;
            case 5: printf("SO_DONTROUTE, "); break;
            case 6: printf("SO_BROADCAST, "); break;
            case 7: printf("SO_SNDBUF, "); break;
            case 8: printf("SO_RCVBUF, "); break;
            case 9: printf("SO_SNDBUFFORCE, "); break;
            case 10: printf("SO_RCVBUFFORCE, "); break;
            case 11: printf("SO_NO_CHECK, "); break;
            case 12: printf("SO_PRIORITY, "); break;
            case 13: printf("SO_LINGER, "); break;
            case 14: printf("SO_BSDCOMPAT, "); break;
            case 15: printf("SO_REUSEPORT, "); break;
            default: printf("OPTION UNKNOWN (%d), ", arg->optname); break; 
          }
          break;
            case 41: printf("SOL_IPV6, "); break;
            case 58: printf("SOL_ICMPV6, "); break;
            default: printf("PROTOCOL UNKNOWN (%d), ",arg->level); break;
  }
  
  printf("%d ) = ", arg->optlen);
  
  printf("%d\n", (int)arg->ret);
}

void print_listen_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  listen_arg_t arg = &(sysarg->listen);
  
  printf("[%d] listen(", pid);
  printf("%d, ",arg->sockfd);
  printf("%d ",arg->backlog);
  printf(") = %d\n", arg->ret);
}

void print_flags_send(int flags) {
  if (flags & MSG_CONFIRM)
    printf(" MSG_CONFIRM |");
  if (flags & MSG_DONTROUTE)
    printf(" MSG_DONTROUTE |");
  if (flags & MSG_DONTWAIT)
    printf(" MSG_DONTWAIT |");
  if (flags & MSG_EOR)
    printf(" MSG_EOR |");
  if (flags & MSG_MORE)
    printf(" MSG_MORE |");
  if (flags & MSG_NOSIGNAL)
    printf(" MSG_NOSIGNAL |");
  if (flags & MSG_OOB)
    printf(" MSG_OOB |");
  printf(", ");
}


void print_flags_recv(int flags) {
  if (flags & MSG_DONTWAIT)
    printf(" MSG_DONTWAIT |");
  if (flags & MSG_ERRQUEUE)
    printf(" MSG_ERRQUEUE |");
  if (flags & MSG_PEEK)
    printf(" MSG_PEEK |");
  if (flags & MSG_OOB)
    printf(" MSG_OOB |");
  if (flags & MSG_TRUNC)
    printf(" MSG_TRUNC |");
  if (flags & MSG_WAITALL)
    printf(" MSG_WAITALL |");
  printf(", ");
}


void print_recv_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  recv_arg_t arg = &(sysarg->recv);
  printf("[%d] send(", pid);
  
  printf("%d, ",arg->sockfd);
  printf("%d ",(int)arg->len);
  
  if (arg->flags>0) {
    print_flags_recv(arg->flags); 
  } else
    printf("0, ");
  
  printf(") = %d\n", arg->ret);
}

void print_send_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  recv_arg_t arg = &(sysarg->send);
  printf("[%d] send( ", pid);
  
  printf("%d, ",arg->sockfd);
  printf("%d ",(int)arg->len);
  
  if (arg->flags>0) {
    print_flags_send(arg->flags); 
  } else
    printf("0, ");
  
  printf(") = %d\n", arg->ret);
}

void print_sendto_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  int domain = get_domain_socket(pid,arg->sockfd);
  
  printf("[%d] sendto(", pid);
#ifndef no_full_mediate
  char buff[200];
  if(arg->len<200)
  {
    memcpy(buff, arg->data, arg->len);
    buff[arg->ret] = '\0';
    printf("%d, \"%s\" , %d, ",arg->sockfd, buff, arg->len);
  }
  else
  {
    memcpy(buff, arg->data, 200);
    buff[199]='\0';
    printf("%d, \"%s...\" , %d, ",arg->sockfd, buff, arg->len);
  }
#else
    printf("%d, \"...\" , %d, ",arg->sockfd, arg->len);
#endif
  if (arg->flags>0) {
    print_flags_send(arg->flags); 
  } else
    printf("0, ");
  
  if (domain == 2 ) { // PF_INET
    if (arg->is_addr) {
      printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",ntohs(arg->sai.sin_port),inet_ntoa(arg->sai.sin_addr));
    } else
      printf("NULL, ");
  }
  else if (domain == 1) { //PF_UNIX
    if (arg->is_addr) {
      printf("{sa_family=AF_UNIX, sun_path=\"%s\"}, ",arg->sau.sun_path);
    } else
      printf("NULL, ");
    
  }
  else if (domain == 16) { //PF_NETLINK
    if (arg->is_addr) {
      printf("{sa_family=AF_NETLINK, pid=%d, groups=%u}, ",arg->snl.nl_pid, arg->snl.nl_groups);
    } else
      printf("NULL, ");
  } 
  else {
    printf("{sockaddr unknown}, ");
  }

  printf("%d",(int)arg->addrlen); 
  
  printf(") = %d\n", arg->ret);
}

void print_recvfrom_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  sendto_arg_t arg = &(sysarg->sendto);
  int domain = get_domain_socket(pid,arg->sockfd);
  
  printf("[%d] recvfrom(", pid);
  
#ifndef no_full_mediate
  if(arg->ret)
  {
    char buff[500];
    if(arg->ret <= 500)
    {
      memcpy(buff, arg->data, arg->ret);
      buff[arg->ret] = '\0';
      printf("%d, \"%s\" , %d, ",arg->sockfd, buff, arg->len);
    }
    else
    {
      memcpy(buff, arg->data, 500);
      buff[499]='\0';
      printf("%d, \"%s...\" , %d, ",arg->sockfd, buff, arg->len);
    }  
    if (arg->flags>0) {
      print_flags_send(arg->flags); 
    } else
      printf("0, ");
  }
  else
    printf("%d, \"\" , %d, ",arg->sockfd, arg->len);
#else
    printf("%d, \"...\" , %d, ",arg->sockfd, arg->len);
#endif
    
  
  if (domain == 2 ) { // PF_INET
    if (arg->is_addr) {
      printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",ntohs(arg->sai.sin_port),inet_ntoa(arg->sai.sin_addr));
    } else
      printf("NULL, ");
  }
  else if (domain == 1) { //PF_UNIX
    if (arg->is_addr) {
      printf("{sa_family=AF_UNIX, sun_path=\"%s\"}, ",arg->sau.sun_path);
    } else
      printf("NULL, ");
    
  }
  else if (domain == 16) { //PF_NETLINK
    if (arg->is_addr) {
      printf("{sa_family=AF_NETLINK, pid=%d, groups=%u}, ",arg->snl.nl_pid, arg->snl.nl_groups);
    } else
      printf("NULL, ");
  } 
  else {
    printf("{sockaddr unknown}, ");
  }
  
  printf("%d",(int)arg->addrlen); 
  
  printf(") = %d\n", arg->ret);
}

void print_recvmsg_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  recvmsg_arg_t arg = &(sysarg->sendmsg);
  
  printf("[%d] recvmsg(", pid);
  printf("%d, ",arg->sockfd);
  
  printf(", {msg_namelen=%d, msg_iovlen=%d, msg_controllen=%d, msg_flags=%d}, ",(int)arg->msg.msg_namelen,(int)arg->msg.msg_iovlen,(int)arg->msg.msg_controllen,arg->msg.msg_flags);
  
  if (arg->flags>0) {
    print_flags_recv(arg->flags);
  } else
    printf("0 ");
  
  printf(") = %d\n",arg->ret);
}

void print_sendmsg_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  recvmsg_arg_t arg = &(sysarg->sendmsg);
  
  printf("[%d] sendmsg(", pid);
  printf("%d, ",arg->sockfd);
#ifndef no_full_mediate
  char buff[20];
  if(arg->len<20)
  {
    memcpy(buff, arg->data, arg->len);
    printf(", {msg_namelen=%d, msg_iovlen=%d, \"%s\", msg_controllen=%d, msg_flags=%d}, ",(int)arg->msg.msg_namelen,(int)arg->msg.msg_iovlen,buff, (int)arg->msg.msg_controllen,arg->msg.msg_flags);
  }
  else
  {
    memcpy(buff, arg->data, 20);
    buff[19]='\0';
    
    printf(", {msg_namelen=%d, msg_iovlen=%d, \"%s...\", msg_controllen=%d, msg_flags=%d}, ",(int)arg->msg.msg_namelen,(int)arg->msg.msg_iovlen,buff, (int)arg->msg.msg_controllen,arg->msg.msg_flags);
  }
#else
    printf(", {msg_namelen=%d, msg_iovlen=%d, \"...\", msg_controllen=%d, msg_flags=%d}, ",(int)arg->msg.msg_namelen,(int)arg->msg.msg_iovlen, (int)arg->msg.msg_controllen,arg->msg.msg_flags);
#endif
    
  if (arg->flags>0) {
    print_flags_recv(arg->flags);
  } else
    printf("0 ");
  
  printf(") = %d\n",arg->ret);
}



void get_events_poll(short events) {
  printf("events=");
  if ((events & POLLIN)!=0)
    printf("POLLIN |");
  if ((events & POLLPRI)!=0)
    printf("POLLPRI |");
  if ((events & POLLOUT)!=0)
    printf("POLLOUT |");
  if ((events & POLLERR)!=0)
    printf("POLLERR |");
  if ((events & POLLHUP)!=0)
    printf("POLLHUP |");
  if ((events & POLLNVAL)!=0)
    printf("POLLNVAL |");
}

void get_revents_poll(short revents) {
  printf(", revents=");
  if ((revents & POLLIN)!=0)
    printf("POLLIN |");
  if ((revents & POLLPRI)!=0)
    printf("POLLPRI |");
  if ((revents & POLLOUT)!=0)
    printf("POLLOUT |");
  if ((revents & POLLERR)!=0)
    printf("POLLERR |");
  if ((revents & POLLHUP)!=0)
    printf("POLLHUP |");
  if ((revents & POLLNVAL)!=0)
    printf("POLLNVAL |");
  printf("} ");
}

void disp_pollfd(struct pollfd *fds, int nfds) {
  int i;
  for (i = 0; i< nfds-1; i++) {
    printf("{fd=%d, ",fds[i].fd);
    get_events_poll(fds[i].events);
    get_revents_poll(fds[i].revents); 
    if (i>3) {
      printf(" ... }");
      break;
    }
  }
  if (nfds<3) {
    printf("{fd=%d, ",fds[nfds-1].fd);
    get_events_poll(fds[nfds-1].events);
    get_revents_poll(fds[nfds-1].revents);  
  }
  
}

void print_poll_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  poll_arg_t arg = &(sysarg->poll);
  
  printf("[%d] poll([",pid);
  if(arg->fd_list != NULL)
    disp_pollfd(arg->fd_list, arg->nbfd);
  else
    printf("NULL");
  printf(" ]");
  printf("%lf) = %d\n",arg->timeout, arg->ret);
}

void disp_fd(fd_set * fd) {
  int i;
  printf("[ ");
  for (i = 0; i< FD_SETSIZE; i++) {
    if (FD_ISSET(i,fd)) {
      printf("%d ", i);
    }
  }
  printf("]");
}

void print_select_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  select_arg_t arg = &(sysarg->select);
  printf("[%d] select(%d,", pid, arg->maxfd);
  
  if(arg->fd_state & SELECT_FDRD_SET)
    disp_fd(&arg->fd_read);
  else
    printf("NULL");
  printf(", ");
  if(arg->fd_state & SELECT_FDWR_SET)
    disp_fd(&arg->fd_write);
  else
    printf("NULL");
  printf(", ");
  if(arg->fd_state & SELECT_FDEX_SET)
    disp_fd(&arg->fd_except);
  else
    printf("NULL");
  printf(", ");
  
  printf("%lf) = %d\n",arg->timeout, arg->ret);
  
  
}

void print_fcntl_cmd(int cmd)
{
  switch(cmd)
  {
    case F_DUPFD:
      printf("F_DUPFD");
      break;
      
    case F_DUPFD_CLOEXEC:
      printf("F_DUPFD_CLOEXEC");
      break;
    
    case F_GETFD:
      printf("F_GETFD");
      break;
    
    case F_SETFD:
      printf("F_SETFD");
      break;
      
    case F_GETFL:
      printf("F_GETFL");
      break;
      
    case F_SETFL:
      printf("F_SETFL");
      break;
      
    case F_SETLK:
      printf("F_SETLK");
      break;
      
    case F_SETLKW:
      printf("F_SETLKW");
      break;
      
    case F_GETLK:
      printf("F_GETLK");
      break;
      
    default:
      printf("Unknown command");
      break;
  }
}

void print_fcntl_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  fcntl_arg_t arg = &(sysarg->fcntl);
  printf("[%d] fcntl( %d, ", pid, arg->fd);
  print_fcntl_cmd(arg->cmd);
  printf(" , %d) = %d\n", arg->arg, arg->ret);
}

void print_read_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  read_arg_t arg = &(sysarg->read);
  printf("[%d] read(%d, \"...\", %d) = %d\n", pid, arg->fd, arg->count, arg->ret);
}

void print_write_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  write_arg_t arg = &(sysarg->read);
  printf("[%d] write(%d, \"...\", %d) = %d\n", pid, arg->fd, arg->count, arg->ret);
}

void print_shutdown_option(int how)
{
  switch(how)
  {
    case 0: 
      printf("SHUT_RD"); 
      break;
    case 1: 
      printf("SHUT_WR"); 
      break;
    case 2: 
      printf("SHUT_RDWR"); 
      break;
  }
}

void print_shutdown_syscall(pid_t pid, syscall_arg_u *sysarg)
{
  shutdown_arg_t arg = &(sysarg->shutdown);
  printf("[%d] shutdown (%d, ", pid, arg->fd);
  print_shutdown_option(arg->how);
  printf(") = %d\n", arg->ret);
}


void print_getpeername_syscall(pid_t pid, syscall_arg_u *sysarg)
{
  getpeername_arg_t arg = &(sysarg->getpeername);
  printf("[%d] getpeername (%d, ", pid, arg->sockfd);
  printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",arg->in.sin_port,inet_ntoa(arg->in.sin_addr));
  printf("%d ) = %d\n", arg->len, arg->ret);
}

void print_time_syscall(pid_t pid, syscall_arg_u *sysarg)
{
  time_arg_t arg = &(sysarg->time);
  printf("[%d] time = %ld\n", pid, arg->ret);
}
