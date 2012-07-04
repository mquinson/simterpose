#include "print_syscall.h"
#include "args_trace.h"
#include "sysdep.h"

#include <stdio.h>


void print_accept_syscall(pid_t pid, accept_arg_t arg)
{
  int domain = get_domain_socket(pid,arg->sockfd);
  printf("[%d] accept( ", pid);
  
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
  printf(" ) = %d\n", arg->ret);
}


void print_connect_syscall(pid_t pid, connect_arg_t arg)
{
  int domain = get_domain_socket(pid,arg->sockfd);
  
  printf("[%d] connect( ", pid);
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
  printf(" ) = %d\n", arg->ret);
}


void print_bind_syscall(pid_t pid, connect_arg_t arg)
{
  int domain = get_domain_socket(pid,arg->sockfd);
  
  printf("[%d] bind( ", pid);
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
  printf(" ) = %d\n", arg->ret);
}



void print_socket_syscall(pid_t pid, syscall_arg_u* sysarg)
{
  socket_arg_t arg = &(sysarg->socket);
  
  printf("[%d] socket( ",pid);
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
  printf(" ) = %d\n", arg->ret);
}



