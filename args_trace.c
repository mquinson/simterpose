#include "args_trace.h"
#include "ptrace_utils.h"
#include "process_descriptor.h"
#include "communication.h"


void get_args_socket(pid_t child, reg_s *reg, syscall_arg_u * sysarg) { 

  socket_arg_t arg = &sysarg->socket;
  arg->ret = reg->ret;

#if defined(__x86_64)

  arg->domain = (int)reg->arg1;
  arg->type = (int)reg->arg2;
  arg->protocol = (int)reg->arg3;

#else

//   void *addr = (void *)reg->arg2;
//   ptrace_cpy(child,&domain, addr, sizeof(int),"socket");  
//   ptrace_cpy(child,&type, addr + sizeof(long), sizeof(int),"socket");  
//   ptrace_cpy(child,&protocol, addr + 2* sizeof(long), sizeof(int),"socket");  

#endif
}


void get_args_bind_connect(pid_t child, int syscall, reg_s *reg, syscall_arg_u *sysarg) {
  
  connect_arg_t arg = &(sysarg->connect);
  
  arg->ret = reg->ret;
#if defined(__x86_64)

  arg->sockfd=(int)reg->arg1;
  int domain = get_domain_socket(child,arg->sockfd);
  arg->addrlen=(socklen_t)reg->arg3;
  if (domain == 2) // PF_INET
    ptrace_cpy(child, &arg->sai, (void *)reg->arg2, sizeof(struct sockaddr_in),"bind ou connect");
  if (domain == 1) // PF_UNIX
    ptrace_cpy(child, &arg->sau, (void *)reg->arg2, sizeof(struct sockaddr_in),"bind ou connect");
  if (domain == 16) // PF_NETLINK
    ptrace_cpy(child, &arg->sau, (void *)reg->arg2, sizeof(struct sockaddr_in),"bind ou connect");

#else

//     void *addr=(void *)reg.arg2;
//     ptrace_cpy(child, &(arg->connect.sockfd), addr, sizeof(int),"bind ou connect");
//   printf("%d, ",sockfd);
//   int domain = get_domain_socket(child,sockfd);
//   if (domain == 2 ) // PF_INET
//     ptrace_cpy(child, &(arg->connect.psai), addr + sizeof(long), sizeof(struct sockaddr_in *),"bind ou connect");
//   if (domain == 1) // PF_UNIX
//     ptrace_cpy(child, &(arg->connect.psau), addr + sizeof(long), sizeof(struct sockaddr_un *),"bind ou connect");
//   if (domain == 16) // PF_NETLINK
//     ptrace_cpy(child, &(arg->connect.psnl), addr + sizeof(long), sizeof(struct sockaddr_nl *),"bind ou connect");
//   
//   ptrace_cpy(child,&(arg->connect.addrlen), addr + 2 * sizeof(long), sizeof(socklen_t),"bind ou connect");
//  
#endif
}

void get_args_accept(pid_t child, reg_s *reg, syscall_arg_u *sysarg) {
  
  accept_arg_t arg = &(sysarg->accept);

  arg->ret = reg->ret;

#if defined(__x86_64)

  arg->sockfd=(int)reg->arg1;

  int domain = get_domain_socket(child,arg->sockfd);
  if (domain == 2) // PF_INET
    ptrace_cpy(child, &arg->sai, (void*)reg->arg2, sizeof(struct sockaddr_in),"accept");
  if (domain == 1) // PF_UINX
    ptrace_cpy(child, &arg->sau, (void*)reg->arg2, sizeof(struct sockaddr_in),"accept");        
  if (domain == 16) // PF_NETLINK
    ptrace_cpy(child, &arg->snl, (void*)reg->arg2, sizeof(struct sockaddr_in),"accept");

  ptrace_cpy(child,&arg->addrlen, (void*)reg->arg3,sizeof(socklen_t),"accept");

#else

//   void *addr = (void*)reg->arg2;
//   ptrace_cpy(child, &arg->sockfd, addr, sizeof(int),"accept");
// 
//   int domain = get_domain_socket(child,arg->sockfd);
//   if (domain == 2 ) //PF_INET
//     ptrace_cpy(child, &psai, addr + sizeof(long), sizeof(struct sockaddr_in *),"accept");
//   if (domain == 1) //PF_UNIX
//     ptrace_cpy(child, &psau, addr + sizeof(long), sizeof(struct sockaddr_un *),"accept");
//   if (domain == 16) // PF_NETLINK
//     ptrace_cpy(child, &psnl, addr + sizeof(long), sizeof(struct sockaddr_nl *),"accept");
//   
//   long addr_addrlen;
//   ptrace_cpy(child,&addr_addrlen, addr + 2 * sizeof(long), sizeof(long),"accept");
//   ptrace_cpy(child,&addrlen,(void *)addr_addrlen,sizeof(socklen_t),"accept");
//  
#endif

}

void get_args_listen(pid_t pid, reg_s *reg, syscall_arg_u *sysarg) {
  listen_arg_t arg = &(sysarg->listen);

#if defined(__x86_64)

  arg->sockfd=(int)reg->arg1;
  arg->backlog=(int)reg->arg2;
  arg->ret = (int)reg->ret;

#else

//   void *addr= (void*) reg->arg2;
//   ptrace_cpy(pid, &sockfd, addr, sizeof(int),"listen");
//   ptrace_cpy(pid, &backlog, addr + sizeof(long), sizeof(int),"listen");
  
#endif
}

void get_args_send_recv(pid_t child, int syscall, reg_s *reg, syscall_arg_u *sysarg) {  
  recv_arg_t arg = &(sysarg->recv);
  
  arg->ret = (int) reg->ret;
#if defined(__x86_64)

  arg->sockfd = (int)reg->arg1;
  arg->len = (size_t)reg->arg3;
  arg->flags=(int)reg->arg4;

#else

  void *addr= (void*)arg->arg2;
  ptrace_cpy(child,&sockfd, addr, sizeof(int),"send ou recv");   
  ptrace_cpy(child,&len, addr + 2 *sizeof(long), sizeof(size_t),"send ou recv");
//   ptrace_cpy(child,&flags, addr + 3 * sizeof(long), sizeof(int),"send ou recv");

#endif
}


void get_args_select(pid_t child, reg_s *r, syscall_arg_u* sysarg) {
  select_arg_t arg = &(sysarg->select);

  arg->fd_state=0;
  arg->maxfd = (int) r->arg1;

#if defined(__x86_64)

  
  if (r->arg2!=0) {
    ptrace_cpy(child, &arg->fd_read, (void *)r->arg2, sizeof(fd_set),"select");
    arg->fd_state = arg->fd_state | SELECT_FDRD_SET;
  } 
  else 
    FD_ZERO(&arg->fd_read);
  
  if (r->arg3!=0) {
    ptrace_cpy(child, &arg->fd_write, (void *)r->arg3, sizeof(fd_set),"select");
    arg->fd_state = arg->fd_state | SELECT_FDWR_SET;
  } 
  else 
    FD_ZERO(&arg->fd_write);
  
  if (r->arg4!=0) {
    ptrace_cpy(child, &arg->fd_except, (void *)r->arg4, sizeof(fd_set),"select");
    arg->fd_state = arg->fd_state | SELECT_FDEX_SET;
  }
  else 
    FD_ZERO(&arg->fd_except);
  
  if(r->arg5 != 0)
  {
    struct timeval t;
    ptrace_cpy(child, &t, (void *)r->arg5, sizeof(struct timeval),"select");
    arg->timeout = t.tv_sec + 0.000001 * t.tv_usec;
  }
  else
    arg->timeout = -1;
  
  arg->ret = (int)r->ret;

#else 
//   //FIXME do portability on 32 bits
//   printf("[%d] select(%d,", child, (int) r->ebx);
//   if (r->arg2!=0) {
//     ptrace_cpy(child, &fr, (void *)r->arg2, sizeof(fd_set),"select");
//     disp_fd(&fr);
//   } else 
//     printf("NULL");
//   
//   printf(", ");
//   if (r->arg3!=0) {
//     ptrace_cpy(child, &fw, (void *)r->arg3, sizeof(fd_set),"select");
//     disp_fd(&fw);
//   } else 
//     printf("NULL");
//   
//   printf(", ");
// //   if (r->esi!=0) {
// //     ptrace_cpy(child, &fe, (void *)r->esi, sizeof(fd_set),"select");
// //     disp_fd(&fe);
// //   } else 
// //     printf("NULL");
//   
//   printf(") = %d\n",(int)r->ret);

#endif
}

//TODO add 32 bit gestion
//FIXME make this function use unified union syscall_arg_u
void sys_build_select(pid_t pid, int match)
{
  ptrace_restore_syscall(pid, SYS_select, match);
  reg_s r;
  ptrace_get_register(pid, &r);
  
  process_descriptor* proc = process_get_descriptor(pid);
  select_arg_t arg = &(proc->sysarg.select);
  
  if(arg->fd_state & SELECT_FDRD_SET)
  {
    ptrace_poke(pid, (void*)r.arg2, &(arg->fd_read), sizeof(fd_set));
  }
  if(arg->fd_state & SELECT_FDWR_SET)
  {
    ptrace_poke(pid, (void*)r.arg3, &(arg->fd_write), sizeof(fd_set));
  }
  if(arg->fd_state & SELECT_FDEX_SET)
  {
    ptrace_poke(pid, (void*)r.arg4, &(arg->fd_except), sizeof(fd_set));
  }
}



void get_args_get_setsockopt(pid_t child, int syscall, reg_s* reg, syscall_arg_u *sysarg) {

  getsockopt_arg_t arg = &(sysarg->getsockopt);

#if defined(__x86_64)
  arg->ret = (int)reg->ret;
  arg->sockfd=(int)reg->arg1;
  arg->level=(int)reg->arg2;
  arg->optname=(int)reg->arg3;
  //optval=(void *)arg->arg4;

  if (syscall == 1) // getsockopt
    ptrace_cpy(child,&arg->optlen,(void *)reg->arg5,sizeof(socklen_t),"getsockopt ou setsockopt");
  else  // setsockopt
    arg->optlen=reg->arg5;

#else

//   void *src = (void*)arg->arg2;
//   socklen_t *addr_optlen;
//   ptrace_cpy(child,&sockfd,src,sizeof(int),"getsockopt ou setsockopt");
//   ptrace_cpy(child,&level,src + sizeof(long),sizeof(int),"getsockopt ou setsockopt");
//   ptrace_cpy(child,&optname,src + 2 * sizeof(long),sizeof(int),"getsockopt ou setsockopt");
//   ptrace_cpy(child,&optval,src + 3 * sizeof(long),sizeof(void *),"getsockopt ou setsockopt");
// 
//   if (syscall == 1) { // getsockopt
//     ptrace_cpy(child,&addr_optlen,src + 4 * sizeof(long) ,sizeof(socklen_t *),"getsockopt ou setsockopt");
//     ptrace_cpy(child,&optlen,addr_optlen,sizeof(socklen_t),"getsockopt ou setsockopt");
//   } else // setsockopt
//     ptrace_cpy(child,&optlen,src + 4 * sizeof(long),sizeof(socklen_t),"getsockopt ou setsockopt");

#endif
}



void get_args_sendto_recvfrom(pid_t child, int syscall, reg_s* reg, syscall_arg_u *sysarg) {
  sendto_arg_t arg = &(sysarg->sendto);
  
  arg->ret = reg->ret;

#if defined(__x86_64)
  
  arg->sockfd=(int)reg->arg1;
  arg->len=(int)reg->arg3;
  arg->flags=(int)reg->arg4;
  
  int domain = get_domain_socket(child,arg->sockfd);
  if (reg->arg5 != 0) { // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    arg->is_addr = 1;
    if (domain == 2 ) // PF_INET
      ptrace_cpy(child, &arg->sai, (void *)reg->arg5, sizeof(struct sockaddr_in),"sendto ou -- recvfrom");
    if (domain == 1) // PF_UNIX
      ptrace_cpy(child, &arg->sau, (void *)reg->arg5, sizeof(struct sockaddr_in),"sendto ou -- recvfrom");
    if (domain == 16) // PF_NETLINK
      ptrace_cpy(child, &arg->snl, (void *)reg->arg5, sizeof(struct sockaddr_in),"sendto ou -- recvfrom");
  }
  else
    arg->is_addr = 0;

  if (reg->arg5 != 0) {  // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    if (syscall == 1) // sendto
      arg->addrlen=(socklen_t)reg->arg5;
    else // recvfrom
      ptrace_cpy(child,&arg->addrlen,(void *)reg->arg5, sizeof(socklen_t ),"sendto ou recvfrom");
  } else
    arg->addrlen=0;

#else
/*  
  void *src= (void*)reg->arg2;
  ptrace_cpy(child,&sockfd,src,sizeof(int),"sendto ou recvfrom");
  ptrace_cpy(child,&len,src + 2 * sizeof(long), sizeof(size_t),"sendto ou recvfrom");  
  ptrace_cpy(child,&flags,src + 3 * sizeof(long), sizeof(int),"sendto ou recvfrom");
 
  int domain = get_domain_socket(child,sockfd);
  if (domain == 2 ) // PF_INET
    ptrace_cpy(child, &psai, src + 4 * sizeof(long), sizeof(struct sockaddr_in *),"sendto ou recvfrom");
  if (domain == 1) // PF_UNIX
    ptrace_cpy(child, &psau, src + 4 * sizeof(long), sizeof(struct sockaddr_un *),"sendto ou recvfrom");
  if (domain == 16) // PF_NETLINK
    ptrace_cpy(child, &psnl, src + 4 * sizeof(long), sizeof(struct sockaddr_nl *),"sendto ou recvfrom");
  
  if (syscall == 1)
    ptrace_cpy(child,&addrlen, src + 5 * sizeof(long), sizeof(socklen_t),"sendto ou recvfrom");
  else {
    socklen_t *addr_addrlen;
    ptrace_cpy(child,&addr_addrlen, src + 5 * sizeof(long), sizeof(socklen_t *),"sendto ou recvfrom");
    ptrace_cpy(child,&addrlen,(void *)addr_addrlen, sizeof(socklen_t ),"sendto ou recvfrom");
  }*/
#endif
}

void get_args_send_recvmsg(pid_t child, reg_s* reg, syscall_arg_u *sysarg) {
  recvmsg_arg_t arg = &(sysarg->recvmsg);

#if defined(__x86_64)

  arg->sockfd=(int)reg->arg1;
  arg->flags=(int)reg->arg3;
  ptrace_cpy(child, &arg->msg, (void *)reg->arg2, sizeof(struct msghdr),"sendmsg ou recvmsg");  
#else

  void *src= (void*)reg->arg2;
  ptrace_cpy(child,&sockfd,src,sizeof(int),"sendmsg ou recvmsg");
  ptrace_cpy(child, &pmsg, src + sizeof(long), sizeof(struct msghdr *),"sendmsg ou recvmsg");
  ptrace_cpy(child,&flags,src + 2 * sizeof(long), sizeof(int),"sendmsg ou recvmsg");
 
#endif
}


void get_args_poll(pid_t child, reg_s* reg, syscall_arg_u* sysarg) {
  poll_arg_t arg = &(sysarg->poll);
  
  void * src = (void*)reg->arg1;
  arg->nbfd = reg->arg2;
  arg->timeout = reg->arg3;

  if (src!=0) {
    arg->fd_list = malloc(sizeof(arg->nbfd)* sizeof(struct pollfd));
    ptrace_cpy(child,arg->fd_list, src, arg->nbfd * sizeof( struct pollfd),"poll");
    
  } 
  else
    arg->fd_list = NULL;
}

