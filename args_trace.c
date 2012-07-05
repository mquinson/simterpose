#include "args_trace.h"
#include "ptrace_utils.h"
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

//   if (domain == 2 ) {
//      struct sockaddr_in *sai = &(arg->sai);
//     if (arg->ret==0) {
//         update_socket(child,arg->sockfd); // update remote informations if connect
//         struct sockaddr_in * remote_addr = malloc(sizeof(struct sockaddr_in));
//         struct infos_socket* is = get_infos_socket(child, arg->connect.sockfd);
//         
//         socket_get_remote_addr(child, arg->connect.sockfd, remote_addr);
//         //Now mark the socket as connect wait
//         comm_ask_connect(remote_addr->sin_addr.s_addr, remote_addr->sin_port, child);
//         
// //         printf("Connect to peer %d %d\n", remote_addr->sin_addr.s_addr, remote_addr->sin_port);
//         comm_t comm = comm_find_incomplete(remote_addr->sin_addr.s_addr, remote_addr->sin_port, is);
//         if(comm == NULL) //if communication is not create yet
//           comm_new(is, remote_addr->sin_addr.s_addr, remote_addr->sin_port);
//         else
//           comm_join(comm, get_infos_socket(child, arg->connect.sockfd));
//     }
//   }
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

  void *addr= (void*) reg->arg2;
  ptrace_cpy(pid, &sockfd, addr, sizeof(int),"listen");
  ptrace_cpy(pid, &backlog, addr + sizeof(long), sizeof(int),"listen");
  
#endif
}


void get_flags_send(int flags) {
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

void get_flags_recv(int flags) {
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

int get_args_send_recv(pid_t child, int syscall, reg_s *arg) {
 
  int sockfd;
  size_t len;
  //int flags;

#if defined(__x86_64)

  sockfd = (int)arg->arg1;
  len = (size_t)arg->arg3;
  //flags=(int)res->r10;

#else

  void *addr= (void*)arg->arg2;
  ptrace_cpy(child,&sockfd, addr, sizeof(int),"send ou recv");   
  ptrace_cpy(child,&len, addr + 2 *sizeof(long), sizeof(size_t),"send ou recv");
//   ptrace_cpy(child,&flags, addr + 3 * sizeof(long), sizeof(int),"send ou recv");

#endif

  printf("%d, ",sockfd);
  printf("%d ",(int)len);
//   if (flags>0) {
//      if (syscall == 1)//sendto
//        get_flags_send(flags);
//      else //recvfrom
//        get_flags_recv(flags); 
//    } else
//      printf("0, ");
 
  return sockfd;
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

double get_args_select(pid_t child, reg_s *r) {

  fd_set fr, fw, fe;
  double timeout;
  int fd_state=0;
  //TODO add recuperation of except's fd_set
  FD_ZERO(&fe);
#if defined(__x86_64)

  printf("[%d] select(%d,", child, (int) r->arg1);
  if (r->arg2!=0) {
    ptrace_cpy(child, &fr, (void *)r->arg2, sizeof(fd_set),"select");
    disp_fd(&fr);
    fd_state = fd_state | SELECT_FDRD_SET;
  } 
  else 
  {
    FD_ZERO(&fr);
    printf("NULL");
  }
  
  printf(", ");
  if (r->arg3!=0) {
    ptrace_cpy(child, &fw, (void *)r->arg3, sizeof(fd_set),"select");
    disp_fd(&fw);
    fd_state = fd_state | SELECT_FDWR_SET;
  } 
  else 
  {
    FD_ZERO(&fw);
    printf("NULL");
  }
  
  printf(", ");
  if (r->arg4!=0) {
    ptrace_cpy(child, &fe, (void *)r->arg4, sizeof(fd_set),"select");
    disp_fd(&fe);
    fd_state = fd_state | SELECT_FDEX_SET;
  }
  else 
  {
    FD_ZERO(&fw);
    printf("NULL");
  }
  
  if(r->arg5 != 0)
  {
    struct timeval t;
    ptrace_cpy(child, &t, (void *)r->arg5, sizeof(struct timeval),"select");
    timeout = t.tv_sec + 0.000001 * t.tv_usec;
  }
  else
    timeout = -1;
  
  
  printf(") = %d\n",(int)r->ret);

#else 
  //FIXME do portability on 32 bits
  printf("[%d] select(%d,", child, (int) r->ebx);
  if (r->arg2!=0) {
    ptrace_cpy(child, &fr, (void *)r->arg2, sizeof(fd_set),"select");
    disp_fd(&fr);
  } else 
    printf("NULL");
  
  printf(", ");
  if (r->arg3!=0) {
    ptrace_cpy(child, &fw, (void *)r->arg3, sizeof(fd_set),"select");
    disp_fd(&fw);
  } else 
    printf("NULL");
  
  printf(", ");
//   if (r->esi!=0) {
//     ptrace_cpy(child, &fe, (void *)r->esi, sizeof(fd_set),"select");
//     disp_fd(&fe);
//   } else 
//     printf("NULL");
  
  printf(") = %d\n",(int)r->ret);

#endif
  // FIXME handle ret value

  //process_set_select(child, fd_state, r->arg1, fr, fw, fe);
  
  return timeout;
}

//TODO add 32 bit gestion
//FIXME make this function use unified union syscall_arg_u
void sys_build_select(pid_t pid, int match)
{
//   ptrace_restore_syscall(pid, SYS_select, match);
//   reg_s r;
//   ptrace_get_register(pid, &r);
//   
//   select_arg_t arg = (select_arg_t)process_get_argument(pid);
//   
//   if(arg->fd_state & SELECT_FDRD_SET)
//   {
//     ptrace_poke(pid, (void*)r.arg2, &(arg->fd_read), sizeof(fd_set));
//   }
//   if(arg->fd_state & SELECT_FDWR_SET)
//   {
//     ptrace_poke(pid, (void*)r.arg3, &(arg->fd_write), sizeof(fd_set));
//   }
//   if(arg->fd_state & SELECT_FDEX_SET)
//   {
//     ptrace_poke(pid, (void*)r.arg4, &(arg->fd_except), sizeof(fd_set));
//   }
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



int get_args_sendto_recvfrom(pid_t child, int syscall, reg_s* arg) {

  int sockfd;
  int len;
  int flags;
  socklen_t addrlen;
  struct sockaddr_in *psai=NULL; 
  struct sockaddr_un *psau=NULL;
  struct sockaddr_nl *psnl=NULL;

#if defined(__x86_64)

  struct user_regs_struct res;
  
  if (ptrace(PTRACE_GETREGS, child,NULL, &res)==-1) {
    perror("ptrace getregs");
    exit(1);
  }
  sockfd=(int)res.rdi;
  len=(int)res.rdx;
  flags=(int)res.r10;
  
  int domain = get_domain_socket(child,sockfd);
  
  if (res.r8 != 0) { // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    if (domain == 2 ) // PF_INET
      psai=(void *)res.r8;
    if (domain == 1) // PF_UNIX
      psau=(void *)res.r8;
    if (domain == 16) // PF_NETLINK
      psnl=(void *)res.r8;
  }

  if (res.r9 != 0) {  // syscall "send" doesn't exist on x86_64, it's sendto with struct sockaddr=NULL and addrlen=0
    if (syscall == 1) // sendto
      addrlen=(socklen_t)res.r9;
    else // recvfrom
      ptrace_cpy(child,&addrlen,(void *)res.r9, sizeof(socklen_t ),"sendto ou recvfrom");
  } else
    addrlen=0;

#else
  
  void *src= (void*)arg->arg2;
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
  }

 
#endif

  printf("%d, \"...\",%d ",sockfd, len);
  
  if (flags>0) {
    if (syscall == 1)//sendto
      get_flags_send(flags);
    else //recvfrom
      get_flags_recv(flags); 
  } else
    printf("0, ");
  
  if (domain == 2 ) { // PF_INET
    if (psai != NULL) {
      struct sockaddr_in sai;
      ptrace_cpy(child, &sai, (void *)psai, sizeof(struct sockaddr_in),"sendto ou -- recvfrom");
      printf("{sa_family=AF_INET, sin_port=htons(%d), sin_addr=inet_addr(\"%s\")}, ",ntohs(sai.sin_port),inet_ntoa(sai.sin_addr));
     } else
      printf("NULL, ");
  }
    
  if (domain == 1) { //PF_UNIX
    if (psau != NULL) {
      struct sockaddr_un sau;
      ptrace_cpy(child, &sau, psau, sizeof(struct sockaddr_un),"sendto ou recvfrom");
      printf("{sa_family=AF_UNIX, sun_path=\"%s\"}, ",sau.sun_path);
    } else
      printf("NULL, ");
    
  }

  if (domain == 16) { //PF_NETLINK
    if (psnl != NULL) {
      struct sockaddr_nl snl;
      ptrace_cpy(child, &snl, psnl, sizeof(struct sockaddr_nl),"sendto ou recvfrom");
      printf("{sa_family=AF_NETLINK, pid=%d, groups=%u}, ",snl.nl_pid,snl.nl_groups);
    } else
      printf("NULL, ");
  } else {
    printf("{sockaddr unknown}, ");
  }
  
  printf("%d",(int)addrlen); 
  
  return sockfd;
 
}

int get_args_send_recvmsg(pid_t child, int syscall, reg_s* arg) {

  int sockfd;
  int flags;
  struct msghdr *pmsg;
  struct msghdr msg;


#if defined(__x86_64)

  sockfd=(int)arg->arg1;
  flags=(int)arg->arg3;
  pmsg=malloc(sizeof(struct msghdr *));
  pmsg=(struct msghdr *)arg->arg2;

#else

  void *src= (void*)arg->arg2;
  ptrace_cpy(child,&sockfd,src,sizeof(int),"sendmsg ou recvmsg");

  memset(ret_trace,0,SIZE_PARAM_TRACE);
   
  ptrace_cpy(child, &pmsg, src + sizeof(long), sizeof(struct msghdr *),"sendmsg ou recvmsg");
  ptrace_cpy(child,&flags,src + 2 * sizeof(long), sizeof(int),"sendmsg ou recvmsg");
 
#endif

  printf("%d, ",sockfd);

  ptrace_cpy(child, &msg, pmsg, sizeof(struct msghdr),"sendmsg ou recvmsg");  
  printf(", {msg_namelen=%d, msg_iovlen=%d, msg_controllen=%d, msg_flags=%d}, ",(int)msg.msg_namelen,(int)msg.msg_iovlen,(int)msg.msg_controllen,msg.msg_flags);

  if (flags>0) {
    if (syscall == 1)
      get_flags_send(flags);
    else
      get_flags_recv(flags);
  } else
    printf("0 ");

  return sockfd;
  
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

double get_args_poll(pid_t child, reg_s* arg) {
  //TODO modify to found time_out
  
  void * src = (void*)arg->arg1;
  int nbfds = arg->arg2;
  double timeout = arg->arg3;
  
  struct pollfd* fds= malloc(sizeof(nbfds)* sizeof(struct pollfd));
  
  printf("[%d] poll([ ",child);
  if (src!=0) {
    ptrace_cpy(child,fds, src, nbfds * sizeof( struct pollfd),"poll");
    disp_pollfd(fds, nbfds);
  } else {
    printf("NULL");
  }
  printf(" ]");
  
  //process_set_poll(child, nbfds, fds);
  
  return timeout;
}

