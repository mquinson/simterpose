#include "syscall_process.h"
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

#include <linux/futex.h>

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(SYSCALL_PROCESS, SIMTERPOSE, "Syscall process log");

//TODO test the possibility to remove incomplete checking
//There is no need to return value because send always bring a task
void process_send_call(int pid, int sockfd, int ret)
{

  if (socket_registered(pid,sockfd) != -1) {
    if (socket_incomplete(pid,sockfd))
    {
      update_socket(pid,sockfd);
    }
    if (!socket_netlink(pid,sockfd))
    {
      calculate_computation_time(pid);
      struct infos_socket *is = get_infos_socket(pid,sockfd);
      struct infos_socket *s = comm_get_peer(is);
      
      handle_new_send(is,  ret);

      SD_task_t task = create_send_communication_task(pid, is, ret);

      schedule_comm_task(is->proc->station, s->proc->station, task);
    }
  }
  else 
    THROW_IMPOSSIBLE;
}


int process_recv_call(int pid, int sockfd, int ret)
{
  if (socket_registered(pid,sockfd) != -1) {
    if (socket_incomplete(pid,sockfd)) 
      update_socket(pid,sockfd);
    if (!socket_netlink(pid,sockfd))
    {
      calculate_computation_time(pid);
      
      //if handle_new_receive return 1, there is a task found
      if(handle_new_receive(pid, sockfd, ret))
        return PROCESS_TASK_FOUND;
      else
        return PROCESS_NO_TASK_FOUND;
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
  THROW_UNIMPLEMENTED;
//   select_arg_t arg = (select_arg_t) process_get_argument(pid);
//   
//   int i;
//   
//   fd_set fd_rd, fd_wr, fd_ex;
//   
//   fd_rd = arg->fd_read;
//   fd_wr = arg->fd_write;
//   fd_ex = arg->fd_except;
//   
//   int match = 0;
//   
//   for(i=0 ; i < arg->maxfd ; ++i)
//   {
//     struct infos_socket* is = process_get_fd(pid, i);
//     //if i is NULL that means that i is not a socket
//     if(is == NULL)
//       continue;
//     int sock_status = socket_get_state(is);
//     if(FD_ISSET(i, &(fd_rd)))
//     {
//       if(sock_status & SOCKET_READ_OK)
//         ++match;
//       else
//         FD_CLR(i, &(fd_rd));
//     }
//     if(FD_ISSET(i, &(fd_wr)))
//     {
//       XBT_WARN("Mediation for writing states on socket are not support yet\n");
//     }
//     if(FD_ISSET(i, &(fd_ex)))
//     {
//       XBT_WARN("Mediation for exception states on socket are not support yet\n");
//     }
//   }
//   if(match > 0)
//   {
//     sys_build_select(pid, match);
//     return match;
//   }
//   else
//     //printf("No match for select\n");
//   return 0;
}


int process_handle_active(pid_t pid)
{
  int status;
  ptrace_resume_process(pid);

  if(waitpid(pid, &status, 0) < 0)
  {
    fprintf(stderr, " [%d] waitpid %s %d\n", pid, strerror(errno), errno);
    exit(1);
  }
  
  return process_handle( pid, status);
}

//Return 0 if nobody wait or the pid of the one who wait
int process_accept_in_call(pid_t pid, syscall_arg_u* sysarg)
{
  accept_arg_t acc = &(sysarg->accept);
  //We try to find here if there's a connection to accept
  if(comm_has_connect_waiting(get_infos_socket(pid, acc->sockfd)))
  {
    pid_t conn_pid = comm_accept_connect(get_infos_socket(pid, acc->sockfd));
    ptrace_resume_process(conn_pid);
    process_set_state(conn_pid, PROC_CONNECT_DONE);
    return conn_pid;
  }
  else
  {
    process_set_state(pid, PROC_ACCEPT_IN);
    return 0;
  }
}

void process_accept_out_call(pid_t pid, syscall_arg_u* sysarg)
{
  accept_arg_t arg = &(sysarg->accept);
  
  int domain = get_domain_socket(pid, arg->sockfd);
  int protocol=get_protocol_socket(pid, arg->sockfd);
  
  struct infos_socket* is = register_socket(pid, arg->ret, domain, protocol);
  update_socket(pid, arg->ret);
  comm_new(is, arg->sai.sin_addr.s_addr, ntohs(arg->sai.sin_port));
  
  process_set_state(pid, PROC_NO_STATE);
}


int process_handle_idle(pid_t pid)
{
  int status;
  int proc_state = process_get_state(pid);
  
  if(proc_state & PROC_SELECT)
  {
    //if the select match changment we have to run the child
    if(process_select_call(pid))
      return process_handle_active(pid);
    else
      return PROCESS_IDLE_STATE;
  }
  if(proc_state & PROC_CONNECT)
  {
    //if the select match changment we have to run the child
    if(process_is_connect_done(pid))
      return process_handle_active(pid);
    else
      return PROCESS_IDLE_STATE;
  }
  else if(proc_state & PROC_POLL)
  {
    THROW_UNIMPLEMENTED;
  }
  else if(proc_state & PROC_ACCEPT_IN)
  {
    process_descriptor* proc = process_get_descriptor(pid);
    if(process_accept_in_call(pid, &proc->sysarg))
    {
      printf("A process waiting for connection\n");
      //Here process is like an active process so we launch him like that
      return process_handle_active(pid);;
    }
    else
      return PROCESS_IDLE_STATE;
  }
  else
  {
    if(waitpid(pid, &status, WNOHANG))
      return process_handle( pid, status);
    else
      return PROCESS_IDLE_STATE;
  }
}

int process_clone_call(pid_t pid, reg_s *arg)
{
  unsigned long tid = arg->ret;
  unsigned long flags = arg->arg1;
  
  //Now create new process in model
  process_clone(tid, pid, flags);
  
  //Now add it to the launching time table to be the next process to be launch
  set_next_launchment(tid);
  
  int status;
  
  //wait for clone
  waitpid(tid, &status, 0);
  ptrace_resume_process(tid);
  //place process to te first call after clone
  waitpid(tid, &status, 0);
  process_set_in_syscall(tid);
  
  return 0;
}

//This function check if the communication already have been set. Means that 
int process_connect_in_call(pid_t pid, syscall_arg_u *arg)
{
  connect_arg_t conn = &(arg->connect);
  int domain = get_domain_socket(pid, conn->sockfd);
  
  if(domain == 2)//PF_INET
  {
    struct sockaddr_in *sai = &(arg->connect.sai);
    
    //We ask for a connection on the socket
    comm_ask_connect(sai->sin_addr.s_addr, ntohs(sai->sin_port), pid);
    //now mark the process as waiting for conn
    process_set_state(pid, PROC_CONNECT);
  }
  return 1;
}

void process_connect_out_call(pid_t pid, syscall_arg_u *sysarg)
{
  connect_arg_t conn = &(sysarg->connect);
  
  int domain = get_domain_socket(pid, conn->sockfd);
  if(domain ==2 )
  {
    update_socket(pid, conn->sockfd);
    struct sockaddr_in remote_addr;
    struct infos_socket* is = get_infos_socket(pid, conn->sockfd);
    socket_get_remote_addr(pid, conn->sockfd, &remote_addr);
    comm_t comm = comm_find_incomplete(remote_addr.sin_addr.s_addr, remote_addr.sin_port, is);
    comm_join(comm, get_infos_socket(pid, conn->sockfd));
    process_set_state(pid, PROC_NO_STATE);
  }
  else
    THROW_UNIMPLEMENTED;
}

int process_bind_call(pid_t pid, syscall_arg_u *arg)
{
  connect_arg_t conn = &(arg->connect);
  set_localaddr_port_socket(pid,conn->sockfd,inet_ntoa(conn->sai.sin_addr),ntohs(conn->sai.sin_port));
  return 0;
}

int process_socket_call(pid_t pid, syscall_arg_u *arg)
{
  socket_arg_t sock = &(arg->socket);
  if (sock->ret>0) 
    register_socket(pid,sock->ret,sock->domain,sock->protocol);
  return 0;
}


int process_listen_call(pid_t pid, syscall_arg_u* sysarg)
{
  listen_arg_t list = &(sysarg->listen);
  struct infos_socket* is = get_infos_socket(pid, list->sockfd);
  comm_t comm = comm_new(is, 0, 0);
  comm_set_listen(comm);
  
  return 0;
}



int process_handle(pid_t pid, int stat)
{  
  printf("Handling %d \n", pid);
  int status = stat;
  reg_s arg;
  syscall_arg_u sysarg;
  while(1)
  {

    if (process_in_syscall(pid)==0) {
      
      process_set_in_syscall(pid);

      ptrace_get_register(pid, &arg);
      
      if(arg.reg_orig == SYS_poll)
      {
        get_args_poll(pid, &arg, &sysarg);
        //Now we have to add the process in launching list
//         add_launching_time(pid, timeout+SD_get_clock());
//         printf(" = %d \n", (int)arg.ret);
//         ptrace_neutralize_syscall(pid);
//         ptrace_resume_process(pid);
//         process_set_out_syscall(pid);
//         return PROCESS_IDLE_STATE;
      }
      
      if(arg.reg_orig == SYS_exit_group)
      {
        printf("[%d] exit_group(%ld) called \n",pid, arg.arg1);
        return PROCESS_DEAD;
      }
      if(arg.reg_orig == SYS_exit)
      {
        printf("[%d] exit(%ld) called \n", pid, arg.arg1);
        return PROCESS_DEAD;
      }
      
      if(arg.reg_orig == SYS_futex)
      {
        printf("[%d] futex_in %p %d\n", pid, (void*)arg.arg4, arg.arg2 == FUTEX_WAIT);
        //TODO add real gestion of timeout
        if(arg.arg2 == FUTEX_WAIT)
        {
          ptrace_resume_process(pid);
          return PROCESS_IDLE_STATE;
        }
      }
      
      #if defined(__x86_64)
      if(arg.reg_orig == SYS_connect)
      {
        printf("[%d] connect_in\n", pid);
        get_args_bind_connect(pid, 0, &arg, &sysarg);
        process_connect_in_call(pid, &sysarg);
        process_set_state(pid, PROC_CONNECT);
        return PROCESS_IDLE_STATE;
      }
       
      if(arg.reg_orig == SYS_accept)
      {
        printf("[%d] accept_in\n", pid);
        get_args_accept(pid, &arg, &sysarg);
        pid_t conn_pid = process_accept_in_call(pid, &sysarg);
        //if we no process wait for connection we have to put process in idle and save arguments
        if(!conn_pid)
        {
          process_descriptor* proc = process_get_descriptor(pid);
          proc->sysarg.accept = sysarg.accept;
          return PROCESS_IDLE_STATE;
        }
      }
      
      else if(arg.reg_orig == SYS_select)
      {
        THROW_UNIMPLEMENTED;
//         double timeout = get_args_select(pid,&arg);
//         add_launching_time(pid, timeout + SD_get_clock());
//         ptrace_neutralize_syscall(pid);
//         ptrace_resume_process(pid);
//         process_set_out_syscall(pid);
//         return PROCESS_IDLE_STATE;
      }
      
      else if(arg.reg_orig == SYS_recvfrom || arg.reg_orig == SYS_recvmsg)
      {
        printf("[%d] recvfrom_in\n",pid);
        ptrace_resume_process(pid);
        return PROCESS_IDLE_STATE;
      }

      #else

      if(arg.reg_orig == SYS_socketcall)
      {
        if(arg.arg1 == SYS_accept_32)
        {
          printf("[%d] accept_in\n");
          ptrace_resume_process(pid);
          return PROCESS_IDLE_STATE;
        }
        
        else if(arg.arg1 == SYS_select_32)
        {
//           double timeout = get_args_select(pid,&arg);
//           add_launching_time(pid, timeout + SD_get_clock());
//           ptrace_neutralize_syscall(pid);
//           ptrace_resume_process(pid);
//           process_set_out_syscall(pid);
//           return PROCESS_IDLE_STATE;
        }

        else if(arg.arg1 == SYS_recv_32 || arg.arg1 == SYS_recvfrom_32 || arg.arg1 == SYS_recvmsg_32)
        {
          printf("[%d] recvfrom_in\n",pid);
          ptrace_resume_process(pid);
          return PROCESS_IDLE_STATE;
        }
      }
      #endif
    }
    else
    {
      process_set_out_syscall(pid);
      ptrace_get_register(pid, &arg);

      switch (arg.reg_orig) {
        
        case SYS_write:
          printf("[%d] write(%ld, ... , %d) = %ld\n",pid, arg.arg1,(int)arg.arg3, arg.ret);
          if (socket_registered(pid, arg.arg1) != -1) {
            THROW_UNIMPLEMENTED; //non socket interface interaction with socket are not handle yet
          }
          break;

        case SYS_read:
          printf("[%d] read(%ld, ..., %ld) = %ld\n",pid, arg.arg1, arg.arg3, arg.ret);
          if (socket_registered(pid, arg.arg1) != -1) {
            THROW_UNIMPLEMENTED; //non socket interface interaction with socket are not handle yet
          }
          break;

        case SYS_fork: 
          THROW_UNIMPLEMENTED;//Fork are not handle yet
          break;
          
        case SYS_poll:
          THROW_IMPOSSIBLE;
          break;
          
        case SYS_open:
        {
          char *flags = malloc(9);
          switch (arg.arg2) {
            case 0: strcpy(flags,"O_RDONLY"); break;
            case 1: strcpy(flags,"O_WRONLY"); break;
            case 2: strcpy(flags,"O_RDWR"); break;
          }
          if (strlen(flags)>0)
            printf("[%d] open(\"...\", %s) = %ld\n",pid, flags, arg.ret);
          else
            printf("[%d] open(\"...\", no_flags) = %ld\n",pid, arg.ret);
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
            process_set_in_syscall(pid);
          break;
          
        case SYS_close: 
          printf("[%d] close(%ld) = %ld\n",pid, arg.arg1,arg.ret);
          close_sockfd(pid,(int)arg.arg1);
          break;
          
        case SYS_dup:
          printf("[%d] dup(%ld) = %ld\n",pid,arg.arg1,arg.ret);
          THROW_UNIMPLEMENTED; //Dup are not handle yet
          break;
          
        case SYS_dup2:
          printf("[%d] dup2(%ld, %ld) = %ld\n", pid, arg.arg1, arg.arg2, arg.ret);
          THROW_UNIMPLEMENTED; //Dup are not handle yet
          break;
          
        case SYS_execve:
          printf("[%d] execve called\n", pid);
          THROW_UNIMPLEMENTED; //
          break;
              
              
          #if defined(__x86_64)  
          
        case SYS_select: 
          THROW_IMPOSSIBLE;
          break;
          
        case SYS_socket: 
          get_args_socket(pid, &arg, &sysarg);
          print_socket_syscall(pid, &sysarg);
          process_socket_call(pid, &sysarg);
          break;
          
        case SYS_bind:
          get_args_bind_connect(pid, 0, &arg, &sysarg);
          print_bind_syscall(pid, &sysarg);
          process_bind_call(pid, &sysarg);
          break;
          
        case SYS_connect:
          get_args_bind_connect(pid, 1, &arg, &sysarg);
          print_connect_syscall(pid, &(sysarg.connect));
          process_connect_out_call(pid, &sysarg);
          break;
          
        case SYS_accept:
          get_args_accept(pid, &arg, &sysarg);
          print_accept_syscall(pid, &sysarg.accept);
          process_accept_out_call(pid, &sysarg);
          break;
          
        case SYS_listen:
          get_args_listen(pid, &arg, &sysarg);
          print_listen_syscall(pid, &sysarg);
          process_listen_call(pid, &sysarg);
          break;
              
        case SYS_sendto:
          get_args_sendto_recvfrom(pid, 1, &arg, &sysarg);
          print_sendto_syscall(pid, &sysarg);
          process_send_call(pid, sysarg.sendto.sockfd, sysarg.sendto.ret);
          return PROCESS_TASK_FOUND;
          break;
          
        case SYS_recvfrom:
          get_args_sendto_recvfrom(pid, 2, &arg, &sysarg);
          print_recvfrom_syscall(pid, &sysarg);
          if(process_recv_call(pid, sysarg.recvfrom.sockfd, sysarg.recvfrom.ret) == PROCESS_TASK_FOUND)
            return PROCESS_TASK_FOUND;
          break;
          
        case SYS_sendmsg:
          get_args_send_recvmsg(pid, &arg, &sysarg);
          print_sendmsg_syscall(pid, &sysarg);
          process_send_call(pid, sysarg.sendmsg.sockfd, sysarg.sendmsg.ret);
          return PROCESS_TASK_FOUND;
          break;
          
        case SYS_recvmsg:
          get_args_send_recvmsg(pid, &arg, &sysarg);
          print_recvmsg_syscall(pid, &sysarg);
          if(process_recv_call(pid, sysarg.recvmsg.sockfd, sysarg.recvmsg.ret) == PROCESS_TASK_FOUND)
            return PROCESS_TASK_FOUND;
          break;
          
        case SYS_shutdown:
          printf("[%d] shutdown( %ld, ",pid, arg.arg1);
          //Is it really important to know close mode?
    //       char *how=malloc(10);;
    //       switch(arg2){
    //         case 0: strcpy(how,"SHUT_RD"); break;
    //         case 1: strcpy(how,"SHUT_WR"); break;
    //         case 2: strcpy(how,"SHUT_RDWR"); break;
    //       }
    //       printf("%s) = %ld\n",how,ret);
    //       free(how);
          printf(") = %ld\n",arg.ret);
          break;
              
        case SYS_getsockopt:
          get_args_get_setsockopt(pid, 1, &arg, &sysarg);
          print_getsockopt_syscall(pid, &sysarg);
          break;
          
        case SYS_setsockopt:
          get_args_get_setsockopt(pid, 1, &arg, &sysarg);
          print_setsockopt_syscall(pid, &sysarg);
          break;
                
          #else
          
        case SYS__newselect:
          THROW_IMPOSSIBLE;
          break;
          
        case SYS_socketcall:
          switch (arg.arg1) {
            
            case SYS_socket_32:
              printf("[%d] socket( ", pid);
              get_args_socket(pid, &arg);
              printf(" ) = %ld\n", arg.ret);
              break;
              
            case SYS_bind_32:
              printf("[%d] bind( ", pid);
              get_args_bind_connect(pid, 0, &arg, &sysarg);
              printf(" ) = %ld\n",arg.ret);
              break;
              
            case SYS_connect_32:
              printf("[%d] connect( ", pid);
              get_args_bind_connect(pid, 1, &arg, &sysarg);
              printf(" ) = %ld\n", arg.ret);
              if (ret<0)
                printf("%s\n",strerror(-arg.ret));
              ptrace_resume_process(pid);
              return PROCESS_IDLE_STATE;
              break;
                    
            case SYS_listen_32: 
              //TODO add listen mark
              printf("[%d] listen( ", pid); 
              get_args_listen(pid, &arg;
              printf(" ) = %ld\n", arg.ret);
              break;
              
            case SYS_accept_32:
              printf("[%d] accept( ", pid);
              get_args_accept(pid, &arg);
              printf(" ) = %ld\n", arg.ret);
              ptrace_resume_process(pid);
              return PROCESS_IDLE_STATE;
              break;
              
            case SYS_send_32:
              printf("[%d] send( ", pid);
              sockfd=get_args_send_recv(pid, 1, &arg);
              printf(" ) = %ld\n", arg.ret);
              process_send_call(pid, sockfd, arg.ret);
              return PROCESS_TASK_FOUND;
              break;
              
            case SYS_recv_32:
              printf("[%d] recv( ", pid);
              sockfd=get_args_send_recv(pid, 2, &arg);
              printf(" ) = %ld\n", arg.ret);
              if(process_recv_call(pid, sockfd, arg.ret) == PROCESS_TASK_FOUND)
                return PROCESS_TASK_FOUND;
              break;
              
            case SYS_sendto_32:
              printf("[%d] sendto(", pid);
              sockfd=get_args_sendto_recvfrom(pid, 1, &arg);
              printf(" ) = %ld\n", arg.ret); 
              process_send_call(pid, sockfd, arg.ret);
              return PROCESS_TASK_FOUND;
              break;
                    
            case SYS_recvfrom_32:
              printf("[%d] recvfrom(", pid);
              sockfd=get_args_sendto_recvfrom(pid, 2, &arg);
              printf(" ) = %ld\n", arg.ret);
              if(process_recv_call(pid, sockfd, arg.ret) == PROCESS_TASK_FOUND)
                return PROCESS_TASK_FOUND;
              break;
              
            case SYS_shutdown_32:
              printf("shutdown\n");
              break;
              
            case SYS_setsockopt_32:
              printf("[%d] setsockopt(", pid);
              get_args_get_setsockopt(pid, 2, &arg, &sysarg);
              printf("%d\n", (int)arg.ret);
              break;
              
            case SYS_getsockopt_32:
              printf("[%d] getsockopt(", pid);
              get_args_get_setsockopt(pid, 1, &arg, &sysarg);
              printf("%d\n", (int)arg.ret);
              break;
                    
            case SYS_sendmsg_32:
              printf("[%d] sendmsg(", pid);
              sockfd=get_args_send_recvmsg(pid, 1, &arg);
              printf(" ) = %ld\n", ret);
              process_send_call(pid, sockfd, arg.ret);
              return PROCESS_TASK_FOUND;
              break;
              
            case SYS_recvmsg_32:
              printf("[%d] recvmsg(", pid);
              sockfd=get_args_send_recvmsg(pid, 2, &arg);
              printf(" ) = %ld\n", ret);
              if(process_recv_call(pid, sockfd, arg.ret) == PROCESS_TASK_FOUND)
                return PROCESS_TASK_FOUND;
              break;
          }
        break;
                
        #endif
        
        default :
          printf("[%d] Unhandle syscall %s = %ld\n", pid, syscall_list[arg.reg_orig], arg.ret);
          break;
            
      }
    }
    ptrace_resume_process(pid);
    
    //waitpid sur le fils
    waitpid(pid, &status, 0);
    //printf("tempppid = %d\n", temppid);
  }
  
  THROW_IMPOSSIBLE; //There's no way to quit the loop
  
  return 0;
}






