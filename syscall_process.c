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
  select_arg_t arg = (select_arg_t) process_get_argument(pid);
  
  int i;
  
  fd_set fd_rd, fd_wr, fd_ex;
  
  fd_rd = arg->fd_read;
  fd_wr = arg->fd_write;
  fd_ex = arg->fd_except;
  
  int match = 0;
  
  for(i=0 ; i < arg->maxfd ; ++i)
  {
    struct infos_socket* is = process_get_fd(pid, i);
    //if i is NULL that means that i is not a socket
    if(is == NULL)
      continue;
    int sock_status = socket_get_state(is);
    if(FD_ISSET(i, &(fd_rd)))
    {
      if(sock_status & SOCKET_READ_OK)
        ++match;
      else
        FD_CLR(i, &(fd_rd));
    }
    if(FD_ISSET(i, &(fd_wr)))
    {
      XBT_WARN("Mediation for writing states on socket are not support yet\n");
    }
    if(FD_ISSET(i, &(fd_ex)))
    {
      XBT_WARN("Mediation for exception states on socket are not support yet\n");
    }
  }
  if(match > 0)
  {
    sys_build_select(pid, match);
    return match;
  }
  else
    //printf("No match for select\n");
  return 0;
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

int process_connect_in_call(pid_t pid)
{
  
}



int process_handle(pid_t pid, int stat)
{  
  int status = stat;
  int sockfd;
  reg_s arg;
  while(1)
  {
    
   /* int stat16=status >> 16;
    if (stat16== PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK || stat16== PTRACE_EVENT_CLONE) {
      THROW_UNIMPLEMENTED; //For now fork and clone are not handle by simterpose.
    }*/ 

    if (process_in_syscall(pid)==0) {
      
      process_set_in_syscall(pid);

      ptrace_get_register(pid, &arg);
      
      if(arg.reg_orig == SYS_poll)
      {
        double timeout = get_args_poll(pid, &arg);
        //Now we have to add the process in launching list
        add_launching_time(pid, timeout+SD_get_clock());
        printf(" = %d \n", (int)arg.ret);
        ptrace_neutralize_syscall(pid);
        ptrace_resume_process(pid);
        process_set_out_syscall(pid);
        return PROCESS_IDLE_STATE;
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
        ptrace_resume_process(pid);
        return PROCESS_IDLE_STATE;
      }
      if(arg.reg_orig == SYS_accept)
      {
        printf("[%d] accept_in\n", pid);
        ptrace_resume_process(pid);
        return PROCESS_IDLE_STATE;
      }
      
      else if(arg.reg_orig == SYS_select)
      {
        THROW_UNIMPLEMENTED;
        double timeout = get_args_select(pid,&arg);
        add_launching_time(pid, timeout + SD_get_clock());
        ptrace_neutralize_syscall(pid);
        ptrace_resume_process(pid);
        process_set_out_syscall(pid);
        return PROCESS_IDLE_STATE;
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
          double timeout = get_args_select(pid,&arg);
          add_launching_time(pid, timeout + SD_get_clock());
          ptrace_neutralize_syscall(pid);
          ptrace_resume_process(pid);
          process_set_out_syscall(pid);
          return PROCESS_IDLE_STATE;
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
          printf("[%d] socket( ",pid);
          get_args_socket(pid, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
          
        case SYS_bind:
          printf("[%d] bind( ", pid);
          get_args_bind_connect(pid, 0, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
          
        case SYS_connect:
          printf("[%d] connect( ", pid);
          get_args_bind_connect(pid, 1, &arg);
          printf(" ) = %ld\n", arg.ret);
          process_set_state(pid, PROC_CONNECT);
          return PROCESS_IDLE_STATE;
          break;
          
        case SYS_accept:
          printf("[%d] accept( ", pid);
          int conn_pid = get_args_accept(pid, &arg);
          printf(" ) = %ld\n", arg.ret);
          if(conn_pid == 0)
          {
            THROW_IMPOSSIBLE;
            process_set_state(pid, PROC_ACCEPT);
          }
          else
            process_mark_connect_do(conn_pid);
          return PROCESS_IDLE_STATE;
          break;
          
        case SYS_listen:
          printf("[%d] listen( ", pid); 
          get_args_listen(pid, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
              
        case SYS_sendto:
          printf("[%d] sendto( ", pid);
          sockfd=get_args_sendto_recvfrom(pid, 1, &arg);
          printf(" ) = %ld\n", arg.ret);
          process_send_call(pid, sockfd, arg.ret);
          return PROCESS_TASK_FOUND;
          break;
          
        case SYS_recvfrom:
          printf("[%d] recvfrom( ", pid);
          sockfd=get_args_sendto_recvfrom(pid, 2, &arg);
          printf(" ) = %ld\n",arg.ret);
          if(process_recv_call(pid, sockfd, arg.ret) == PROCESS_TASK_FOUND)
            return PROCESS_TASK_FOUND;
          break;
          
        case SYS_sendmsg:
          printf("[%d] sendmsg( ", pid);
          sockfd=get_args_send_recvmsg(pid, 1, &arg);
          printf(" ) = %ld\n", arg.ret); 
          process_send_call(pid, sockfd, arg.ret);
          return PROCESS_TASK_FOUND;
          break;
          
        case SYS_recvmsg:
          printf("[%d] recvmsg( ", pid);
          sockfd=get_args_send_recvmsg(pid, 2, &arg);
          printf(" ) = %ld\n",arg.ret);
          if(process_recv_call(pid, sockfd, arg.ret) == PROCESS_TASK_FOUND)
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
          printf("[%d] getsockopt(", pid);
          get_args_get_setsockopt(pid, 1, &arg);
          printf("%d\n", (int)arg.ret);
          break;
          
        case SYS_setsockopt:
          printf("[%d] setsockopt(", pid);
          get_args_get_setsockopt(pid, 1, &arg);
          printf("%d\n", (int)arg.ret);
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
              get_args_bind_connect(pid, 0, &arg);
              printf(" ) = %ld\n",arg.ret);
              break;
              
            case SYS_connect_32:
              printf("[%d] connect( ", pid);
              get_args_bind_connect(pid, 1, &arg);
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
              get_args_get_setsockopt(pid, 2, &arg;
              printf("%d\n", (int)arg.ret);
              break;
              
            case SYS_getsockopt_32:
              printf("[%d] getsockopt(", pid);
              get_args_get_setsockopt(pid, 1, &arg);
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
          printf("[%d] Unknown syscall %ld ?= %ld\n", pid, arg.reg_orig, arg.ret);
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






