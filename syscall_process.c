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

#include <linux/futex.h>

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
      struct infos_socket *s = getSocketInfoFromContext(is->ip_remote, is->port_remote);
      
      if(s!=NULL)
        handle_new_send(s,  ret);
      else
        THROW_IMPOSSIBLE;

      SD_task_t task = create_send_communication_task(pid, s, ret);

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
  if(waitpid(pid, &status, WNOHANG))
    return process_handle( pid, status);
  else
    return PROCESS_IDLE_STATE;
}

int process_clone_call(pid_t pid, syscall_arg *arg)
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



int process_handle(pid_t pid, int stat)
{  
  int status = stat;
  int sockfd;
  syscall_arg arg;
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
        ptrace_set_register(pid);
        ptrace_resume_process(pid);
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
      if(arg.reg_orig == SYS_accept || arg.reg_orig == SYS_connect)
      {
        printf("[%d] accept_in\n", pid);
        ptrace_resume_process(pid);
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
          get_args_poll(pid,(void *)arg.arg1, (nfds_t)arg.arg2);
          printf(" = %d \n", (int)arg.ret);
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
          get_args_select(pid,&arg);
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
          ptrace_resume_process(pid);
          return PROCESS_IDLE_STATE;
          break;
          
        case SYS_accept:
          printf("[%d] accept( ", pid);
          get_args_accept(pid, &arg);
          printf(" ) = %ld\n", arg.ret);
          ptrace_resume_process(pid);
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
          get_args_select(pid, &arg);
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






