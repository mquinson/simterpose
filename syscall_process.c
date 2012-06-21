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
      struct infos_socket *s = getSocketInfoFromContext(is->ip_local, is->port_local, is->ip_remote, is->port_remote);
      
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
  printf("Entering process_recv_call %d\n", global_data->not_assigned);
  if (socket_registered(pid,sockfd) != -1) {
    if (socket_incomplete(pid,sockfd)) 
      update_socket(pid,sockfd);
    if (!socket_netlink(pid,sockfd))
    {
      calculate_computation_time(pid);
      //if handle_new_receive return 1, we have assigned a new task so one processus are assigned
      if(handle_new_receive(pid, sockfd, ret))
      {
// 	if(!process_descriptor_get_idle(pid))
        return 1;
      }
    }
  }
  return 0;
}

int process_fork_call(int pid)
{
  printf("New fork\n");
  unsigned long new_pid;
  if (ptrace(PTRACE_GETEVENTMSG, pid, 0, &new_pid)==-1) {
    perror("ptrace geteventmsg");
    exit(1);
  }
//   if(pid == global_data->launcherpid)
//   {
    global_data->last_pid_create = new_pid;
    printf("Creation of pid %lud\n", new_pid);
    char buff[256];
    char* tmp= buff;
    int got;
    while ((got = read(global_data->launcher_com,tmp,1))>0) {
      if(*tmp=='\n')
      {
	*tmp='\0';
	break;
      }
      else
	++tmp;
    }
    if(got <0)
    {
      perror("read");
      exit(1);
    }
    char name[256];
    double *next = malloc(sizeof(double));
    sscanf(buff, "%s %lf", name, next);

    global_data->process_desc[new_pid] = process_descriptor_new(name, new_pid);
    global_data->process_desc[new_pid]->launch_by_launcher = 1;
    
    #if defined(DEBUG)
    print_trace_header(global_data->process_desc[new_pid]->trace);
    #endif
    printf("New application launch\n");
    insert_init_trace(new_pid);


    printf("new pid with (v)fork %lu by processus %d\n",new_pid, pid);
//     if(pid != global_data->launcherpid)
//       insert_trace_fork_exit(pid, "(v)fork", (int)new_pid);
    ++global_data->child_amount;
    return 1;
//   }
//   else//This is an application which fork
//   {
    insert_trace_fork_exit(pid, "fork", (int)new_pid);
    ++global_data->child_amount;
    return 0;
//   }
}



int process_handle(pid_t pid, SD_task_t task)
{
  //Tant que les poules ne font pas des gauffres
  
  int status;
  int sockfd;
  char ret_trace[SIZE_PARAM_TRACE]; 
  syscall_arg arg;
  while(1)
  {
    //waitpid sur le fils
    waitpid(pid, &status, 0);
    
    if (WIFEXITED(status)) {
      printf("[%d] Child is dead\n",pid);
      return PROCESS_DEAD;
    }
    
    int stat16=status >> 16;
    if (stat16== PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK || stat16== PTRACE_EVENT_CLONE) {
      THROW_UNIMPLEMENTED; //For now fork and clone are not handle by simterpose.
    } 
    
    if (process_in_syscall(pid)==0) {
      process_set_in_syscall(pid);

      ptrace_get_register(pid, &arg);

      #if defined(__x86_64)
      if(arg.reg_orig == SYS_accept)
      {
        printf("[%d] accept_in", pid);
        ptrace_resume_process(pid);
        return PROCESS_IDLE_STATE;
      }

      else if(arg.reg_orig == SYS_recvfrom || arg.reg_orig == SYS_recvmsg)
      {
        printf("[%d] recvfrom_in",pid);
        ptrace_resume_process(pid);
        return PROCESS_IDLE_STATE;
      }

      #else

      if(arg.reg_orig == SYS_socketcall)
      {
        if(arg.arg1 == SYS_accept_32)
        {
          printf("[%d] accept_in( ");
          ptrace_resume_process(pid);
          return PROCESS_IDLE_STATE;
        }

        else if(arg.arg1 == SYS_recv_32 || arg.arg1 == SYS_recvfrom_32 || arg.arg1 == SYS_recvmsg_32)
        {
          printf("[%d] recvfrom_in",pid);
          ptrace_resume_process(pid);
          return PROCESS_IDLE_STATE;
        }
      }
      #endif
    }
    else
    {
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
          printf("[%d] clone\n",pid);
          THROW_UNIMPLEMENTED; //Clone are not handle yet
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
          
        case SYS_exit_group:
          printf("[%d] exit_group(%ld) called \n",pid, arg.arg1);
          //insert_trace_fork_exit(pid,"exit_group", (int)arg.arg1);
          break;
          
        case SYS_exit:
          printf("[%d] exit(%ld) called \n", pid, arg.arg1);
          //insert_trace_fork_exit(pid,"exit",(int)arg.arg1);
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
          get_args_socket(pid, (int)arg.ret, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
          
        case SYS_bind:
          printf("[%d] bind( ", pid);
          get_args_bind_connect(pid,(int)arg.ret, 0, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
          
        case SYS_connect:
          printf("[%d] connect( ", pid);
          get_args_bind_connect(pid, (int)arg.ret, 1, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
          
        case SYS_accept:
          printf("[%d] accept( ", pid);
          get_args_accept(pid, (int)arg.ret, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
          
        case SYS_listen:
          printf("[%d] listen( ", pid); 
          get_args_listen(pid, &arg);
          printf(" ) = %ld\n", arg.ret);
          break;
              
        case SYS_sendto:
          printf("[%d] sendto( ", pid);
          sockfd=get_args_sendto_recvfrom(pid, 1, ret_trace, &arg);
          printf(" ) = %ld\n", arg.ret);
          //FIXME   
          break;
          
        case SYS_recvfrom:
          printf("[%d] recvfrom( ", pid);
          sockfd=get_args_sendto_recvfrom(pid, 2, ret_trace, &arg);
          printf(" ) = %ld\n",arg.ret);
          //FIXME
          break;
          
        case SYS_sendmsg:
          printf("[%d] sendmsg( ", pid);
          sockfd=get_args_send_recvmsg(pid, 1, ret_trace, &arg);
          printf(" ) = %ld\n", arg.ret); 
          //FIXME
          break;
          
        case SYS_recvmsg:
          printf("[%d] recvmsg( ", pid);
          sockfd=get_args_send_recvmsg(pid, 2, ret_trace, &arg);
          printf(" ) = %ld\n",arg.ret);
          //FIXME
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
              get_args_socket(pid, (int)arg.ret, (void *)arg.arg2, NULL);
              printf(" ) = %ld\n", arg.ret);
              break;
              
            case SYS_bind_32:
              printf("[%d] bind( ", pid);
              get_args_bind_connect(pid, (int)arg.ret, 0, (void *)arg.arg2);
              printf(" ) = %ld\n",arg.ret);
              break;
              
            case SYS_connect_32:
              printf("[%d] connect( ", pid);
              get_args_bind_connect(pid, (int)arg.ret, 1, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret);
              if (ret<0)
                printf("%s\n",strerror(-arg.ret));
              break;
                    
            case SYS_listen_32: 
              printf("[%d] listen( ", pid); 
              get_args_listen(pid, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret);
              break;
              
            case SYS_accept_32:
              printf("[%d] accept( ", pid);
              get_args_accept(pid, (int)arg.ret, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret);
              break;
              
            case SYS_send_32:
              printf("[%d] send( ", pid);
              sockfd=get_args_send_recv(pid, 1, ret_trace, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret);
              //FIXME
              break;
              
            case SYS_recv_32:
              printf("[%d] recv( ", pid);
              sockfd=get_args_send_recv(pid, 2, ret_trace, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret);
              //FIXME
              break;
              
            case SYS_sendto_32:
              printf("[%d] sendto(", pid);
              sockfd=get_args_sendto_recvfrom(pid, 1, ret_trace, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret); 
              //FIXME
              break;
                    
            case SYS_recvfrom_32:
              printf("[%d] recvfrom(", pid);
              sockfd=get_args_sendto_recvfrom(pid, 2, ret_trace, (void *)arg.arg2);
              printf(" ) = %ld\n", arg.ret);
              //FIXME
              break;
              
            case SYS_shutdown_32:
              printf("shutdown\n");
              break;
              
            case SYS_setsockopt_32:
              printf("[%d] setsockopt(", pid);
              get_args_get_setsockopt(pid, 2, (void *)arg.arg2);
              printf("%d\n", (int)arg.ret);
              break;
              
            case SYS_getsockopt_32:
              printf("[%d] getsockopt(", pid);
              get_args_get_setsockopt(pid, 1, (void *)arg.arg2);
              printf("%d\n", (int)arg.ret);
              break;
                    
            case SYS_sendmsg_32:
              printf("[%d] sendmsg(", pid);
              sockfd=get_args_send_recvmsg(pid, 1, ret_trace, (void *)arg.arg2);
              printf(" ) = %ld\n", ret);
              //FIXME
              break;
              
            case SYS_recvmsg_32:
              printf("[%d] recvmsg(", pid);
              sockfd=get_args_send_recvmsg(pid, 2, ret_trace, (void *)arg.arg2);
              printf(" ) = %ld\n", ret);
              //FIXME
              break;
              
              
          }
        break;
                
        #endif
        
        default :
          printf("[%d] Unknown syscall %ld ?= %ld\n", pid, arg.reg_orig, arg.ret);
          break;
            
      }
      process_set_out_syscall(pid);
    }
    
    
    //analyse du syscall
    //débloquer le fils
  }
  return 0;
}






