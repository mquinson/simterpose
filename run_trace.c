#include <unistd.h>

#include "args_trace.h"
#include "ptrace_utils.h"
#include "sysdep.h"
#include "calc_times_proc.h"
#include "process_descriptor.h"
#include "sockets.h"
#include "insert_trace.h"
#include "run_trace.h"
#include "benchmark.h"
#include "syscall_process.h"
#include "xbt/fifo.h"
#include "replay.h"
#include "data_utils.h"

#define BUFFER_SIZE 512


void usage(char* progName) {
  printf("usage : %s platform_file.xml deployment_file.xml [-fp flops_power]\n", progName);
}

void print_trace_header(FILE* trace)
{
  fprintf(trace,"%8s %12s %8s %10s %10s %21s %21s\n","pidX", "syscall", "pidY", "return","diff_cpu","local_addr:port", "remote_addr:port");
}


int main(int argc, char *argv[]) { 
  
  global_data = malloc(sizeof(simterpose_data_t));
  init_global_data();

  int status;
  int stoppedpid;

  int sockfd; 

  
  //TODO mettre un vrai gestionnaire d'option et gérer les extensions des fichiers passés en paramètre
  int i, manual_flop=0;
  if(argc>2)
  {
    for(i=3; i<argc; ++i)
    {
      if(!strcmp(argv[i], "-fp"))
      {
	if(argv[i+1] == NULL)
	{
	  usage(argv[0]); 
	}
	else
	{
	  char* endptr = argv[i+1]+strlen(argv[i+1])-1;
	  global_data->flops_per_second = strtod(argv[i+1], &endptr);
	  if(endptr == argv[i+1])
	    usage(argv[0]);
	  else
	  {
	    global_data->micro_s_per_flop  = 1000000/global_data->flops_per_second;
	    manual_flop = 1;
	  }
	}
      }
    }
  }
  else
  {
    usage(argv[0]);
    exit(1);
  }
  
  if(!manual_flop)
    benchmark_matrix_product(&(global_data->flops_per_second), &(global_data->micro_s_per_flop));
  
  SD_init(&argc, argv);
  SD_create_environment(argv[1]);
// 
//   char ret_trace[SIZE_PARAM_TRACE];
// 
//   
//   
//   int comm_launcher[2];
//   pipe(comm_launcher);
// 
//   init_socket_gestion();
//   global_data->launcherpid = fork();
//   
//   if (global_data->launcherpid == 0) {
//     
//     close(comm_launcher[0]);
//     dup2(comm_launcher[1],3);
//     close(comm_launcher[1]);
//     if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1) {
//       perror("ptrace traceme");
//       exit(1);
//     }
//     if (execl("launcher", "launcher", argv[2], NULL)==-1) {
//       perror("execl 1");
//       exit(1);
//     }
//   
//   } else {
//     
//     
//     close(comm_launcher[1]);
//     global_data->launcher_com = comm_launcher[0];
//     
//     //We enter name of processus in array
//     printf("launcher pid %d\n", global_data->launcherpid);
//     global_data->process_desc[global_data->launcherpid]= process_descriptor_new("launcher", global_data->launcherpid);
//     
//     // We wait for the child to be blocked by ptrace in the first exec()
//     wait(&status);
//     
//     if (ptrace(PTRACE_SETOPTIONS,global_data->launcherpid,NULL,PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)==-1) {
//       perror("Error setoptions 1");
//       exit(1);
//     }
// 
//     ++global_data->child_amount;
//     ++global_data->not_assigned;
//     // Resume the launcher
//     resume_process(global_data->launcherpid);
//    
// 
//     if (init_cputime()) {
//       perror("Error init cputime");
//       exit(1);
//     }
//     
// 	  
//       while(global_data->child_amount) {
// 	
// 	//The first loop consist on advance each processus until found task for each
// 	while(global_data->not_assigned)
// 	{
// 	  printf("New tour : left %d not assigned\n", global_data->not_assigned);
// 	  int task_found = 0;
// 	  // __WALL to follow all children
// 	  //TODO parcour de tous les pid dans l'ordre en traitant l'appel système s'il y en a ou en passant à un autre sinon option WNOHANG
// 	  stoppedpid = waitpid(-1, &status, __WALL);
// 
// 	  
// 	  if (WIFEXITED(status)) {
// 	    printf("[%d] Child is dead\n",stoppedpid);
// 	    if (stoppedpid == global_data->launcherpid)
// 	      global_data->launcherpid=0;
// 	    else
// 	      finish_all_communication(stoppedpid);
// 	    --global_data->child_amount;
// 	    --global_data->not_assigned;
// 	    printf("Left %d child\n", global_data->child_amount);
// 	    continue;
// 	  }
// 	  
// 	  
// 	  int stat16=status >> 16;
// 
// 	  if (stat16== PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK || stat16== PTRACE_EVENT_CLONE) {
// 	    ++global_data->not_assigned;
// 	    task_found = process_fork_call(stoppedpid);
// 	  } 
// 	  
// 	  else if(stoppedpid != global_data->launcherpid){
// 	    
// 	    /*If this is the interrupt of the syscall and not the return, we print computation time */
// 	    if (in_syscall(stoppedpid)==0) {
// 	      set_in_syscall(stoppedpid);
// 	      
// 	      get_register(stoppedpid);
// 	      
// 	      #if defined(__x86_64)
// 	      if(reg_orig == SYS_accept)
// 	      {
// 		printf("[%d] accept_in( ");
// 		--global_data->not_assigned;
// 		process_descriptor_set_idle(stoppedpid, 1);
// 	      }
// 
// 	      else if(reg_orig == SYS_recvfrom || reg_orig == SYS_recvmsg)
// 	      {
// 		printf("[%d] recvfrom_in",stoppedpid);
// 		sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,&regs);
// 		if(!is_communication_received(stoppedpid, sockfd))
// 		{
// 		  task_found=1;
// 		  socket_wait_for_sending(stoppedpid, sockfd);
// 		}
// 	      }
// 	      
// 	      #else
// 	      
// 	      if(reg_orig == SYS_socketcall)
// 	      {
// 		if(arg1 == SYS_accept_32)
// 		{
// 		  printf("[%d] accept_in( ");
// 		  --global_data->not_assigned;
// 		  process_descriptor_set_idle(stoppedpid, 1);
// 		}
// 		
// 		else if(arg1 == SYS_recv_32 || arg1 == SYS_recvfrom_32 || arg1 == SYS_recvmsg_32)
// 		{
// 		  printf("[%d] recvfrom_in",stoppedpid);
// 		  sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,&regs);
// 		  if(!is_communication_received(stoppedpid, sockfd))
// 		  {
// 		    task_found=1;
// 		    socket_wait_for_sending(stoppedpid, sockfd);
// 		  }
// 		}
// 	      }
// 	      
// 	      #endif
// 	    }
// 	    else
// 	    {
// 	      get_register(stoppedpid);
// 
// 	      switch (reg_orig) {
// 	      case SYS_write:
// 		printf("[%d] write(%ld, ... , %d) = %ld\n",stoppedpid,arg1,(int)arg3, ret);
// 		if (socket_registered(stoppedpid,arg1) != -1) {
// 		  if ((int)ret>0 && socket_incomplete(stoppedpid,arg1)) 
// 		    update_socket(stoppedpid,(int)arg1);
// 		  insert_trace_comm(stoppedpid,(int)arg1,"write",(int)ret);
// 		}
// 		break;
// 
// 	      case SYS_read:
// 		printf("[%d] read(%ld, ..., %ld) = %ld\n",stoppedpid, arg1,arg3, ret);
// 		if (socket_registered(stoppedpid,arg1) != -1) {
// 		  if ((int)ret>0 && socket_incomplete(stoppedpid,arg1)) 
// 		    update_socket(stoppedpid,(int)arg1);
// 		  insert_trace_comm(stoppedpid,(int)arg1,"read",(int)ret);
// 		}
// 		break;
// 
// 	      case SYS_fork: 
// 		printf("[%d] fork = %ld\n", stoppedpid,ret);
// 		break;
// 	      
// 	      case SYS_poll:
// 		get_args_poll(stoppedpid,(void *)arg1, (nfds_t)arg2);
// 		printf(" = %d \n",(int)ret);
// 		break;
// 
// 	      case SYS_open:
// 	      {
// 		char *flags = malloc(9);
// 		switch (arg2) {
// 		case 0: strcpy(flags,"O_RDONLY"); break;
// 		case 1: strcpy(flags,"O_WRONLY"); break;
// 		case 2: strcpy(flags,"O_RDWR"); break;
// 		}
// 		if (strlen(flags)>0)
// 		  printf("[%d] open(\"...\", %s) = %ld\n",stoppedpid,flags, ret);
// 		else
// 		  printf("[%d] open(\"...\", no_flags) = %ld\n",stoppedpid, ret);
// 	      }
// 	      break;
// 
// 	      case SYS_clone:
// 		printf("[%d] clone() ?= %ld\n",stoppedpid,ret);
// 		break;
// 
// 	      case SYS_close: 
// 		printf("[%d] close(%ld) = %ld\n",stoppedpid,arg1,ret);
// 		close_sockfd(stoppedpid,(int)arg1);
// 		break;
// 
// 	      case SYS_dup:
// 		printf("[%d] dup(%ld) = %ld\n",stoppedpid,arg1,ret);
// 		break;
// 
// 	      case SYS_dup2:
// 		printf("[%d] dup2(%ld, %ld) = %ld\n",stoppedpid,arg1,arg2,ret);
// 		break;
// 
// 	      case SYS_exit_group:
// 		printf("[%d] exit_group(%ld) called \n",stoppedpid,arg1);
// 		insert_trace_fork_exit(stoppedpid,"exit_group",(int)arg1);
// 		break;
// 
// 	      case SYS_exit:
// 		printf("[%d] exit(%ld) called \n",stoppedpid,arg1);
// 		insert_trace_fork_exit(stoppedpid,"exit",(int)arg1);
// 		break;
// 
// 	      case SYS_execve:
// 		printf("[%d] execve called\n",stoppedpid);
// 		process_descriptor* proc = process_descriptor_get(stoppedpid);
// 		if(proc->execve_call_before_start)
// 		{
// 		  --proc->execve_call_before_start;
// 		}
// 		else
// 		{
// 		  if(proc->launch_by_launcher)
// 		    task_found=1;
// 		  else
// 		    THROW_UNIMPLEMENTED; //this is not the direct son
// 		}
// 		break;
// 		
// 		
//       #if defined(__x86_64)  
// 
// 	      case SYS_select: 
// 		get_args_select(stoppedpid,&regs);
// 		break;
// 
// 	      case SYS_socket: 
// 		printf("[%d] socket( ",stoppedpid);
// 		get_args_socket(stoppedpid,(int)ret, &regs);
// 		printf(" ) = %ld\n",ret);
// 		break;
// 
// 	      case SYS_bind:
// 		printf("[%d] bind( ",stoppedpid);
// 		get_args_bind_connect(stoppedpid,(int)ret,0,&regs);
// 		printf(" ) = %ld\n",ret);
// 		break;
// 
// 	      case SYS_connect:
// 		printf("[%d] connect( ",stoppedpid);
// 		get_args_bind_connect(stoppedpid,(int)ret,1,&regs);
// 		printf(" ) = %ld\n",ret);
// 		break;
// 
// 	      case SYS_accept:
// 		printf("[%d] accept( ",stoppedpid);
// 		get_args_accept(stoppedpid,(int)ret,&regs);
// 		++global_data->not_assigned;
// 		process_descriptor_set_idle(stoppedpid, 0);
// 		printf(" ) = %ld\n",ret);
// 		break;
// 
// 	      case SYS_listen:
// 		printf("[%d] listen( ", stoppedpid); 
// 		get_args_listen(stoppedpid,&regs);
// 		printf(" ) = %ld\n", ret);
// 		break;
// 
// 	      case SYS_sendto:
// 		printf("[%d] sendto( ",stoppedpid);
// 		sockfd=get_args_sendto_recvfrom(stoppedpid,1,ret_trace,&regs);
// 		printf(" ) = %ld\n",ret);
// 		task_found = process_send_call(stoppedpid,sockfd,(int)ret);   
// 		break;
// 
// 	      case SYS_recvfrom:
// 		printf("[%d] recvfrom( ",stoppedpid);
// 		sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,&regs);
// 		printf(" ) = %ld\n",ret);
// 		task_found = process_recv_call(stoppedpid,sockfd,(int)ret);
// 		break;
// 	      
// 	      case SYS_sendmsg:
// 		printf("[%d] sendmsg( ",stoppedpid);
// 		sockfd=get_args_send_recvmsg(stoppedpid,1,ret_trace,&regs);
// 		printf(" ) = %ld\n",ret); 
// 		task_found = process_send_call(stoppedpid,sockfd,(int)ret);
// 		break;
// 
// 	      case SYS_recvmsg:
// 		printf("[%d] recvmsg( ",stoppedpid);
// 		sockfd=get_args_send_recvmsg(stoppedpid,2,ret_trace,&regs);
// 		printf(" ) = %ld\n",ret);
// 		task_found = process_recv_call(stoppedpid,sockfd,(int)ret);
// 		break;
// 
// 	      case SYS_shutdown:
// 		printf("[%d] shutdown( %ld, ",stoppedpid, arg1);
// 		char *how=malloc(10);;
// 		switch(arg2){
// 		case 0: strcpy(how,"SHUT_RD"); break;
// 		case 1: strcpy(how,"SHUT_WR"); break;
// 		case 2: strcpy(how,"SHUT_RDWR"); break;
// 		}
// 		printf("%s) = %ld\n",how,ret);;
// 		break;
// 
// 	      case SYS_getsockopt:
// 		printf("[%d] getsockopt(",stoppedpid);
// 		get_args_get_setsockopt(stoppedpid, 1, &regs);
// 		printf("%d\n",(int)ret);
// 		break;
// 
// 	      case SYS_setsockopt:
// 		printf("[%d] setsockopt(",stoppedpid);
// 		get_args_get_setsockopt(stoppedpid, 1, &regs);
// 		printf("%d\n",(int)ret);
// 		break;
// 
//       #else
// 
// 	      case SYS__newselect:
// 		get_args_select(stoppedpid,&regs);
// 		break;
// 
// 	      case SYS_socketcall:
// 		switch (arg1) {
// 		
// 		  case SYS_socket_32:
// 		  printf("[%d] socket( ",stoppedpid);
// 		  get_args_socket(stoppedpid, (int)ret, (void *)arg2,NULL);
// 		  printf(" ) = %ld\n",ret);
// 		  break;
// 
// 		  case SYS_bind_32:
// 		  printf("[%d] bind( ",stoppedpid);
// 		  get_args_bind_connect(stoppedpid,(int)ret,0,(void *)arg2);
// 		  printf(" ) = %ld\n",ret);
// 		  break;
// 
// 		  case SYS_connect_32:
// 		  printf("[%d] connect( ",stoppedpid);
// 		  get_args_bind_connect(stoppedpid,(int)ret,1,(void *)arg2);
// 		  printf(" ) = %ld\n",ret);
// 		  if (ret<0)
// 		    printf("%s\n",strerror(-ret));
// 		  break;
// 
// 		  case SYS_listen_32: 
// 		  printf("[%d] listen( ", stoppedpid); 
// 		  get_args_listen(stoppedpid,(void *)arg2);
// 		  printf(" ) = %ld\n", ret);
// 		  break;
// 
// 		  case SYS_accept_32:
// 		  printf("[%d] accept( ",stoppedpid);
// 		  get_args_accept(stoppedpid,(int)ret, (void *)arg2);
// 		  printf(" ) = %ld\n",ret);
// 		  break;
// 
// 		  case SYS_send_32:
// 		  printf("[%d] send( ",stoppedpid);
// 		  sockfd=get_args_send_recv(stoppedpid,1,ret_trace,(void *)arg2);
// 		  printf(" ) = %ld\n",ret);
// 		  task_found = process_send_call(stoppedpid,sockfd,(int)ret);
// 		  break;
// 
// 		  case SYS_recv_32:
// 		  printf("[%d] recv( ",stoppedpid);
// 		  sockfd=get_args_send_recv(stoppedpid,2,ret_trace,(void *)arg2);
// 		  printf(" ) = %ld\n",ret);
// 		  task_found = process_recv_call(stoppedpid,sockfd,(int)ret);
// 		  break;
// 
// 		  case SYS_sendto_32:
// 		  printf("[%d] sendto(",stoppedpid);
// 		  sockfd=get_args_sendto_recvfrom(stoppedpid,1,ret_trace, (void *)arg2);
// 		  printf(" ) = %ld\n", ret); 
// 		  task_found = process_send_call(stoppedpid,sockfd,(int)ret);
// 		  break;
// 
// 		  case SYS_recvfrom_32:
// 		  printf("[%d] recvfrom(",stoppedpid);
// 		  sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,(void *)arg2);
// 		  printf(" ) = %ld\n", ret);
// 		  task_found = process_recv_call(stoppedpid,sockfd,(int)ret);
// 		  break;
// 
// 		  case SYS_shutdown_32:
// 		  printf("shutdown\n");
// 		  break;
// 
// 		  case SYS_setsockopt_32:
// 		  printf("[%d] setsockopt(",stoppedpid);
// 		  get_args_get_setsockopt(stoppedpid, 2, (void *)arg2);
// 		  printf("%d\n",(int)ret);
// 		  break;
// 
// 		  case SYS_getsockopt_32:
// 		  printf("[%d] getsockopt(",stoppedpid);
// 		  get_args_get_setsockopt(stoppedpid, 1, (void *)arg2);
// 		  printf("%d\n",(int)ret);
// 		  break;
// 
// 		  case SYS_sendmsg_32:
// 		  printf("[%d] sendmsg(",stoppedpid);
// 		  sockfd=get_args_send_recvmsg(stoppedpid,1,ret_trace,(void *)arg2);
// 		  printf(" ) = %ld\n", ret);
// 		  task_found = process_send_call(stoppedpid,sockfd,(int)ret);
// 		  break;
// 
// 		  case SYS_recvmsg_32:
// 		  printf("[%d] recvmsg(",stoppedpid);
// 		  sockfd=get_args_send_recvmsg(stoppedpid,2,ret_trace,(void *)arg2);
// 		  printf(" ) = %ld\n", ret);
// 		  task_found = process_recv_call(stoppedpid,sockfd,(int)ret);
// 		  break;
// 
// 	      
// 		}
// 		break;
// 
//       #endif
// 
// 	      default :
// 		  printf("[%d] Unknown syscall %ld ?= %ld\n", stoppedpid,reg_orig,ret);
// 		  break;
// 
// 	      }
// 	      set_out_syscall(stoppedpid);
// 	    
// 	    }
// 	  }
// 	  
// 	  //if the syscalls we trap doesn't lead to a task we resume child to found the next one
// 	  if(!task_found)
// 	  {
// 	    resume_process(stoppedpid);
// 	  }
// 	  else
// 	  {
// 	    --(global_data->not_assigned);
// 	    printf("(left %d) New task found for pid %d\n",global_data->not_assigned, stoppedpid);
// 	  }
// 	}//End of task reserach loop
// 	
// 	if(!global_data->child_amount)
// 	  break;
// 	
// 	
// 	//Here, all process have there own task to execute (or there are idle) so we can start simulation
// 	double* next_time = xbt_fifo_get_item_content(xbt_fifo_get_first_item(global_data->time_to_next));
// 	
// 	printf("\t\t\t\t\t NEW SIMULATION TURN with time %lf\n", *next_time);
// 	xbt_dynar_t arr = SD_simulate(*next_time);
// 	
// 	//Now there is two case.
// 	//	1: there no processus in arr and we have to launch the next processus.
// 	//	2: there's processus and we have to substract time and resume these processus.
// 	if(xbt_dynar_is_empty(arr))
// 	{
// 	  xbt_fifo_shift(global_data->time_to_next);
// 	  printf("New simulation time %lf\n", update_simulation_clock());
// 	  if(global_data->launcherpid)
// 	  {
// 	    resume_process(global_data->launcherpid);
// 	  }
// 	  resume_process(global_data->last_pid_create);
// 	  
// 	  global_data->not_assigned +=2;
// 	}
// 	else
// 	{
// 	  //We update time only if there are always process to launch
// 	  if(*next_time != -1)
// 	    *next_time -= update_simulation_clock();
// 	  
// 	  SD_task_t temp_task;
// 	  unsigned int cpt;
// 	  xbt_dynar_foreach(arr, cpt, temp_task){
// 	    if(SD_task_get_state(temp_task) == SD_DONE)
// 	    {
// 	      int* data = (int *)SD_task_get_data(temp_task);
// 	      //if data is null, that significate that is a task we don't watch
// 	      if(data!=NULL)
// 	      {
// 		if (ptrace(PTRACE_SYSCALL, *data, NULL, NULL)==-1) {
// 		  perror("ptrace syscall");
// 		  exit(1);
// 		}
// 		++global_data->not_assigned;
// 	      }
// 	    }
// 	  }
// 	}
//       }
//       
//       
//   //Now we have to run simulation until the end
// 
//   xbt_dynar_t arr;
//   do{
//     arr = SD_simulate(-1);
//   }while(!xbt_dynar_is_empty(arr));
// 
//   
//   
//   
//   printf("Result of simulation -> %lf s\n", SD_get_clock());
//   }
  return 0;

}
