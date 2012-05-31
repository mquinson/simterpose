#include "args_trace.h"
#include "peek_data.h"
#include "sysdep.h"
#include "calc_times_proc.h"
#include "times_proc.h"
#include "sockets.h"
#include "insert_trace.h"
#include "syscalls_io.h"
#include "run_trace.h"

//#define DEBUG
#define BUFFER_SIZE 512


struct time_process all_procs[MAX_PROCS]; 
int nb_procs = 0;
process_descriptor process_desc[MAX_PID];


void usage() {
  printf("usage : ./run_trace [-simgrid] application_test trace_simgrid.txt\n");
}


int main(int argc, char *argv[]) { 

  if (argc<3) {
    usage();
    exit(1);
  }
  
  char buff[256];
  pid_t launcherpid;
  int status;
  int stoppedpid;

  int sockfd;
  int simgrid = 0;

  FILE *trace;

  if(argc==3){
    trace=fopen(argv[2],"w");
    fprintf(trace,"%15s %8s %10s %10s %10s %10s %5s %12s %21s %21s %8s %10s \t%s\n","Timestamp","pidX","wall_time","cpu_time","diff_wall","diff_cpu","type","syscall","local_addr:port", "remote_addr:port","pidY","return","param");
  }else{
    trace=fopen(argv[3],"w");
    
#if defined(DEBUG)
    fprintf(trace,"%8s %12s %8s %10s %10s %21s %21s\n","pidX", "syscall", "pidY", "return","diff_cpu","local_addr:port", "remote_addr:port");
#endif
    simgrid=1;
  }

  int i;
  for(i=0; i<MAX_PID; ++i)
  {
    process_desc[i].name=NULL;
    process_desc[i].trace=NULL;
  }
    
  
  
  struct user_regs_struct regs;
  

  char ret_trace[SIZE_PARAM_TRACE];

  unsigned long reg_orig;
  unsigned long ret;
  unsigned long arg1;
  unsigned long arg2;
  unsigned long arg3;
  
  int comm_launcher[2];
  pipe(comm_launcher);

  init_syscalls_in();
  launcherpid = fork();
  
  if (launcherpid == 0) {
    
    close(comm_launcher[0]);
    dup2(comm_launcher[1],3);
    close(comm_launcher[1]);
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1) {
      perror("ptrace traceme");
      exit(1);
    }
    if (execl("launcher", "launcher", NULL)==-1) {
      perror("execl 1");
      exit(1);
    }
  
  } else {
    //We enter name of processus in array
    printf("launcher pid %d\n", launcherpid);
    process_desc[launcherpid].name=strdup("launcher");
    
    // We wait for the child to be blocked by ptrace in the first exec()
    wait(&status);

    printf("Starting following of %d\n", launcherpid);
    if (ptrace(PTRACE_SETOPTIONS,launcherpid,NULL,PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)==-1) {
      perror("Error setoptions 1");
      exit(1);
    }

    // Resume the child
    if (ptrace(PTRACE_SYSCALL, launcherpid, 0, 0)==-1) {
      perror("ptrace syscall 1");
      exit(1);
    }

    insert_walltime_procs(launcherpid);
    insert_cputime_procs(launcherpid);
      nb_procs++;

   

    if (init_cputime()) {
      perror("Error init cputime");
      exit(1);
    }
	  
    while(1) {
      // __WALL to follow all children
      stoppedpid = waitpid(-1, &status, __WALL);
      if (stoppedpid == -1) {
	perror("wait");
	exit(1);
      }

      if (WIFEXITED(status)) {
        printf("[%d] Child is dead\n",stoppedpid);
	continue;
      }
      

      if (ptrace(PTRACE_GETREGS, stoppedpid,NULL, &regs)==-1) {
	perror("ptrace getregs");
	exit(1);
      }

      int stat16=status >> 16;
      
      if (stat16== PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK) {
	unsigned long new_pid;
	if (ptrace(PTRACE_GETEVENTMSG, stoppedpid, 0, &new_pid)==-1) {
	  perror("ptrace geteventmsg");
	  exit(1);
	}
	if(stoppedpid == launcherpid)
	{
	  char* tmp= buff;
	  int got;
	  while ((got = read(comm_launcher[0],tmp,1))>0) {
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
	  process_desc[new_pid].name = strdup(buff);
	  strcat(buff, ".txt");
	  process_desc[new_pid].trace = fopen(buff, "w");
	  insert_init_trace(new_pid);
	}
	
	
	insert_walltime_procs(new_pid);
	insert_cputime_procs(new_pid);
	nb_procs++;
	printf("new pid with (v)fork %lu by processus %d\n",new_pid, stoppedpid);
	if(stoppedpid != launcherpid)
	  insert_trace_fork_exit(simgrid, trace, stoppedpid, "(v)fork", (int)new_pid);
      } else if (stat16== PTRACE_EVENT_CLONE) {
	unsigned long new_pid;
	if (ptrace(PTRACE_GETEVENTMSG, stoppedpid, 0, &new_pid)==-1) {
	  perror("ptrace geteventmsg");
	  exit(1);
	}
	insert_walltime_procs(new_pid);
	insert_cputime_procs(new_pid);
	nb_procs++;
	printf("new pid with clone %lu\n",new_pid);
	insert_trace_fork_exit(simgrid, trace, stoppedpid, "clone", (int)new_pid);
      } else if(stoppedpid != launcherpid){
    

	/* ---- test archi for registers ---- */

        #if defined(__x86_64) || defined(amd64)
	   reg_orig=regs.orig_rax;
	   ret=regs.rax;
	   arg1=regs.rdi;
	   arg2=regs.rsi;
	   arg3=regs.rdx;
        #elif defined(i386)
           reg_orig=regs.orig_eax;
	   ret=regs.eax;
	   arg1=regs.ebx;
	   arg2=regs.ecx;
	   arg3=regs.edx;
        #endif

	/*------------------*/

	switch (reg_orig) {
	case SYS_write:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    if (socket_registered(stoppedpid,arg1) != -1)
	      insert_trace_comm(simgrid,trace,stoppedpid,(int)arg1,"write","in",-1);
	  } else {
	    printf("[%d] write(%ld, ... , %d) = %ld\n",stoppedpid,arg1,(int)arg3, ret);
	    sprintf(ret_trace,"(%ld,\"...\", %d)",arg1,(int)arg3);
	    set_out_syscall(stoppedpid);
	    if (socket_registered(stoppedpid,arg1) != -1) {
	      if ((int)ret>0 && socket_incomplete(stoppedpid,arg1)) 
		update_socket(stoppedpid,(int)arg1);
	      insert_trace_comm(simgrid, trace,stoppedpid,(int)arg1,"write","out",(int)ret, ret_trace);
	    }
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_read:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    if (socket_registered(stoppedpid,arg1) != -1) 
	      insert_trace_comm(simgrid, trace,stoppedpid,(int)arg1,"read","in", -1);
	  } else { 
	    printf("[%d] read(%ld, ..., %ld) = %ld\n",stoppedpid, arg1,arg3, ret);
	    sprintf(ret_trace,"(%ld, ... , %d)",arg1,(int)arg3);
	    set_out_syscall(stoppedpid);
	    if (socket_registered(stoppedpid,arg1) != -1) {
	      if ((int)ret>0 && socket_incomplete(stoppedpid,arg1)) 
		update_socket(stoppedpid,(int)arg1);
	      insert_trace_comm(simgrid, trace,stoppedpid,(int)arg1,"read","out",(int)ret, ret_trace);
	    }
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_fork:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    printf("[%d] fork = %ld\n", stoppedpid,ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;
	 
	case SYS_poll:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    get_args_poll(stoppedpid,(void *)arg1, (nfds_t)arg2);
	    printf(" = %d \n",(int)ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_open:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    char *flags = malloc(9);
	    switch (arg2) {
	    case 0: strcpy(flags,"O_RDONLY"); break;
	    case 1: strcpy(flags,"O_WRONLY"); break;
	    case 2: strcpy(flags,"O_RDWR"); break;
	    }
	    if (strlen(flags)>0)
	      printf("[%d] open(\"...\", %s) = %ld\n",stoppedpid,flags, ret);
	    else
	      printf("[%d] open(\"...\", no_flags) = %ld\n",stoppedpid, ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_clone:
	  printf("[%d] clone() ?= %ld\n",stoppedpid,ret);
	  break;

	case SYS_close:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    printf("[%d] close(%ld) = %ld\n",stoppedpid,arg1,ret);
	    close_sockfd(stoppedpid,(int)arg1);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_dup:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    printf("[%d] dup(%ld) = %ld\n",stoppedpid,arg1,ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_dup2:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    printf("[%d] dup2(%ld, %ld) = %ld\n",stoppedpid,arg1,arg2,ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_exit_group:
	  printf("[%d] exit_group(%ld) called \n",stoppedpid,arg1);
	  insert_trace_fork_exit(simgrid, trace,stoppedpid,"exit_group",(int)arg1);
	  break;

	case SYS_exit:
	  printf("[%d] exit(%ld) called \n",stoppedpid,arg1);
	  insert_trace_fork_exit(simgrid, trace,stoppedpid,"exit",(int)arg1);
	  break;

	case SYS_execve:
	  printf("[%d] execve called\n",stoppedpid);
	  break;
	  
	  
#if defined(__x86_64)  

	case SYS_select:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    get_args_select(stoppedpid,&regs);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_socket:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    printf("[%d] socket( ",stoppedpid);
	    get_args_socket(stoppedpid,(int)ret, &regs);
	    printf(" ) = %ld\n",ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_bind:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] bind( ",stoppedpid);
	    get_args_bind_connect(stoppedpid,(int)ret,0,&regs);
	    printf(" ) = %ld\n",ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_connect:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] connect( ",stoppedpid);
	    get_args_bind_connect(stoppedpid,(int)ret,1,&regs);
	    printf(" ) = %ld\n",ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_accept:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] accept( ",stoppedpid);
	    get_args_accept(stoppedpid,(int)ret,&regs);
	    printf(" ) = %ld\n",ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_listen:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] listen( ", stoppedpid); 
	    get_args_listen(stoppedpid,&regs);
	    printf(" ) = %ld\n", ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	 case SYS_sendto:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    sockfd=get_args_sendto_recvfrom(stoppedpid,1,ret_trace,&regs);
	    if (socket_registered(stoppedpid,sockfd) != -1) {
	      if (socket_incomplete(stoppedpid,sockfd)) 
		update_socket(stoppedpid,sockfd);
	      if (!socket_netlink(stoppedpid,sockfd))
		insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","in", -1);
	    } 
	  } else {
	    printf("[%d] sendto( ",stoppedpid);
	    sockfd=get_args_sendto_recvfrom(stoppedpid,1,ret_trace,&regs);
	    printf(" ) = %ld\n",ret);
	    if (socket_registered(stoppedpid,sockfd) != -1) {
	      if (socket_incomplete(stoppedpid,sockfd)) 
		update_socket(stoppedpid,sockfd);
	      if (!socket_netlink(stoppedpid,sockfd)) 
		insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","out",(int)ret,ret_trace);   
	    }
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_recvfrom:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,&regs);
	    if (socket_registered(stoppedpid,sockfd) != -1) {
	      if (socket_incomplete(stoppedpid,sockfd)) 
		update_socket(stoppedpid,sockfd);
	      if (!socket_netlink(stoppedpid,sockfd))
		insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","in", -1);
	    } 
	  } else {
	    printf("[%d] recvfrom( ",stoppedpid);
	    sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,&regs);
	    printf(" ) = %ld\n",ret);
	    if (socket_registered(stoppedpid,sockfd) != -1) {
	      if (socket_incomplete(stoppedpid,sockfd)) 
		update_socket(stoppedpid,sockfd);
	      if (!socket_netlink(stoppedpid,sockfd)) 
		insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","out",(int)ret,ret_trace);   
	    }
	    set_out_syscall(stoppedpid);
	  }
	  break;
	 
	case SYS_sendmsg:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    sockfd=get_args_send_recvmsg(stoppedpid,1,ret_trace,&regs);
	    if (socket_registered(stoppedpid,sockfd) != -1) {
	      if (socket_incomplete(stoppedpid,sockfd)) 
		update_socket(stoppedpid,sockfd);
	      if (!socket_netlink(stoppedpid,sockfd))
		insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","in", -1);
	    } 
	   } else {
	     printf("[%d] sendmsg( ",stoppedpid);
	     sockfd=get_args_send_recvmsg(stoppedpid,1,ret_trace,&regs);
	     printf(" ) = %ld\n",ret);
	     if (socket_registered(stoppedpid,sockfd) != -1) {
	       if (socket_incomplete(stoppedpid,sockfd)) 
		 update_socket(stoppedpid,sockfd);
	       if (!socket_netlink(stoppedpid,sockfd)) 
		 insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","out",(int)ret,ret_trace);   
	     }
	     set_out_syscall(stoppedpid);
	   }
	  break;

	case SYS_recvmsg:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    sockfd=get_args_send_recvmsg(stoppedpid,2,ret_trace,&regs);
	    if (socket_registered(stoppedpid,sockfd) != -1) {
	      if (socket_incomplete(stoppedpid,sockfd)) 
		update_socket(stoppedpid,sockfd);
	      if (!socket_netlink(stoppedpid,sockfd))
		insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","in", -1);
	    } 
	   } else {
	     printf("[%d] recvmsg( ",stoppedpid);
	     sockfd=get_args_send_recvmsg(stoppedpid,2,ret_trace,&regs);
	     printf(" ) = %ld\n",ret);
	     if (socket_registered(stoppedpid,sockfd) != -1) {
	       if (socket_incomplete(stoppedpid,sockfd)) 
		 update_socket(stoppedpid,sockfd);
	       if (!socket_netlink(stoppedpid,sockfd)) 
		 insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","out",(int)ret,ret_trace);   
	     }
	     set_out_syscall(stoppedpid);
	   }
	  break;

	case SYS_shutdown:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] shutdown( %ld, ",stoppedpid, arg1);
	    char *how=malloc(10);;
	    switch(arg2){
	    case 0: strcpy(how,"SHUT_RD"); break;
	    case 1: strcpy(how,"SHUT_WR"); break;
	    case 2: strcpy(how,"SHUT_RDWR"); break;
	    }
	    printf("%s) = %ld\n",how,ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_getsockopt:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] getsockopt(",stoppedpid);
	    get_args_get_setsockopt(stoppedpid, 1, &regs);
	    printf("%d\n",(int)ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_setsockopt:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else {
	    printf("[%d] setsockopt(",stoppedpid);
	    get_args_get_setsockopt(stoppedpid, 1, &regs);
	    printf("%d\n",(int)ret);
	    set_out_syscall(stoppedpid);
	  }
	  break;

#else

	case SYS__newselect:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	  } else { 
	    get_args_select(stoppedpid,&regs);
	    set_out_syscall(stoppedpid);
	  }
	  break;

	case SYS_socketcall:
	  if (in_syscall(stoppedpid)==0) {
	    set_in_syscall(stoppedpid);
	    if ((arg1 > 8 && arg1 < 13) || arg1 == 16 || arg1 == 17 ) {
	      char *syscall;
	      switch (arg1) {
	      case 9 :
		syscall="send";
		sockfd=get_args_send_recv(stoppedpid,1,ret_trace,(void *)arg2);
		break;
	      case 10:
		syscall="recv";
		sockfd=get_args_send_recv(stoppedpid,2,ret_trace,(void *)arg2);
		break;
	      case 11:
		syscall="send";
		sockfd=get_args_sendto_recvfrom(stoppedpid,1,ret_trace,(void *)arg2);
		break;
	      case 12:
		syscall="recv";
		sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,(void *)arg2);
		break;
	      case 16:
		syscall="send";
		sockfd=get_args_send_recvmsg(stoppedpid,1,ret_trace,(void *)arg2);
		break;
	      case 17:
		syscall="recv";
		sockfd=get_args_send_recvmsg(stoppedpid,2,ret_trace,(void *)arg2);
		break;
	      }
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		if (!socket_netlink(stoppedpid,sockfd)) 
		  insert_trace_comm(simgrid,trace,stoppedpid,sockfd,syscall,"in", -1);
	      } 
	    }
	  } else { 

	    switch (arg1) {
	    
	    case 1:
	      printf("[%d] socket( ",stoppedpid);
	      get_args_socket(stoppedpid, (int)ret, (void *)arg2,NULL);
	      printf(" ) = %ld\n",ret);
	      break;

	    case 2:
	      printf("[%d] bind( ",stoppedpid);
	      get_args_bind_connect(stoppedpid,(int)ret,0,(void *)arg2);
	      printf(" ) = %ld\n",ret);
	      break;

	    case 3:
	      printf("[%d] connect( ",stoppedpid);
	      get_args_bind_connect(stoppedpid,(int)ret,1,(void *)arg2);
	      printf(" ) = %ld\n",ret);
	      if (ret<0)
		printf("%s\n",strerror(-ret));
	      break;

	    case 4: 
	      printf("[%d] listen( ", stoppedpid); 
	      get_args_listen(stoppedpid,(void *)arg2);
	      printf(" ) = %ld\n", ret);
	      break;

	    case 5:
	      printf("[%d] accept( ",stoppedpid);
	      get_args_accept(stoppedpid,(int)ret, (void *)arg2);
	      printf(" ) = %ld\n",ret);
	      break;

	    case 9:
	      printf("[%d] send( ",stoppedpid);
	      sockfd=get_args_send_recv(stoppedpid,1,ret_trace,(void *)arg2);
	      printf(" ) = %ld\n",ret);
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		 if (!socket_netlink(stoppedpid,sockfd))
		   insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","out",(int)ret,ret_trace);   
	      }
	      break;

	    case 10:
	      printf("[%d] recv( ",stoppedpid);
	      sockfd=get_args_send_recv(stoppedpid,2,ret_trace,(void *)arg2);
	      printf(" ) = %ld\n",ret);
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		if (!socket_netlink(stoppedpid,sockfd)) 
		  insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","out", (int)ret, ret_trace);   
	      }
	      break;

	    case 11:
	      printf("[%d] sendto(",stoppedpid);
	      sockfd=get_args_sendto_recvfrom(stoppedpid,1,ret_trace, (void *)arg2);
	      printf(" ) = %ld\n", ret);
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		if (!socket_netlink(stoppedpid,sockfd)) 
		  insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","out", (int)ret, ret_trace);   
	      }
	      break;

	    case 12:
	      printf("[%d] recvfrom(",stoppedpid);
	      sockfd=get_args_sendto_recvfrom(stoppedpid,2,ret_trace,(void *)arg2);
	      printf(" ) = %ld\n", ret);
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		if (!socket_netlink(stoppedpid,sockfd)) 
		  insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","out", (int)ret);   
	      }
	      break;

	    case 13:
	      printf("shutdown\n");
	      break;

	    case 14:
	      printf("[%d] setsockopt(",stoppedpid);
	      get_args_get_setsockopt(stoppedpid, 2, (void *)arg2);
	      printf("%d\n",(int)ret);
	      break;

	    case 15:
	      printf("[%d] getsockopt(",stoppedpid);
	      get_args_get_setsockopt(stoppedpid, 1, (void *)arg2);
	      printf("%d\n",(int)ret);
	      break;

	    case 16:
	      printf("[%d] sendmsg(",stoppedpid);
	      sockfd=get_args_send_recvmsg(stoppedpid,1,ret_trace,(void *)arg2);
	      printf(" ) = %ld\n", ret);
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		if (!socket_netlink(stoppedpid,sockfd))
		  insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"send","out", (int)ret);  
	      } 
	      break;

	    case 17:
	      printf("[%d] recvmsg(",stoppedpid);
	      sockfd=get_args_send_recvmsg(stoppedpid,2,ret_trace,(void *)arg2);
	      printf(" ) = %ld\n", ret);
	      if (socket_registered(stoppedpid,sockfd) != -1) {
		if (socket_incomplete(stoppedpid,sockfd)) 
		  update_socket(stoppedpid,sockfd);
		if (!socket_netlink(stoppedpid,sockfd))
		  insert_trace_comm(simgrid,trace,stoppedpid,sockfd,"recv","out", (int)ret); 
	      }  
	      break;

	  
	    }
	  
	    set_out_syscall(stoppedpid);
	  }
	  break;

#endif

	default :
	    printf("[%d] Unknown syscall %ld ?= %ld\n", stoppedpid,reg_orig,ret);
	    break;

	}

      
      } 
      if (ptrace(PTRACE_SYSCALL, stoppedpid, NULL, NULL)==-1) {
	perror("ptrace syscall");
	exit(1);
      }

  
   
    }

  }

  fclose(trace);
  return 0;

}
