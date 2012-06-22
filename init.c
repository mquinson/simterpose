#include "parser.h" /* for launcher proc desc*/
#include "run_trace.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"

#include <stdio.h>


void fprint_array(FILE* file, char** array)
{
  int i=0;
  while(array[i]!= NULL)
  {
    fprintf(file, "%s ", array[i]);
    ++i;
  }
  fprintf(file, "\n");
  fflush(file);
}


void run_until_exec(pid_t pid)
{
  int exec_found=0;
  int exec_passed=0;
  int status;
  
  //First we run process until we found the first exec.
  syscall_arg arg;
  while(!exec_found)
  {
    waitpid(pid, &status, 0);
    ptrace_get_register(pid, &arg);
    if(arg.reg_orig == SYS_execve)
    {
      exec_found=1;
    }
    //Here we can run even if we found an execve because we trap the syscall when it came from process
    ptrace_resume_process(pid);
  }
  
  //Second we bring process to the first syscall which is not an execve
  while(!exec_passed)
  {
    waitpid(pid, &status, 0);
    ptrace_get_register(pid, &arg);
    if(arg.reg_orig != SYS_execve)
      exec_passed=1;
    else
      ptrace_resume_process(pid);
  }
}



void init_all_process()
{
  int status;
  
  //First we make pipe for communication and we start running the launcher
  int comm_launcher[2];
  pipe(comm_launcher);
  

  int launcherpid = fork();
  
  if (launcherpid == 0) {
      
    close(comm_launcher[1]);
    //Here to avoid non desire closing
    if(comm_launcher[0] != 3)
    {
      dup2(comm_launcher[0],3);
      close(comm_launcher[0]);
    }
    if (ptrace(PTRACE_TRACEME, 0, NULL, NULL)==-1) {
	perror("ptrace traceme");
      exit(1);
    }
    if (execl("launcher", "launcher", NULL)==-1) {
	perror("execl");
      exit(1);
    }
  
  } else {
    
    close(comm_launcher[0]);
    
    global_data->process_desc[launcherpid]= process_descriptor_new("launcher", launcherpid);
    
    // We wait for the child to be blocked by ptrace in the first exec()
    waitpid(launcherpid, &status, 0);
    
    
    //We set option for trace all of this son
    if (ptrace(PTRACE_SETOPTIONS, launcherpid,NULL,PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)==-1) {
	perror("Error setoptions");
      exit(1);
    }
    
    FILE* launcher_pipe = NULL;
    launcher_pipe = fdopen(comm_launcher[1], "w");
    
    int amount_process_launch = 0;
    int amount = parser_get_amount();
    
    //We initialise launching time array
    global_data->launching_time = malloc(sizeof(time_desc*)*amount);
    
    //We write the amount of process to launch for the launcher
    fprintf(launcher_pipe, "%d\n", amount);
    fflush(launcher_pipe);
    
    
    //Now we launch all process and let them blocked on the first syscall following the exec
    while(amount_process_launch < amount)
    {
      fprint_array(launcher_pipe, parser_get_commandline(amount_process_launch));

      int forked = 0;
      pid_t new_pid;
      while(!forked)
      {
	ptrace_resume_process(launcherpid);
	
	waitpid(launcherpid, &status, 0);
	
	//try to found if it is a fork
	int stat16=status >> 16;
    
	if (stat16== PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK || stat16== PTRACE_EVENT_CLONE) {
	  new_pid = ptrace_get_pid_fork(launcherpid);
	  global_data->process_desc[new_pid] = process_descriptor_new(parser_get_workstation(amount_process_launch), new_pid);
	  forked=1;
	}
      }
      //resume fork syscall
      ptrace_resume_process(launcherpid);
      
      run_until_exec(new_pid);
      process_set_in_syscall(new_pid);
      
      time_desc* t = malloc(sizeof(time_desc));
      t->pid = new_pid;
      t->start_time = parser_get_start_time(amount_process_launch);
      
      global_data->launching_time[amount_process_launch] = t;
      
      ++amount_process_launch;
    }
    
  }
  
  //Now we detach launcher because we don't need it anymore
  ptrace_detach_process(launcherpid);
}