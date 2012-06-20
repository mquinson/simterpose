#include "parser.h" /* for launcher proc desc*/
#include "run_trace.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"

#include <stdio.h>
#include "sysdep.h"

void fprint_array(FILE* file, char** array)
{
  int i=0;
  while(array[i]!= NULL)
  {
    printf("%s ", array[i]);
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
//   printf("Entering run_until_exec\n");
  
  //First we run process until we found the first exec.
  syscall_arg arg;
  while(!exec_found)
  {
//     printf("New syscall found\n");
    waitpid(pid, &status, 0);
    ptrace_get_register(pid, &arg);
//     printf("New syscall : %lu %lu %d\n", arg.reg_orig, arg.arg1, SYS_clone); 
    if(arg.reg_orig == SYS_execve)
    {
//       printf("Exec found\n");
      exec_found=1;
    }
    //Here we can run even if we found an execve because we trap the syscall when it came from process
    ptrace_resume_process(pid);
  }
  
//   printf("First exec found\n");
  
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
  
//   printf("Leaving run_until_exec\n");
}



void init_all_process()
{
  int status;
  
  //First we make pipe for communication and we start running the launcher
  int comm_launcher[2];
  pipe(comm_launcher);
  

  global_data->launcherpid = fork();
  
  if (global_data->launcherpid == 0) {
      
    close(comm_launcher[1]);
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
	perror("execl 1");
      exit(1);
    }
  
  } else {
    
    close(comm_launcher[0]);
    
    
    printf("launcher pid %d\n", global_data->launcherpid);
    global_data->process_desc[global_data->launcherpid]= process_descriptor_new("launcher", global_data->launcherpid);
    
    // We wait for the child to be blocked by ptrace in the first exec()
    waitpid(global_data->launcherpid, &status, 0);
    
    
    //We set option for trace all of this son
    if (ptrace(PTRACE_SETOPTIONS,global_data->launcherpid,NULL,PTRACE_O_TRACECLONE | PTRACE_O_TRACEFORK | PTRACE_O_TRACEVFORK | PTRACE_O_TRACEVFORKDONE)==-1) {
	perror("Error setoptions 1");
      exit(1);
    }
    
    FILE* launcher_pipe = NULL;
    launcher_pipe = fdopen(comm_launcher[1], "w");
    
    int amount_process_launch = 0;
    
    int amount = parser_get_amount();
    
    printf("%d %d\n", amount, comm_launcher[1]);
    
    //on écrit ensuite sur le file le nombre de process à lancer
//     write(comm_launcher[1], "2\n", 2);
    fprintf(launcher_pipe, "%d\n", amount);
    if(fflush(launcher_pipe)==EOF)
      perror("fflush");
    
    
    //Now we launch all process and let them blocked on the first syscall following the exec
    while(amount_process_launch < amount)
    {
//       printf("new loop %d\n", amount_process_launch);
      fprint_array(launcher_pipe, parser_get_commandline(amount_process_launch));
//       printf("End printing commandline\n");
      int forked = 0;
      pid_t new_pid;
      while(!forked)
      {
	ptrace_resume_process(global_data->launcherpid);
	
	waitpid(global_data->launcherpid, &status, 0);
	
	//try to found if it is a fork
	int stat16=status >> 16;
    
	if (stat16== PTRACE_EVENT_FORK || stat16 == PTRACE_EVENT_VFORK || stat16== PTRACE_EVENT_CLONE) {
          printf("New fork\n");
	  new_pid = ptrace_get_pid_fork(global_data->launcherpid);
	  global_data->process_desc[new_pid] = process_descriptor_new(parser_get_workstation(amount_process_launch), new_pid);
	  forked=1;
	}
      }
      //resume fork syscall
//       printf("Resuming launcher\n");
      ptrace_resume_process(global_data->launcherpid);
      
//       printf("Bring son until exec\n");
      run_until_exec(new_pid);
      
      //Faire l'association start_time pid ici
      
      ++amount_process_launch;
    }
    
  }
  
  
  //pour 0 .. nb_process dans launcher_procdesc
    //Tant que le launcher ne fait pas de fork
      //s'il fait pas un fork on le relance
      //sinon on crée le processus et on passe au suivant
    //on écrit le prochain nom de processus
    //on relance le launcher
  
}