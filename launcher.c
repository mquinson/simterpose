#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "xbt.h"
#include "surf/surfxml_parse.h"
#include "parser.h"

process_descriptor* proc;

FILE* comm_sim;


static int compare_time(const void* proc1, const void* proc2)
{
  int time1 = (*((process_descriptor**)proc1))->launching_time;
  int time2 = (*((process_descriptor**)proc2))->launching_time;
  
  if (time1 < time2)
    return -1;
  else if ( time1 == time2 )
    return 0;
  else
    return 1;
}


static void cmd(char *fmt, ...) {
  va_list va;
  va_start(va,fmt);
  vfprintf(comm_sim, fmt, va);
  fflush(comm_sim);
}

void destruct_process_descriptor(process_descriptor* proc)
{
  free(proc->process_name);
  int i;
  for(i=0; i< proc->argument_nbr-1; ++i)
    free(proc->command_line_argument[i]);
  free(proc->command_line_argument);
  //We don't free executable because it is already free when freeing command_line member
  
}

int main (int argc, char** argv)
{
  
  surf_init (&argc, argv);
  parse_deployment_file(argv[1]);

  qsort(proc_list, proc_amount, sizeof(process_descriptor*), compare_time);
  
  comm_sim = fdopen(3, "w");
  double time_before_next=0.0;
  int numero=0;
  
  while(numero < proc_amount)
  {
    if(numero == proc_amount-1)
      time_before_next=-1;
    else
      time_before_next = proc_list[numero+1]->launching_time - proc_list[numero]->launching_time;
  
    cmd("%s %lf\n", proc_list[numero]->process_name, time_before_next);
    int pid = fork();
    if(pid==0)
    {
      if (execv(proc_list[numero]->executable, proc_list[numero]->command_line_argument)==-1) {
	perror("execl server");
	exit(1);
      }
    }
    
    destruct_process_descriptor(proc_list[numero]);
    ++numero;
  }
  
  fclose(comm_sim);
  return EXIT_SUCCESS;
}