#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "xbt.h"
#include "surf/surfxml_parse.h"

typedef struct {
  char* process_name;
  char* executable;
  double launching_time;
  char** command_line_argument;
  int argument_nbr;
}process_descriptor;

process_descriptor* proc;
process_descriptor** proc_list = NULL;
int proc_amount = 0;

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


static double parse_double(const char *string)
{
  double value;
  char *endptr;
  
  value = strtod(string, &endptr);
  if (*endptr != '\0')
    THROWF(unknown_error, 0, "%s is not a double", string);
  return value;
}

static void cmd(char *fmt, ...) {
  va_list va;
  va_start(va,fmt);
  vfprintf(comm_sim, fmt, va);
  fflush(comm_sim);
}

static void parse_process_init(void)
{
  proc = malloc(sizeof(process_descriptor));
  proc->process_name = strdup(A_surfxml_process_host);
  proc->executable = strdup(A_surfxml_process_function);
  proc->launching_time=-1;
  proc->argument_nbr=1;
  proc->command_line_argument=malloc(sizeof(char*));
  proc->command_line_argument[0] = proc->executable;
}

static void parse_process_finalize(void)
{
  //Starting with add NULL termination to command line
  ++(proc->argument_nbr);
  proc->command_line_argument = realloc(proc->command_line_argument, proc->argument_nbr*sizeof(char*));
  proc->command_line_argument[proc->argument_nbr-1] = NULL;
  
  
  ++proc_amount;
  proc_list = realloc(proc_list, sizeof(process_descriptor*)*proc_amount);
  proc_list[proc_amount-1]=proc;
}

static void parse_argument(void)
{
  if(proc->launching_time == -1)
    proc->launching_time = parse_double(A_surfxml_argument_value);
  else
  {
    ++(proc->argument_nbr);
    proc->command_line_argument = realloc(proc->command_line_argument, proc->argument_nbr*sizeof(char*));
    proc->command_line_argument[proc->argument_nbr-1] = strdup(A_surfxml_argument_value);
  }
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
  xbt_ex_t e;
  
  surf_parse_reset_callbacks();
  
  surfxml_add_callback(STag_surfxml_process_cb_list, parse_process_init);
  surfxml_add_callback(ETag_surfxml_argument_cb_list, parse_argument);
  surfxml_add_callback(ETag_surfxml_process_cb_list, parse_process_finalize);
  
  printf("%s\n", argv[1]);
  
  surf_parse_open(strdup(argv[1]));
  TRY {
    int parse_status = surf_parse();
    surf_parse_close();
    xbt_assert(!parse_status, "Parse error at %s", argv[1]);
  } CATCH(e) {
  }
  
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