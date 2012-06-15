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
  printf("Entering parse_process_init %s %s\n", A_surfxml_process_host, A_surfxml_process_function);
  proc = malloc(sizeof(process_descriptor));
  proc->process_name = strdup(A_surfxml_process_host);
  proc->executable = strdup(A_surfxml_process_function);
  proc->launching_time=-1;
  proc->argument_nbr=0;
  proc->command_line_argument=NULL;
}

static void parse_process_finalize(void)
{
  printf("Entering parse_process_finalize");
  ++proc_amount;
  proc_list = realloc(proc_list, sizeof(process_descriptor*)*proc_amount);
  proc_list[proc_amount-1]=proc;
  
  printf(" %d process create\n", proc_amount);
}

static void parse_argument(void)
{
  printf("Entering parse_argument %s\n", A_surfxml_argument_value);
  if(proc->launching_time == -1)
    proc->launching_time = parse_double(A_surfxml_argument_value);
  else
  {
    ++(proc->argument_nbr);
    proc->command_line_argument = realloc(proc->command_line_argument, proc->argument_nbr*sizeof(char*));
    proc->command_line_argument[proc->argument_nbr-1] = strdup(A_surfxml_argument_value);
  }
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
//   printf("%s %s\n", proc_list[0]->process_name, proc_list[1]->process_name);
  
  comm_sim = fdopen(3, "w");
  
  cmd("Tremblay 3\n");
  int pid = fork();
  if(pid==0)
  {
    if (execl("applications/server", "applications/server", NULL)==-1) {
      perror("execl server");
      exit(1);
    }
  }
  
  
  cmd("Jupiter -1\n");
  pid = fork(); 
  if(pid==0)
  {
    if (execl("applications/client", "applications/client", NULL)==-1) {
      perror("execl client");
      exit(1);
    }
  }
  
  
  return EXIT_SUCCESS;
}