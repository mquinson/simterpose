#include <unistd.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <sys/types.h>
#include <sys/wait.h>

#include "parser.h"
#include "xbt.h"
#include "surf/surfxml_parse.h"


process_descriptor* proc;

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

static void parse_process_init(void)
{
  proc = malloc(sizeof(process_descriptor));
  proc->process_name = strdup(A_surfxml_process_host);
  proc->executable = strdup(A_surfxml_process_function);
  proc->launching_time=parse_double(A_surfxml_process_start_time);
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
  ++(proc->argument_nbr);
  proc->command_line_argument = realloc(proc->command_line_argument, proc->argument_nbr*sizeof(char*));
  proc->command_line_argument[proc->argument_nbr-1] = strdup(A_surfxml_argument_value);
}

void parse_deployment_file(const char* filename)
{
  xbt_ex_t e;
  
  surf_parse_reset_callbacks();
  
  surfxml_add_callback(STag_surfxml_process_cb_list, parse_process_init);
  surfxml_add_callback(ETag_surfxml_argument_cb_list, parse_argument);
  surfxml_add_callback(ETag_surfxml_process_cb_list, parse_process_finalize);
  
  surf_parse_open(filename);
  TRY {
    int parse_status = surf_parse();
    surf_parse_close();
    xbt_assert(!parse_status, "Parse error at %s", filename);
  } CATCH(e) {
  }
}

