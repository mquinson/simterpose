#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/types.h>

#include "parser.h"
#include <xbt.h>
#include "surf/surfxml_parse.h"
#include "simgrid/platf.h"

XBT_LOG_NEW_DEFAULT_SUBCATEGORY(PARSE, SIMTERPOSE, "parsing of command-line");

int proc_amount = 0;
launcher_procdesc **proc_list = NULL;

void destruct_process_descriptor(launcher_procdesc * proc)
{
  free(proc->process_name);
  free(proc->executable);
  xbt_dynar_free(&(proc->command_line_argument));
  free(proc);
}

static void parse_process(sg_platf_process_cbarg_t args)
{
  launcher_procdesc *proc;
  int i;

  proc = malloc(sizeof(launcher_procdesc));
  proc->process_name = strdup(args->host);
  proc->executable = strdup(args->function);
  proc->launching_time = args->start_time;

  proc->command_line_argument = xbt_dynar_new(sizeof(char *), &xbt_free_ref);
  for (i = 0; i < args->argc; i++) {
    char *val = (args->argv[i] == NULL) ? NULL : xbt_strdup(args->argv[i]);
    xbt_dynar_push(proc->command_line_argument, &val);
  }

  ++proc_amount;
  proc_list = realloc(proc_list, sizeof(launcher_procdesc *) * proc_amount);
  proc_list[proc_amount - 1] = proc;
}

static int compare_time(const void *proc1, const void *proc2)
{
  int time1 = (*((launcher_procdesc **) proc1))->launching_time;
  int time2 = (*((launcher_procdesc **) proc2))->launching_time;

  if (time1 < time2)
    return -1;
  else if (time1 == time2)
    return 0;
  else
    return 1;
}

void parse_deployment_file(const char *filename)
{
  surf_parse_reset_callbacks();
  sg_platf_process_add_cb(parse_process);

  surf_parse_open(filename);
  int parse_status = surf_parse();
  surf_parse_close();
  xbt_assert(!parse_status, "Parse error at %s", filename);

  qsort(proc_list, proc_amount, sizeof(launcher_procdesc *), compare_time);
}

xbt_dynar_t parser_get_commandline(int rank)
{
  return proc_list[rank]->command_line_argument;
}

char *parser_get_workstation(int rank)
{
  return proc_list[rank]->process_name;
}

int parser_get_amount()
{
  return proc_amount;
}

double parser_get_start_time(int rank)
{
  return proc_list[rank]->launching_time;
}


void parser_free_all()
{
  int i;
  for (i = 0; i < proc_amount; ++i) {
    destruct_process_descriptor(proc_list[i]);
  }
  free(proc_list);
}
