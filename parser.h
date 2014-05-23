#ifndef INCLUDE_PARSER_H
#define INCLUDE_PARSER_H

#include <xbt/dynar.h>

typedef struct {
  char *process_name;
  char *executable;
  double launching_time;
  xbt_dynar_t command_line_argument;
} launcher_procdesc;

launcher_procdesc **proc_list;



void parse_deployment_file(const char *filename);

void destruct_process_descriptor(launcher_procdesc * proc);

xbt_dynar_t parser_get_commandline(int numero);

char *parser_get_workstation(int numero);

double parser_get_start_time(int numero);

int parser_get_amount();

void parser_free_all();


#endif
