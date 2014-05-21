#ifndef INCLUDE_PARSER_H
#define INCLUDE_PARSER_H

typedef struct {
  char *process_name;
  char *executable;
  double launching_time;
  char **command_line_argument;
  int argument_nbr;
} launcher_procdesc;

launcher_procdesc **proc_list;



void parse_deployment_file(const char *filename);

void destruct_process_descriptor(launcher_procdesc * proc);

char **parser_get_commandline(int numero);

char *parser_get_workstation(int numero);

double parser_get_start_time(int numero);

int parser_get_amount();

void parser_free_all();


#endif
