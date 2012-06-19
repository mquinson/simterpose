#ifndef INCLUDE_PARSER_H
#define INCLUDE_PARSER_H

typedef struct {
  char* process_name;
  char* executable;
  double launching_time;
  char** command_line_argument;
  int argument_nbr;
}launcher_procdesc;

launcher_procdesc** proc_list;
int proc_amount;


void parse_deployment_file(const char* filename);

void destruct_process_descriptor(launcher_procdesc* proc);


#endif