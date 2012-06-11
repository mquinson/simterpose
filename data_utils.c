#include "run_trace.h"
#include "data_utils.h"
#include "simdag/simdag.h"

#include <string.h>

process_descriptor *process_descriptor_new(char* name, pid_t pid)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  result->name = strdup(name);
  char buff[256];
  strcpy(buff, name);
  strcat(buff, ".txt");
  result->trace = fopen(buff, "w");
  result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
  result->pid=pid;
  result->cpu_time=0;
  result->syscall_in = 0;
  int i;
  for(i=0; i<MAX_FD ; ++i)
    result->fd_list[i]=NULL;
  
  result->station = SD_workstation_get_by_name(result->name);
  
  return result;
}

//TODO regarder l'inline pour cette fonction
process_descriptor *process_descriptor_get(pid_t pid)
{
  return global_data->process_desc[pid];
}

void process_descriptor_set(pid_t pid, process_descriptor* proc)
{
  global_data->process_desc[pid]=proc;
}