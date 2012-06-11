#include "run_trace.h"
#include "data_utils.h"

process_descriptor *process_descriptor_new(char* name, pid_t pid)
{
  process_descriptor* result = malloc(sizeof(process_descriptor));
  result->name = strdup(name);
  strcat(name, ".txt");
  result->trace = fopen(name, "w");
  result->fd_list = malloc(sizeof(struct infos_socket*)*MAX_FD);
  result->pid=pid;
  int i;
  for(i=0; i<MAX_FD ; ++i)
    result->fd_list[i]=NULL;
}