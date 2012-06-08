#ifndef INCLUDE_RUN_TRACE_H
#define INCLUDE_RUN_TRACE_H

#define MAX_FD 1024

#include "simdag/simdag.h"

//#define DEBUG

typedef struct{
  int pid;
  char* name;
  FILE* trace;
  SD_workstation_t station;
  struct infos_socket** fd_list;
}process_descriptor;


#endif