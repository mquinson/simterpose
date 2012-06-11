#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include "run_trace.h"

process_descriptor *process_descriptor_new(char* name, pid_t pid);

process_descriptor *process_descriptor_get(pid_t pid);

void process_descriptor_set(pid_t pid, process_descriptor* proc);

#endif