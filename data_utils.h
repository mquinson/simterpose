#ifndef INCLUDE_DATA_UTILS_H
#define INCLUDE_DATA_UTILS_H

#include "run_trace.h"

void init_global_data();

double update_simulation_clock();

void launch_process_idling(pid_t pid);

#endif