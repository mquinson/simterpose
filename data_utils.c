#include "run_trace.h"
#include "data_utils.h"
#include "simdag/simdag.h"
#include "sysdep.h"
#include "process_descriptor.h"

#include <string.h>

void init_global_data()
{
  global_data->launcherpid=0;
  global_data->child_amount=0;
  global_data->last_clock=0;
  global_data->idle_amount=0;
  global_data->not_assigned=0;
  global_data->launcher_com=-1;
  global_data->last_pid_create=0;
  global_data->flops_per_second=0.0;
  global_data->micro_s_per_flop=0.0;
  
  int i;
  for(i=0; i<MAX_PID; ++i)
  {
      global_data->process_desc[i]=NULL;
  }
}

double update_simulation_clock()
{
  double new_clock = SD_get_clock();
  double result = new_clock - global_data->last_clock;
  global_data->last_clock = new_clock;
  return result;
}

void launch_process_idling(pid_t pid)
{
  ++global_data->not_assigned;
  process_set_idle(pid, 0);
  if (ptrace(PTRACE_SYSCALL, pid, NULL, NULL)==-1) {
    perror("ptrace syscall");
    exit(1);
  }
}



