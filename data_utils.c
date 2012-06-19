#include "run_trace.h"
#include "data_utils.h"
#include "simdag/simdag.h"
#include "sysdep.h"
#include "process_descriptor.h"

#include <string.h>


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



