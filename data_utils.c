#include "run_trace.h"
#include "data_utils.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"

void init_global_data()
{
  global_data->child_amount = 0;
  global_data->flops_per_second = 0.0;
  global_data->micro_s_per_flop = 0.0;
  global_data->launching_time = NULL;
  
  int i;
  for(i=0; i<MAX_PID; ++i)
  {
      global_data->process_desc[i]=NULL;
  }
}

// double update_simulation_clock()
// {
//   double new_clock = SD_get_clock();
//   double result = new_clock - global_data->last_clock;
//   global_data->last_clock = new_clock;
//   return result;
// }

void launch_process_idling(pid_t pid)
{
  process_set_idle(pid, 0);
  ptrace_resume_process(pid);
}



