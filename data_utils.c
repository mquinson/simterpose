#include "run_trace.h"
#include "data_utils.h"
#include "process_descriptor.h"
#include "ptrace_utils.h"
#include "xbt.h"
#include "simdag/simdag.h" /* For SD_get_clock() */

void init_global_data()
{
  global_data->child_amount = 0;
  global_data->flops_per_second = 0.0;
  global_data->micro_s_per_flop = 0.0;
  global_data->launching_time = xbt_dynar_new(sizeof(time_desc*), NULL);
  
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


double get_next_start_time()
{
  if(xbt_dynar_is_empty(global_data->launching_time))
    return -1;
  
  time_desc** t = (time_desc**)xbt_dynar_get_ptr(global_data->launching_time, 0);
  return (*t)->start_time;
}

pid_t pop_next_pid()
{
  time_desc* t = NULL;
  xbt_dynar_shift(global_data->launching_time, &t);
  int res = t->pid;
  free(t);
  return res;
}

void add_launching_time(pid_t pid, double start_time)
{
  time_desc* t = malloc(sizeof(time_desc));
  t->pid = pid;
  t->start_time = start_time;
  
  xbt_dynar_push(global_data->launching_time, &t);
}

void set_next_launchment(pid_t pid)
{
  time_desc* t = malloc(sizeof(time_desc));
  t->pid = pid;
  t->start_time = SD_get_clock();
  
  xbt_dynar_unshift(global_data->launching_time, &t);
}

int has_sleeping_to_launch()
{
  return !xbt_dynar_is_empty(global_data->launching_time);
}

