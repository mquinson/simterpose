#include "run_trace.h"
#include "data_utils.h"
#include "process_descriptor.h"
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

void destroy_global_data()
{
  xbt_dynar_free(&(global_data->launching_time));
  free(global_data);
}

double get_next_start_time()
{
  if(xbt_dynar_is_empty(global_data->launching_time))
    return -1;
  
  time_desc** t = (time_desc**)xbt_dynar_get_ptr(global_data->launching_time, 0);
  printf("Next start_time %lf\n", (*t)->start_time);
  return (*t)->start_time;
}

pid_t pop_next_pid()
{
  time_desc* t = NULL;
  xbt_dynar_shift(global_data->launching_time, &t);
  int res = t->pid;
  
  process_descriptor* proc = process_get_descriptor(res);
  if(proc->in_timeout == PROC_IN_TIMEOUT)
    proc->in_timeout = PROC_TIMEOUT_EXPIRE;
  proc->timeout = NULL;
  
  free(t);
  return res;
}

void add_launching_time(pid_t pid, double start_time)
{
  time_desc* t = malloc(sizeof(time_desc));
  t->pid = pid;
  t->start_time = start_time;
  
  process_descriptor* proc = process_get_descriptor(pid);
  proc->timeout = t;
  
  xbt_dynar_push(global_data->launching_time, &t);
}

void set_next_launchment(pid_t pid)
{
  time_desc* t = malloc(sizeof(time_desc));
  t->pid = pid;
  t->start_time = SD_get_clock();
  
  process_descriptor* proc = process_get_descriptor(pid);
  proc->timeout = t;
  
  xbt_dynar_unshift(global_data->launching_time, &t);
}

int has_sleeping_to_launch()
{
  return !xbt_dynar_is_empty(global_data->launching_time);
}

void add_timeout(pid_t pid, double start_time)
{
  
  if(start_time == SD_get_clock())
    start_time += 0.0001;
  printf("Add new timeout of %lf for %d\n", start_time, pid);
  time_desc* t = malloc(sizeof(time_desc));
  t->pid = pid;
  t->start_time = start_time;
  
  process_descriptor* proc = process_get_descriptor(pid);
  proc->timeout = t;
  proc->in_timeout = PROC_IN_TIMEOUT;
  
  int i=0;
  while( i < xbt_dynar_length(global_data->launching_time))
  {
    time_desc** t = xbt_dynar_get_ptr(global_data->launching_time, i);
    if( start_time < (*t)->start_time)
      break;
    ++i;
  }
  xbt_dynar_insert_at(global_data->launching_time, i, &t);
}

void remove_timeout(pid_t pid)
{
  process_descriptor* proc = process_get_descriptor(pid);
  time_desc* t = proc->timeout;
  proc->timeout = NULL;
  proc->in_timeout = PROC_NO_TIMEOUT;
  
  xbt_ex_t e;
  TRY{
    int i= xbt_dynar_search(global_data->launching_time, &t);
    xbt_dynar_remove_at(global_data->launching_time, i, NULL);
  }
  CATCH(e){
    printf("Timeout not found %d\n", xbt_dynar_is_empty(global_data->launching_time));
  }
  free(t);
}

