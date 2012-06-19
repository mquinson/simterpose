#include "process_descriptor.h"
#include "run_trace.h"
#include "data_utils.h"


int update_cputime_procs(pid_t pid, long long int new_cputime) {
  
  process_descriptor *proc = process_descriptor_get(pid);
  int result = new_cputime - proc->cpu_time;
  proc->cpu_time = new_cputime;
  return result;
}


long long int get_last_cputime(pid_t pid) {
  process_descriptor *proc = process_descriptor_get(pid);
  return proc->cpu_time;
}
