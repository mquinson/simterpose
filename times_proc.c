#include "times_proc.h"
#include "run_trace.h"
#include "data_utils.h"

// void update_walltime_procs(pid_t pid, long long int new_walltime) {
// 
//   int i=0;
//   int update=0;
//   while (i<nb_procs && !update) {
//     if (all_procs[i].pid==pid) {
//       all_procs[i].last_walltime=new_walltime;
//       update=1;
//     }
//     i++;
//   }
// 
// }

int update_cputime_procs(pid_t pid, long long int new_cputime) {
  
  process_descriptor *proc = process_descriptor_get(pid);
  int result = new_cputime - proc->cpu_time;
  proc->cpu_time = new_cputime;
  return result;
}

// void insert_walltime_procs(pid_t pid) {
// 
//   all_procs[nb_procs].pid=pid;
//   all_procs[nb_procs].last_walltime=-1;
// }


// long long int get_last_walltime(pid_t pid) {
// 
//   int i=0;
//   int found=0;
//   while (i<nb_procs && !found) {
//     if (all_procs[i].pid==pid)
//       return all_procs[i].last_walltime;
//     i++;
//   }
//   return -1;
// }

long long int get_last_cputime(pid_t pid) {
  process_descriptor *proc = process_descriptor_get(pid);
  return proc->cpu_time;
}
