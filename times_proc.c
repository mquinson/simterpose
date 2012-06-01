#include "times_proc.h"

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

void update_cputime_procs(pid_t pid, long long int new_cputime) {

  int i=0;
  int update=0;
  while (i<nb_procs && !update) {
    if (all_procs[i].pid==pid) {
      all_procs[i].last_cputime=new_cputime;
      update=1;
    }
    i++;
  }

}

// void insert_walltime_procs(pid_t pid) {
// 
//   all_procs[nb_procs].pid=pid;
//   all_procs[nb_procs].last_walltime=-1;
// }

void insert_cputime_procs(pid_t pid) {

  all_procs[nb_procs].pid=pid;
  all_procs[nb_procs].last_cputime=0;
}


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

  int i=0;
  int found=0;
  while (i<nb_procs && !found) {
    if (all_procs[i].pid==pid)
      return all_procs[i].last_cputime;
    i++;
  }
  return -1;
}
