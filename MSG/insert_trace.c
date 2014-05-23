#include "insert_trace.h"
#include "data_utils.h"
#include "task.h"
#include "sockets.h"
#include "calc_times_proc.h"
#include "process_descriptor.h"
#include "run_trace.h"
#include "simdag/simdag.h"

char buftrace[512];
long long int times_syscall[3];


int calculate_computation_time(int pid)
{
  // printf("entering calculate_computation_time \n");
  cputimer_get(pid, times_syscall);
    process_descriptor *proc = process_get_descriptor(pid);
    long long int diff_cpu=0;

    // On crée la tache seulement si le temps a avancé
    if((diff_cpu=process_update_cputime(proc,times_syscall[1]+times_syscall[2])) > 0)
    {
      //process_descriptor* proc = process_get_descriptor(pid);
      double amount = (diff_cpu/global_data->micro_s_per_flop);
      fprintf(proc->trace,"%s compute %10f\n", proc->name, amount);
      
      msg_task_t comp_task = create_computation_task(pid, amount);
      proc->last_computation_task = comp_task;
      return 1;
    }
  return 0;
}



// char * trace_header(int pid, char * syscall) {
//   process_descriptor* proc = process_get_descriptor(pid);
// #if defined(DEBUG)
// 	sprintf(buftrace, "%8s %12s", proc->name, syscall);
// #else
// 	sprintf(buftrace, "%s %s", proc->name, syscall);
// #endif
//     return buftrace;
// }
// 
// void insert_trace_comm(pid_t pid, int sockfd , char *syscall, int res) {
//   process_descriptor* proc = process_get_descriptor(pid);
// 
//   if (get_domain_socket(pid,sockfd) == 2) { // PF_INET -> local and remote addr:port known
// 
//     struct infos_socket* is = get_infos_socket(pid,sockfd);
//     process_descriptor* proc_dest = process_get_descriptor(get_pid_socket_dest(is));
//     char* header = trace_header(pid, syscall);
// #if defined(DEBUG)
//     fprintf(proc->trace,"%s %8s %10d", header, proc_dest->name, res);
//     fprintf(proc->trace," %15s %5d %15s %5d\n", is->ip_local,is->port_local,is->ip_remote,is->port_remote);
// #else
//     fprintf(proc->trace,"%s %s %d", header, proc_dest->name, res);
//     fprintf(proc->trace," %s %d %s %d\n", is->ip_local,is->port_local,is->ip_remote,is->port_remote);
// #endif
//   } 
//   else{
//     fprintf(proc->trace,"%s %10d", trace_header(pid, syscall), res);
//   }
// 
// }
// 
// void insert_trace_fork_exit(pid_t pid, char *syscall, int res) {
//   process_descriptor* proc = process_get_descriptor(pid);
//   fprintf(proc->trace,"%s %10s %8d\n", trace_header(pid,syscall), " ", res);
// 
// }
// 
// void insert_init_trace(pid_t pid)
// {
//   process_descriptor* proc = process_get_descriptor(pid);
//   fprintf(proc->trace,"%s init\n", proc->name);
// }
