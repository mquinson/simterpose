#include "insert_trace.h"
#include "data_utils.h"
#include "task.h"

char buftrace[512];
long long int times_syscall[3];
long long int diff_time=0;



void calculate_computation_time(int pid)
{
  if (ask_time(pid, times_syscall)) {
    perror("Error ask_time");
    exit(1);
  } else {
    
    long long int diff_cpu=0;

    if((diff_cpu=update_cputime_procs(pid,times_syscall[1]+times_syscall[2])) > 0)
    {
      //update_walltime_procs(pid,times_syscall[0]);
      process_descriptor* proc = process_descriptor_get(pid);
      double amount = (diff_cpu/global_data->micro_s_per_flop);
      fprintf(proc->trace,"%s compute %10f\n", proc->name, amount);
      create_computation_task(pid, amount);
    }
  }
}



char * trace_header(int pid, char * syscall) {
  process_descriptor* proc = process_descriptor_get(pid);
#if defined(DEBUG)
	sprintf(buftrace, "%8s %12s", proc->name, syscall);
#else
	sprintf(buftrace, "%s %s", proc->name, syscall);
#endif
    return buftrace;
}

void insert_trace_comm(pid_t pid, int sockfd , char *syscall, int res) {
  process_descriptor* proc = process_descriptor_get(pid);

  if (get_domain_socket(pid,sockfd) == 2) { // PF_INET -> local and remote addr:port known

    struct infos_socket* is = get_infos_socket(pid,sockfd);
    process_descriptor* proc_dest = process_descriptor_get(get_pid_socket_dest(is));
    char* header = trace_header(pid, syscall);
#if defined(DEBUG)
    fprintf(proc->trace,"%s %8s %10d", header, proc_dest->name, res);
    fprintf(proc->trace," %15s %5d %15s %5d\n", is->ip_local,is->port_local,is->ip_remote,is->port_remote);
#else
    fprintf(proc->trace,"%s %s %d", header, proc_dest->name, res);
    fprintf(proc->trace," %s %d %s %d\n", is->ip_local,is->port_local,is->ip_remote,is->port_remote);
#endif
  } 
  else{
    calculate_computation_time(pid);
    fprintf(proc->trace,"%s %10d", trace_header(pid, syscall), res);
  }

}

void insert_trace_fork_exit(pid_t pid, char *syscall, int res) {
  calculate_computation_time(pid);
  process_descriptor* proc = process_descriptor_get(pid);
  fprintf(proc->trace,"%s %10s %8d\n", trace_header(pid,syscall), " ", res);

}

void insert_init_trace(pid_t pid)
{
  process_descriptor* proc = process_descriptor_get(pid);
  fprintf(proc->trace,"%s init\n", proc->name);
}
