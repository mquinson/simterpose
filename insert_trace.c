#include "insert_trace.h"

char buftrace[512];
long long int times_syscall[3];
long long int diff_time=0;
long long int diff_cpu=0;


void calculate_computation_time(int pid)
{
  if (ask_time(pid, times_syscall)) {
    perror("Error ask_time");
    exit(1);
  } else {
    
    long long int last_cpu = get_last_cputime(pid);

    if((diff_cpu=(times_syscall[1] + times_syscall[2]) - last_cpu))
    {
      //update_walltime_procs(pid,times_syscall[0]);
      update_cputime_procs(pid,times_syscall[1]+times_syscall[2]);
      printf("%p %p\n", process_desc[pid]->trace, process_desc[pid]->name);
      fprintf(process_desc[pid]->trace,"%s compute %10f\n", process_desc[pid]->name, (diff_cpu/global_data->micro_s_per_flop));
    }
  }
}



char * trace_header(int pid, char * syscall) {
#if defined(DEBUG)
	sprintf(buftrace, "%8s %12s", process_desc[pid]->name, syscall);
#else
	sprintf(buftrace, "%s %s", process_desc[pid]->name, syscall);
#endif
    return buftrace;
}

void insert_trace_comm(pid_t pid, int sockfd , char *syscall, int res) {

  //printf(" ___ printing new trace ____");
  if (get_domain_socket(pid,sockfd) == 2) { // PF_INET -> local and remote addr:port known

    struct infos_socket* is = get_infos_socket(pid,sockfd);
    char* header = trace_header(pid, syscall);
#if defined(DEBUG)
    fprintf(process_desc[pid]->trace,"%s %8s %10d", header, process_desc[get_pid_socket_dest(is)]->name, res);
    fprintf(process_desc[pid]->trace," %15s %5d %15s %5d\n", is->ip_local,is->port_local,is->ip_remote,is->port_remote);
#else
    fprintf(process_desc[pid]->trace,"%s %s %d", header, process_desc[get_pid_socket_dest(is)]->name, res);
    fprintf(process_desc[pid]->trace," %s %d %s %d\n", is->ip_local,is->port_local,is->ip_remote,is->port_remote);
#endif
  } 
  else{
    calculate_computation_time(pid);
    fprintf(process_desc[pid]->trace,"%s %10d", trace_header(pid, syscall), res);
  }

}

void insert_trace_fork_exit(pid_t pid, char *syscall, int res) {
  calculate_computation_time(pid);
  fprintf(process_desc[pid]->trace,"%s %10s %8d\n", trace_header(pid,syscall), " ", res);

}

void insert_init_trace(pid_t pid)
{
  fprintf(process_desc[pid]->trace,"%s init\n", process_desc[pid]->name);
}
