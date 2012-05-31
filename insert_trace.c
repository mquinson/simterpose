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
    struct timeval tv;
    struct timezone tz;
    gettimeofday(&tv, &tz);
    
    long long int last_cpu = get_last_cputime(pid);
    //printf("%lld %lld %lld\n", last_cpu, (times_syscall[1] + times_syscall[2]) - last_cpu);
    if((diff_cpu=(times_syscall[1] + times_syscall[2]) - last_cpu))
    {
      update_walltime_procs(pid,times_syscall[0]);
      update_cputime_procs(pid,times_syscall[1]+times_syscall[2]);
      fprintf(process_desc[pid].trace,"%s compute %10lld\n", process_desc[pid].name, diff_cpu);
    }
  }
}



char * trace_header(int simgrid, int pid, char *type, char * syscall) {
    if(simgrid){
#if defined(DEBUG)
	sprintf(buftrace, "%8s %12s", process_desc[pid].name, syscall);
#else
	sprintf(buftrace, "%s %s", process_desc[pid].name, syscall);
#endif
    }else{
      if (ask_time(pid, times_syscall)) {
	perror("Error ask_time");
	exit(1);
      } else {
	struct timeval tv;
	struct timezone tz;
	struct tm *t;
	gettimeofday(&tv, &tz);
	t=localtime(&tv.tv_sec);
	
	long long int last_time = get_last_walltime(pid);
	
	if (last_time != -1)
	  diff_time = times_syscall[0] - last_time;
	long long int last_cpu = get_last_cputime(pid);
	//printf("%lld %lld %lld\n", last_cpu, (times_syscall[1] + times_syscall[2]) - last_cpu);
	diff_cpu=(times_syscall[1] + times_syscall[2]) - last_cpu;
	
	update_walltime_procs(pid,times_syscall[0]);
	update_cputime_procs(pid,times_syscall[1]+times_syscall[2]);
      sprintf(buftrace, "%02u:%02u:%02u:%6d %8s %10lld %10lld %10lld %10lld %5s %12s", t->tm_hour,t->tm_min,t->tm_sec,(int)tv.tv_usec,process_desc[pid].name, times_syscall[0],times_syscall[1]+times_syscall[2],diff_time,diff_cpu,type,syscall);
    }
    }
    return buftrace;
}

void insert_trace_comm(int simgrid, FILE *trace, pid_t pid, int sockfd , char *syscall, char *type, ...) {
 
  va_list ap;
  va_start(ap, type);
  int res = va_arg(ap,int);
  char *trace_param = va_arg(ap,char *);
  

  if (get_domain_sockfd(pid,sockfd) == 2) { // PF_INET -> local and remote addr:port known
    struct infos_socket is;
    get_infos_socket(pid,sockfd,&is);
    if(simgrid){
      if(strcmp(type,"out") == 0){
	calculate_computation_time(pid);
	char* header = trace_header(simgrid, pid, type, syscall);
#if defined(DEBUG)
	fprintf(process_desc[pid].trace,"%s %8s %10d", header, process_desc[get_pid_socket_dest(&is)].name, res);
	fprintf(process_desc[pid].trace," %15s %5d %15s %5d\n", is.ip_local,is.port_local,is.ip_remote,is.port_remote);
#else
	fprintf(process_desc[pid].trace,"%s %s %d", header, process_desc[get_pid_socket_dest(&is)].name, res);
	fprintf(process_desc[pid].trace," %s %d %s %d\n", is.ip_local,is.port_local,is.ip_remote,is.port_remote);
#endif
      }
    }else{
      fprintf(trace,"%s %15s:%5d %15s:%5d", trace_header(simgrid, pid, type, syscall), is.ip_local,is.port_local,is.ip_remote,is.port_remote);
      fprintf(trace," %8s",process_desc[get_pid_socket_dest(&is)].name);
    }
  } else{
    if(simgrid){
      if(strcmp(type,"out") == 0)
	fprintf(process_desc[pid].trace,"%s %10d %52s", trace_header(simgrid,pid, type, syscall), res, " ");
      fprintf(process_desc[pid].trace, "\n");
    }else
    {
      fprintf(trace,"%s %52s", trace_header(simgrid,pid, type, syscall)," ");
      if(strcmp(type,"out") == 0)
	fprintf(trace, " %10d \t%s\n", res, trace_param);
      else
	fprintf(trace, "\n");
    }
  }
    
  va_end(ap);


}

void insert_trace_fork_exit(int simgrid, FILE *trace,pid_t pid, char *syscall, int res) {

  if(simgrid)
    fprintf(process_desc[pid].trace,"%s %10s %8d\n", trace_header(simgrid, pid,"out",syscall), " ", res);
  else
    fprintf(trace,"%s %52s %10d\n", trace_header(simgrid, pid, " ",syscall)," ",res);

}

void insert_init_trace(pid_t pid)
{
  fprintf(process_desc[pid].trace,"%s init\n", process_desc[pid].name);
}
