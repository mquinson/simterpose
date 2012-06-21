#include <unistd.h>

#include "args_trace.h"
#include "ptrace_utils.h"
#include "sysdep.h"
#include "calc_times_proc.h"
#include "process_descriptor.h"
#include "sockets.h"
#include "insert_trace.h"
#include "run_trace.h"
#include "benchmark.h"
#include "syscall_process.h"
#include "xbt/fifo.h"
#include "replay.h"
#include "data_utils.h"
#include "parser.h"
#include "init.h"

#define BUFFER_SIZE 512


void usage(char* progName) {
  printf("usage : %s platform_file.xml deployment_file.xml [-fp flops_power]\n", progName);
}

void print_trace_header(FILE* trace)
{
  fprintf(trace,"%8s %12s %8s %10s %10s %21s %21s\n","pidX", "syscall", "pidY", "return","diff_cpu","local_addr:port", "remote_addr:port");
}


int main(int argc, char *argv[]) { 
  
  global_data = malloc(sizeof(simterpose_data_t));
  
  init_global_data();
  init_socket_gestion();
  init_cputime();

  
  //TODO mettre un vrai gestionnaire d'option et gérer les extensions des fichiers passés en paramètre
  int i, manual_flop=0;
  if(argc>2)
  {
    for(i=3; i<argc; ++i)
    {
      if(!strcmp(argv[i], "-fp"))
      {
	if(argv[i+1] == NULL)
	{
	  usage(argv[0]); 
	}
	else
	{
	  char* endptr = argv[i+1]+strlen(argv[i+1])-1;
	  global_data->flops_per_second = strtod(argv[i+1], &endptr);
	  if(endptr == argv[i+1])
	    usage(argv[0]);
	  else
	  {
	    global_data->micro_s_per_flop  = 1000000/global_data->flops_per_second;
	    manual_flop = 1;
	  }
	}
      }
    }
  }
  else
  {
    usage(argv[0]);
    exit(1);
  }
  
  if(!manual_flop)
    benchmark_matrix_product(&(global_data->flops_per_second), &(global_data->micro_s_per_flop));
  
  SD_init(&argc, argv);
  SD_create_environment(argv[1]);
  
  parse_deployment_file(argv[2]);
  
  init_all_process();
  
  int amount_process_launch=0;
  int time_to_simulate=0;
  
  xbt_dynar_t idle_process = xbt_dynar_new(sizeof(int*), NULL);
  
  do{
    //We calculate the time of simulation.
    if(amount_process_launch < parser_get_amount())
      time_to_simulate = global_data->launching_time[amount_process_launch]->start_time - SD_get_clock();
    else
      time_to_simulate=-1;
    
    xbt_dynar_t arr = SD_simulate(time_to_simulate);
    
    
    //Now we gonna handle each son for which a watching task is over
    SD_task_t task_over = NULL;
    while(!xbt_dynar_is_empty(arr))
    {
      xbt_dynar_shift(arr, task_over);
      int* data = (int *)SD_task_get_data(task_over);
      //If data is null, we are in presence of a non watch task
      if(data != NULL)
      {
        int status = process_handle(*data, NULL);
        if(status == PROCESS_DEAD) //TODO add real gestion of process death
          --global_data->child_amount;
        else if(status == PROCESS_IDLE_STATE)
        {
          int *temp = malloc(sizeof(int));
          *temp = *data;
          xbt_dynar_push(idle_process, temp);
        }
      }
    }
    
    //Now we will run all idle process store in 
    unsigned int cpt=0;
    int* idle_pid;
    xbt_dynar_foreach(idle_process, cpt, idle_pid)
    {
      //Do handling of idle process here.
      //use void        xbt_dynar_cursor_rm (xbt_dynar_t dynar, unsigned int *const cursor) for remove
    }
    
    
    //Make idle handling here
    
    
    //Now we the next process if the time is come
    if(amount_process_launch < parser_get_amount())
    {
      if(SD_get_clock() == global_data->launching_time[amount_process_launch]->start_time)
      {
        ptrace_resume_process(global_data->launching_time[amount_process_launch]->pid);
        process_handle(global_data->launching_time[amount_process_launch]->pid, NULL);
        ++global_data->child_amount;
        ++amount_process_launch;
      }
    }
    
  }while(global_data->child_amount);
  

  finish_cputime();
  return 0;

}
