#include <unistd.h>

#include "args_trace.h"
#include "calc_times_proc.h"
#include "process_descriptor.h"
#include "run_trace.h"
#include "xbt/fifo.h"
#include "xbt/log.h"
#include "data_utils.h"
#include "parser.h"
#include "init.h"
#include "communication.h"
#include "syscall_process.h"

#define BUFFER_SIZE 512

XBT_LOG_NEW_CATEGORY(SIMTERPOSE, "Simterpose log");


void print_trace_header(FILE* trace)
{
  fprintf(trace,"%8s %12s %8s %10s %10s %21s %21s\n","pidX", "syscall", "pidY", "return","diff_cpu","local_addr:port", "remote_addr:port");
}
xbt_dynar_t idle_process;
xbt_dynar_t sched_list;


void add_to_idle(pid_t pid)
{
  unsigned int cpt=0;
  int idle_pid;
  xbt_dynar_foreach(idle_process, cpt, idle_pid)
  {
    if(idle_pid == pid)
      return;
  }
  xbt_dynar_push_as(idle_process, pid_t, pid);
}


//Verify is the process is not already schedule before adding
void add_to_sched_list(pid_t pid)
{
  unsigned int cpt=0;
  int temp=0;
  xbt_dynar_foreach(sched_list, cpt, temp)
  {
    if(temp == pid)
      return;
  }
  xbt_dynar_push_as(sched_list, pid_t, pid);
}



int main(int argc, char *argv[]) { 
  
  simterpose_init(argc, argv);

  int time_to_simulate=0;
  
  idle_process = xbt_dynar_new(sizeof(pid_t), NULL);
  sched_list = xbt_dynar_new(sizeof(pid_t), NULL);
  
  do{
    
    //We calculate the time of simulation.
    time_to_simulate= get_next_start_time() - SD_get_clock();
    
//     printf("Next simulation time %d\n", time_to_simulate);
    xbt_dynar_t arr = SD_simulate(time_to_simulate);
//     printf("NEW TURN %lf\n", SD_get_clock());
    
    //Now we gonna handle each son for which a watching task is over
    SD_task_t task_over = NULL;
    while(!xbt_dynar_is_empty(arr))
    {
      xbt_dynar_shift(arr, &task_over);
      int* data = (int *)SD_task_get_data(task_over);
      //If data is null, we are in presence of a non watch task
      if(data != NULL)
      {
//         printf("Handling ended task for %d\n", *data);
        int status = process_handle_active(*data);
        if(status == PROCESS_DEAD) //TODO add real gestion of process death
          --global_data->child_amount;
        else if(status == PROCESS_IDLE_STATE)
        {
          add_to_idle(*data);
        }
      }
    }
    
    
    //Now we will run all idle process store in 
    unsigned int cpt=0;
    int idle_pid;
    xbt_dynar_foreach(idle_process, cpt, idle_pid)
    {
//       printf("Handle idling process %d\n", *idle_pid);
      int status = process_handle_idle(idle_pid);
      if(status != PROCESS_IDLE_STATE)
          xbt_dynar_cursor_rm (idle_process, &cpt);
    }

    
//     printf("Handle sleeping process %d\n", has_sleeping_to_launch());
    
    //Now we the next process if the time is come
    if(has_sleeping_to_launch())
    {
      if(SD_get_clock() == get_next_start_time())
      {
        //printf("Starting new process\n");
        int temp_pid = pop_next_pid();
        process_descriptor* proc = process_get_descriptor(temp_pid);
        if(!proc->in_timeout)
          ++global_data->child_amount;
        else
          proc->in_timeout=0;
        int status = process_handle_active(temp_pid);
        if(status == PROCESS_IDLE_STATE)
        {
          add_to_idle(temp_pid);
        }
      }
    }
//     printf("End of loop (left %d): Simulation time : %lf\n",global_data->child_amount, SD_get_clock());
  }while(global_data->child_amount);
  

  finish_cputime();
  
  printf("End of simulation. Time : %lf\n", SD_get_clock());
  
  return 0;

}
