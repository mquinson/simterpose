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


void remove_from_idle_list(pid_t pid)
{
  int t;
  unsigned int cpt;
  xbt_dynar_foreach(idle_process, cpt, t)
  {
    if(t == pid)
    {
//       printf("Remove process %d from idle list\n", pid); 
      xbt_dynar_cursor_rm (idle_process, &cpt);
      return;
    }
  }
}


void add_to_idle(pid_t pid)
{

  int t;
  unsigned int cpt;
  xbt_dynar_foreach(idle_process, cpt, t)
  {
    if(t == pid)
      return;
  }
//   printf("Add process %d to idle list\n", pid);
  xbt_dynar_push_as(idle_process, pid_t, pid);
}


//Verify is the process is not already schedule before adding
void add_to_sched_list(pid_t pid)
{
  printf("Entering sched\n");
  process_descriptor *proc = process_get_descriptor(pid);
  if(proc->scheduled)
    return;
  
  proc->scheduled =1;
  xbt_dynar_push_as(sched_list, pid_t, pid);
  
  printf("Add process %d to sched list\n", pid);
  remove_from_idle_list(pid);
}



int main(int argc, char *argv[]) { 
  
  simterpose_init(argc, argv);

  int time_to_simulate=0;
  
  idle_process = xbt_dynar_new(sizeof(pid_t), NULL);
  xbt_dynar_reset(idle_process);
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
      //If data is null, we schedule the process
      if(data != NULL)
        add_to_sched_list(*data);
    }

    //Now adding all idle process to the scheduled list
    pid_t idle_pid;
    while(!xbt_dynar_is_empty(idle_process))
    {
      xbt_dynar_shift(arr, &idle_pid);
      add_to_sched_list(idle_pid);
    }

    while(has_sleeping_to_launch())
    {
      //if we have to launch them to this turn
      if(SD_get_clock() == get_next_start_time())
      {
        int temp_pid = pop_next_pid();
        add_to_sched_list(temp_pid);
        process_descriptor* proc = process_get_descriptor(temp_pid);
        if(!proc->in_timeout)
          ++global_data->child_amount;
        else
          proc->in_timeout=0;
      }
      else
        break;
    }
//     printf("Size of sched_list %ldu\n", xbt_dynar_length(sched_list));
    
    //Now we have global list of process_data, we have to handle them
    while(!xbt_dynar_is_empty(sched_list))
    {
      
      pid_t pid;
      xbt_dynar_shift (sched_list, &pid);
      process_descriptor* proc = process_get_descriptor(pid);
      proc->scheduled = 0;
      
//       printf("Handling process %d %d\n", pid, process_get_idle(pid));
      
      if(process_get_idle(pid) == PROC_IDLE)
      {
        int status = process_handle_idle(pid);
        if(status == PROCESS_IDLE_STATE)
        {
          process_set_idle(pid, PROC_IDLE);
          add_to_idle(pid);
        }
        else if( status == PROCESS_DEAD)
          --global_data->child_amount;
        else
          process_set_idle(pid, PROC_NO_IDLE);
      }
      else
      {
        int status = process_handle_active(pid);
        if(status == PROCESS_IDLE_STATE)
        {
          process_set_idle(pid, PROC_IDLE);
          add_to_idle(pid);
        }
        else if( status == PROCESS_DEAD)
          --global_data->child_amount;
        else
          process_set_idle(pid, PROC_NO_IDLE);
      }
    }
    
    printf("End of loop (left %d): Simulation time : %lf\n",global_data->child_amount, SD_get_clock());
  }while(global_data->child_amount);
  

  finish_cputime();
  
  printf("End of simulation. Time : %lf\n", SD_get_clock());
  
  return 0;
}
