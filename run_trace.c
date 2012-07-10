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
  xbt_ex_t e;
  TRY{
    int i= xbt_dynar_search(idle_process, &pid);
    xbt_dynar_remove_at(idle_process, i, NULL);
    process_descriptor *proc = process_get_descriptor(pid);
    proc->idle_list=0;
  }
  CATCH(e){
    xbt_die("Pid not found in list. Inconsistance found in model");
  } 
}


void add_to_idle(pid_t pid)
{
  process_descriptor* proc = process_get_descriptor(pid);
  if(proc->idle_list)
    return;
  proc->idle_list=1;
//   printf("Add process %d to idle list\n", pid);
  xbt_dynar_push_as(idle_process, pid_t, pid);
}

//Verify is the process is not already schedule before adding
void add_to_sched_list(pid_t pid)
{
  process_descriptor *proc = process_get_descriptor(pid);
  if(proc->scheduled)
    return;
  
  proc->scheduled =1;
  xbt_dynar_push_as(sched_list, pid_t, pid);
  
//   printf("Add process %d to sched_list\n", pid);
  if(proc->idle_list)
    remove_from_idle_list(pid);
}


void move_idle_to_sched()
{
  pid_t pid;
  while(!xbt_dynar_is_empty(idle_process))
  {
    xbt_dynar_shift(idle_process, &pid);
    process_descriptor *proc = process_get_descriptor(pid);
    
    proc->idle_list = 0;
//     printf("Move process %d on sched_list\n", pid);
    proc->scheduled =1;
    xbt_dynar_push_as(sched_list, pid_t, pid);
  }
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
    printf("NEW TURN %lf\n", SD_get_clock());
    
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
    move_idle_to_sched();

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
//       printf("Scheduling process %d\n", pid);      
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
