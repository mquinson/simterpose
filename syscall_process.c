#include "syscall_process.h"
#include "insert_trace.h"
#include "sockets.h"

int process_send_call(int pid, int sockfd, int ret)
{
  calculate_computation_time(pid);
  printf("Entering process_send_call %d\n", ret);
  struct infos_socket is;
  get_infos_socket(pid,sockfd,&is);
  struct infos_socket *s = getSocketInfoFromContext(is.ip_local, is.port_local, is.ip_remote, is.port_remote);
  if(s!=NULL)
    handle_new_send(s,  ret);
  else
    THROW_IMPOSSIBLE;
  insert_trace_comm(pid,sockfd,"send",(int)ret);  
  
  
  return 0;
}

int process_recv_call(int pid, int sockfd, int ret)
{
  calculate_computation_time(pid);
  printf("Entering recv_call %d\n", ret);
  
  handle_new_receive(pid, sockfd, ret);
  //insert_trace_comm(pid,sockfd,"recv",(int)ret); 
  return 0;
}