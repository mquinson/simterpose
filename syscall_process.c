#include "syscall_process.h"
#include "insert_trace.h"
#include "sockets.h"

int process_send_call(int pid, int sockfd, int ret)
{
  printf("Entering process_send_call\n");
  struct infos_socket is;
  get_infos_socket(pid,sockfd,&is);
  struct infos_socket *s = getSocketInfoFromContext(is.ip_local, is.port_local, is.ip_remote, is.port_remote);
  if(s!=NULL)
    add_new_transmission(s,is.port_local,is.ip_local,  ret);
  else
    THROW_IMPOSSIBLE;
  insert_trace_comm(pid,sockfd,"send",(int)ret);   
  
  return 0;
}

int process_recv_call(int pid, int sockfd, int ret)
{
  printf("Entering recv_call %d\n", ret);
//   struct infos_socket is;
//   get_infos_socket(pid,sockfd,&is);
//   int transmission_complete = handle_new_reception(&is, is.port_remote, is.ip_remote, ret);
//   printf("Entering recv_call %d\n", transmission_complete);
//   while(transmission_complete)
//   {
    insert_trace_comm(pid,sockfd,"recv",(int)ret); 
//     --transmission_complete;
//   }
  return 0;
}