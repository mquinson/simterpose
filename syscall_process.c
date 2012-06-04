#include "syscall_process.h"
#include "insert_trace.h"
#include "sockets.h"

int process_send_call(int pid, int sockfd, int ret)
{
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