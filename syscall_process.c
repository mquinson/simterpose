#include "syscall_process.h"
#include "insert_trace.h"
#include "sockets.h"

//TODO test the possibility to remove incomplete checking
int process_send_call(int pid, int sockfd, int ret)
{
  if (socket_registered(pid,sockfd) != -1) {
    if (socket_incomplete(pid,sockfd))
    {
      update_socket(pid,sockfd);
    }
    if (!socket_netlink(pid,sockfd))
    {
      calculate_computation_time(pid);
      struct infos_socket *is = get_infos_socket(pid,sockfd);
      struct infos_socket *s = getSocketInfoFromContext(is->ip_local, is->port_local, is->ip_remote, is->port_remote);
      if(s!=NULL)
	handle_new_send(s,  ret);
      else
	THROW_IMPOSSIBLE;
      insert_trace_comm(pid,sockfd,"send",(int)ret);  
    }
  }
  return 0;
}

int process_recv_call(int pid, int sockfd, int ret)
{
  if (socket_registered(pid,sockfd) != -1) {
    if (socket_incomplete(pid,sockfd)) 
      update_socket(pid,sockfd);
    if (!socket_netlink(pid,sockfd))
    {
      calculate_computation_time(pid);
      handle_new_receive(pid, sockfd, ret);
    }
  }
  return 0;
}

void process_fork_call(int pid)
{
  
}