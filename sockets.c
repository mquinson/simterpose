#include "sockets.h"
#include "insert_trace.h"
#include "xbt.h"
#include "task.h"

#define LOCAL 1
#define REMOTE 2

#define TCP_PROTOCOL 0
#define UDP_PROTOCOL 1
#define RAW_PROTOCOL 2

xbt_dynar_t all_sockets;
int nb_sockets = 0;

int get_addr_port_sock(pid_t pid, int fd, int addr);
void print_infos_socket(struct infos_socket *is);

void init_socket_gestion()
{
   all_sockets = xbt_dynar_new(sizeof(struct infos_socket*), NULL);
}

void confirm_register_socket(pid_t pid, int sockfd, int domain, int protocol) {

  process_descriptor* proc = global_data->process_desc[pid];
  
  struct infos_socket *is = malloc(sizeof(struct infos_socket));
  proc->fd_list[sockfd]=is;
  is->fd= sockfd;
  
  is->proc_infos = xbt_dynar_new(sizeof(process_info*), NULL);
  
  process_info* proc_info  = malloc(sizeof(process_info));
  proc_info->proc = proc;
  proc_info->fd = sockfd;
  
  is->proc=proc;
  is->domain=domain;
  is->protocol=protocol;
  is->ip_local=strdup("");
  is->ip_remote=strdup("");
  is->port_local=0;
  is->port_remote=0;
  is->incomplete=1;
  is->closed=0;
  
  recv_information* recv = malloc(sizeof(recv_information));
  recv->quantity_recv=0;
  recv->send_fifo = xbt_fifo_new();
  recv->recv_task = xbt_fifo_new();
  is->recv_info = recv;

  xbt_dynar_push(all_sockets, &is);
}

void delete_socket(pid_t pid, int fd) {
  xbt_ex_t e;
  TRY{
    int i= xbt_dynar_search(all_sockets, get_infos_socket(pid, fd));
    xbt_dynar_remove_at(all_sockets, i, NULL);
  }
  CATCH(e){
    printf("Socket not found\n");
  }
  
  
}


void register_socket(pid_t pid, int sockfd, int domain, int protocol) {
//   printf("Registering socket %d for processus %d\n", sockfd, pid);
  if (socket_registered(pid,sockfd)==1) {
    if (socket_closed(pid,sockfd) == 1) {
      delete_socket(pid,sockfd);
      confirm_register_socket(pid,sockfd,domain,protocol);
    } else {
      perror("Error create socket, fd not closed !");
      exit(1);
    }
  }else{
     confirm_register_socket(pid,sockfd,domain,protocol);
  }

}


void update_socket(pid_t pid, int fd) {

  struct infos_socket* is = get_infos_socket(pid, fd);

  if (is->domain == 2) { // PF_INET
    if (get_addr_port_sock(pid, fd, LOCAL)) { // 1-> locale
      if (get_addr_port_sock(pid, fd, REMOTE)) { // 2 -> remote
	is->incomplete=0;
      }
    }
    print_infos_socket(is);
  }
}



void set_localaddr_port_socket(pid_t pid, int fd, char *ip, int port) {
  struct infos_socket* is = get_infos_socket(pid, fd);
  is->ip_local = strdup(ip);
  is->port_local = port;
  print_infos_socket(is);
}



void get_localaddr_port_socket(pid_t pid, int fd) {
  struct infos_socket* is = get_infos_socket(pid, fd);

  if (is->domain == 2) { // PF_INET
    if (!get_addr_port_sock(pid, fd, 1))
      printf("Failed reading locale addr:port after bind\n");
    print_infos_socket(is);
  }
}


void print_infos_socket(struct infos_socket *is) {
  fprintf(stdout,"\n%5s %5s %10s %10s %21s %21s %12s %10s\n","pid","fd","domain","protocol","locale_ip:port","remote_ip:port","incomplete", "closed");
    if(is->proc != NULL){

  fprintf(stdout,"%5d %5d %10d %10d %15s:%5d %15s:%5d %12d %10d\n",
	  is->proc->pid,
	  is->fd,
	  is->domain,
	  is->protocol,
	  is->ip_local,
	  is->port_local,
	  is->ip_remote,
	  is->port_remote,
	  is->incomplete,
	  is->closed);
  }
}

#define INODE_OFFSET 91

int get_addr_port(int type, int num_sock, struct sockaddr_in *addr_port, int addr ) {

  FILE *file;
  
  
  //printf("Socket number : %d\n", num_sock);
  if (type == TCP_PROTOCOL) // TCP
    file=fopen("/proc/net/tcp","r");
  else if (type == UDP_PROTOCOL) // UDP
    file=fopen("/proc/net/udp","r");
  else // RAW
    file=fopen("/proc/net/raw","r");
  if (file == NULL) {
    perror("Open file /proc/net/...");
    exit(1);
  }
  char buff[512];
  char *loc_addr_hex;
  char *rem_addr_hex;
  char addrs[27];
  char part_inode[512 - INODE_OFFSET]; // size buff = 512 - all informations before inode
  char *inode;
  while (fgets(buff,sizeof(buff),file)) {
    strncpy(part_inode,buff+INODE_OFFSET,512-INODE_OFFSET);
    inode = strtok(part_inode," ");
    if (atoi(inode) == num_sock) {
      strncpy(addrs,buff+6,27);
      loc_addr_hex=strtok(addrs," ");
      rem_addr_hex=strtok(NULL," ");
      if (addr==LOCAL) // 1 -> locale
	sscanf(loc_addr_hex, "%X:%hX", &addr_port->sin_addr.s_addr, &addr_port->sin_port);
      else // remote
	sscanf(rem_addr_hex, "%X:%hX", &addr_port->sin_addr.s_addr, &addr_port->sin_port);
      fclose(file);
      return 1;
    }
  }
  fclose(file);
  return -1;

}


int get_addr_port_sock(pid_t pid, int fd, int addr_type) {

  struct infos_socket* is = get_infos_socket(pid, fd);
  int protocol = is->protocol;
  
  char path[512];
  char dest[512];
  sprintf(path,"/proc/%d/fd/%d", pid, fd);
  if (readlink(path, dest, 512) == -1) {
    printf("Failed reading /proc/%d/fd/%d",pid,fd);
    return -1;
  }

  char *token;
  token = strtok(dest,"["); // left part before socket id
  token = strtok(NULL,"]"); // socket id 
  int num_socket = atoi(token);
  
  struct sockaddr_in addr_port;
  
  int res=0;

  if (protocol == 1) { // case IPPROTO_ICMP -> protocol unknown -> test TCP
    res = get_addr_port(TCP_PROTOCOL, num_socket, &addr_port, addr_type);
    if (res == -1) { // not tcp -> test UDP
      res = get_addr_port(UDP_PROTOCOL, num_socket, &addr_port, addr_type);
      if (res == -1) // not udp -> test RAW
	res = get_addr_port(RAW_PROTOCOL, num_socket, &addr_port, addr_type);
    }
  }

  if (protocol == 6 || protocol == 0) // case IPPROTO_TCP ou IPPROTO_IP
    res=get_addr_port(TCP_PROTOCOL, num_socket, &addr_port, addr_type);
  if (protocol == 17 ) // case IPPROTO_UDP 
    res=get_addr_port(UDP_PROTOCOL, num_socket, &addr_port, addr_type);
  if (protocol == 255 ) // case IPPROTO_RAW 
    res=get_addr_port(RAW_PROTOCOL, num_socket, &addr_port, addr_type);
      

  if (res==1) {
    if (addr_type==LOCAL) { // locale
      is->ip_local=strdup(inet_ntoa(addr_port.sin_addr));
      is->port_local = addr_port.sin_port;
    } else { // remote
      is->ip_remote=strdup(inet_ntoa(addr_port.sin_addr));
      is->port_remote = addr_port.sin_port;
    }
  }

  return res;
  
}


int get_domain_socket(pid_t pid, int fd) {
  struct infos_socket* is = get_infos_socket(pid, fd);
  
  if (is != NULL )
    return is->domain;
  return -1;
}

int socket_registered(pid_t pid, int fd) {
  struct infos_socket* is = get_infos_socket(pid, fd);
  
  if(is != NULL && !is->closed)
      return 1;
  else if( is != NULL)
    return 0;
  //printf("[IMPORTANT] unknown socket\n");
  return -1;
}


struct infos_socket* get_infos_socket(pid_t pid, int fd) {
  return global_data->process_desc[pid]->fd_list[fd];
}

//TODO faire en sortes que la structure socket soit un lien entre les deux processus qui parle et que l'on puisse les récupérer sans faire des foreach
int get_pid_socket_dest(struct infos_socket *is) {
  
  struct infos_socket* temp_is;
  unsigned int cpt=0;
  
  xbt_dynar_foreach(all_sockets, cpt, temp_is){
    if ((strcmp(temp_is->ip_remote,is->ip_local)==0) 
      && (temp_is->port_remote==is->port_local)
      && (strcmp(temp_is->ip_local,is->ip_remote)==0) 
      && (temp_is->port_local==is->port_remote))
      return temp_is->proc->pid;
  }
  return -1;
}


void close_sockfd(pid_t pid, int fd) {
  struct infos_socket* is = get_infos_socket(pid, fd);
  printf(" (%p) ", is);
  if(is!=NULL)
    is->closed=1;
}



int get_protocol_socket(pid_t pid, int fd) {
  struct infos_socket* is = get_infos_socket(pid, fd);
  
  if (is != NULL )
    return is->protocol;
  return -1;
}

int socket_incomplete(pid_t pid, int fd){
  struct infos_socket* is = get_infos_socket(pid, fd);
  
  if (is != NULL )
    return is->incomplete;
  return -1;
}

int socket_closed(pid_t pid, int fd) { 
  struct infos_socket* is = get_infos_socket(pid, fd);
  
  if (is != NULL )
    return is->closed;
  return -1;
}


int socket_netlink(pid_t pid, int fd) {
  struct infos_socket* is = get_infos_socket(pid, fd);
  
  if (is != NULL )
    return is->protocol==16;
  return -1;
}


struct infos_socket* getSocketInfoFromContext(char* ip_remote, int port_remote, char* ip_local, int port_local)
{
  struct infos_socket* temp_is;
  unsigned int cpt=0;
  xbt_dynar_foreach(all_sockets, cpt, temp_is){
    print_infos_socket(temp_is);
    if ((strcmp(temp_is->ip_remote,ip_remote)==0) 
      && (temp_is->port_remote==port_remote)
      && (strcmp(temp_is->ip_local,ip_local)==0) 
      && (temp_is->port_local==port_local)){
      return temp_is;
    }
  }
  return NULL;
}

//FIXME what happen when there's to sending akwnowledgement in the same turn
//maybe use an global ghost task which have every recv task in dependencies and use last_computation task mecanism
int handle_communication_stat(struct infos_socket* is)
{
  int result=0;
  int *size = (int*)xbt_fifo_shift(is->recv_info->send_fifo);
  if(size==NULL)
    return 0;
  
  //if size == -1 , that mean that we start a new recv and we have to make a new task
  if(*size == -1)
  {
//     insert_trace_comm(is->proc->pid, is->fd, "recv", 0);
    task_schedule_receive(is);
    free(size);
    result = 1;
    size = (int*)xbt_fifo_shift(is->recv_info->send_fifo);
  }
  
  if(is->recv_info->quantity_recv < *size)
  {
    xbt_fifo_unshift(is->recv_info->send_fifo, size);
  }
  else
  {
    is->recv_info->quantity_recv -= *size;
    free(size);
    //til we acknowledge sending, we continue
    if(is->recv_info->quantity_recv > 0)
    {
      result = 1;
      handle_communication_stat(is);
    }
  }
  
  return result;
}


int handle_new_receive(int pid, int sockfd, int length)
{
  struct infos_socket* is = get_infos_socket(pid, sockfd);

  recv_information* recv = is->recv_info;
  recv->quantity_recv += length;
  
  return handle_communication_stat(is);
}


//TODO simplify handling 
void handle_new_send(struct infos_socket *is,  int length)
{
  recv_information* recv = is->recv_info;
  int *size = malloc(sizeof(int));
  *size=length;
  
  int *buf = malloc(sizeof(int));
  *buf=-1;

  xbt_fifo_push(recv->send_fifo, buf);
  xbt_fifo_push(recv->send_fifo, size);
}


int finish_all_communication(int pid){
  
  process_descriptor* proc = global_data->process_desc[pid];
  int i=0;
  int result=0;
  for(i=0; i<MAX_FD ; ++i)
  {
    if (proc->fd_list[i]!=NULL)
    {
      int *size = (int*)xbt_fifo_shift(proc->fd_list[i]->recv_info->send_fifo);
      while(size != NULL)
      {
	insert_trace_comm(pid, i, "recv", 0);
	//create_recv_communication_task(proc->fd_list[i]);
	free(size);
	size = (int*)xbt_fifo_shift(proc->fd_list[i]->recv_info->send_fifo);
	result=1;
      }
      //FIXME add reference counter to see if this is the last process to use the socket
      //delete_socket(pid, i);
      proc->fd_list[i]=NULL;
    }
  }
  return result;
}

