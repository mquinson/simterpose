#include "sockets.h"

struct infos_socket all_sockets[MAX_SOCKETS];
int nb_sockets = 0;

int get_addr_port_sock(pid_t pid, int fd, int protocol, struct infos_socket *is, int addr);
void print_infos_socket();


void confirm_register_socket(pid_t pid, int sockfd, int domain, int protocol) {

  struct infos_socket is;
  is.pid=pid;
  is.sockfd=sockfd;
  is.domain=domain;
  is.protocol=protocol;
  is.ip_local="";
  is.ip_remote="";
  is.port_local=0;
  is.port_remote=0;
  is.incomplete=1;
  is.closed=0;
  is.recv_arr=xbt_dynar_new(sizeof(recv_information), free);

  all_sockets[nb_sockets]=is;
  nb_sockets++;
  
  print_infos_socket();
      
}

void delete_socket(pid_t pid, int fd) {
  
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid ) {
      int j;
      for(j=i+1;j<nb_sockets;j++)
	all_sockets[j-1]=all_sockets[j];
      nb_sockets--;
      break;
    }
    i++;
  }

}

void register_socket(pid_t pid, int sockfd, int domain, int protocol) {
  //printf("Registering socket %d for processus %d\n", sockfd, pid);
  if (socket_registered(pid,sockfd)) {
    if (socket_closed(pid,sockfd)) {
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

  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid) {
      if (all_sockets[i].domain == 2) { // PF_INET
	if (get_addr_port_sock(pid, fd, all_sockets[i].protocol, &all_sockets[i],1)) { // 1-> locale
	  if (get_addr_port_sock(pid, fd, all_sockets[i].protocol, &all_sockets[i],2)) { // 2 -> remote
	    all_sockets[i].incomplete=0;
	  }
	}
	print_infos_socket();
	break;
	  
      }
    }
    i++;
  }
  
}

void set_localaddr_port_socket(pid_t pid, int fd, char *ip, int port) {
  
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid) {
      all_sockets[i].ip_local=strdup(ip);
      all_sockets[i].port_local=port;
      print_infos_socket();
      break;
    }
    i++;
  }
  
}

void get_localaddr_port_socket(pid_t pid, int fd) {
  
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid) {
      if (all_sockets[i].domain == 2) { // PF_INET
	if (!get_addr_port_sock(pid, fd, all_sockets[i].protocol, &all_sockets[i], 1))
	  printf("Failed reading locale addr:port after bind\n");
	print_infos_socket();
	break;
	  
      }
    }
    i++;
  }
  
}


void print_infos_socket(char *syscall) {
  int i=0;
 
  fprintf(stdout,"\n%5s %5s %10s %10s %21s %21s %12s %10s\n","pid","fd","domain","protocol","locale_ip:port","remote_ip:port","incomplete", "closed");
  while (i<nb_sockets ) {
    fprintf(stdout,"%5d %5d %10d %10d %15s:%5d %15s:%5d %12d %10d\n",
	    all_sockets[i].pid,
	    all_sockets[i].sockfd,
	    all_sockets[i].domain,
	    all_sockets[i].protocol,
	    all_sockets[i].ip_local,
	    all_sockets[i].port_local,
	    all_sockets[i].ip_remote,
	    all_sockets[i].port_remote,
	    all_sockets[i].incomplete,
	    all_sockets[i].closed);
    i++;
  }

}

int get_addr_port(int type, int num_sock, struct sockaddr_in *addr_port, int addr ) {

  FILE *file;
  
  
  //printf("Socket number : %d\n", num_sock);
  if (type == 0) // TCP
    file=fopen("/proc/net/tcp","r");
  else if (type == 1) // UDP
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
  char part_inode[435]; // size buff = 512 - all informations before inode
  char *inode;
  while (fgets(buff,sizeof(buff),file)) {
    strncpy(part_inode,buff+91,435);
    inode = strtok(part_inode," ");
    if (atoi(inode) == num_sock) {
      strncpy(addrs,buff+6,27);
      loc_addr_hex=strtok(addrs," ");
      rem_addr_hex=strtok(NULL," ");
      if (addr==1) // 1 -> locale
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


int get_addr_port_sock(pid_t pid, int fd, int protocol, struct infos_socket *is, int addr) {

  char path[512];
  char dest[512];
  sprintf(path,"/proc/%d/fd/%d", pid, fd);
  if (readlink(path, dest, 512) == -1) {
    printf("Failed reading /proc/%d/fd/%d",pid,fd);
    return -1;
  }
  //printf("Reading of fd description : %s\n", dest);
  char *token;
  token = strtok(dest,"["); // left part before socket id
  token = strtok(NULL,"]"); // socket id 
  int num_socket = atoi(token);
  
  struct sockaddr_in addr_port;
  
  int res=0;

  if (protocol == 1) { // case IPPROTO_ICMP -> protocol unknown -> test TCP
    res = get_addr_port(0, num_socket, &addr_port, addr);
    if (res == -1) { // not tcp -> test UDP
      res = get_addr_port(1, num_socket, &addr_port, addr);
      if (res == -1) // not udp -> test RAW
	res = get_addr_port(2, num_socket, &addr_port, addr);
    }
  }

  if (protocol == 6 || protocol == 0) // case IPPROTO_TCP ou IPPROTO_IP
    res=get_addr_port(0, num_socket, &addr_port, addr);
  if (protocol == 17 ) // case IPPROTO_UDP 
    res=get_addr_port(1, num_socket, &addr_port, addr);
  if (protocol == 255 ) // case IPPROTO_RAW 
    res=get_addr_port(2, num_socket, &addr_port, addr);
      

  if (res==1) {
    if (addr==1) { // locale
      is->ip_local=strdup(inet_ntoa(addr_port.sin_addr));
      is->port_local = addr_port.sin_port;
    } else { // remote
      is->ip_remote=strdup(inet_ntoa(addr_port.sin_addr));
      is->port_remote = addr_port.sin_port;
    }
  }

  return res;
  
}


int get_domain_sockfd(pid_t pid, int fd) {
  int i=0;
  while (i<nb_sockets ) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid )
      return all_sockets[i].domain;
    i++;
  }
  return -1;
}

int socket_registered(pid_t pid, int fd) {
  int i=0;
  while (i<nb_sockets ) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid && !all_sockets[i].closed )
      return 1;
    i++;
  }
  //printf("[IMPORTANT] unknown socket\n");
  return -1;
}

void get_infos_socket(pid_t pid, int fd, struct infos_socket *res) {

  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid ) {
      res->ip_local=all_sockets[i].ip_local;
      res->port_local=all_sockets[i].port_local;
      res->ip_remote=all_sockets[i].ip_remote;
      res->port_remote=all_sockets[i].port_remote;
      break;
    }
    i++;
  }
}

int get_pid_socket_dest(struct infos_socket *is) {
  int i=0;
  while (i<nb_sockets) {
    if ((strcmp(all_sockets[i].ip_remote,is->ip_local)==0) 
       && (all_sockets[i].port_remote==is->port_local)
       && (strcmp(all_sockets[i].ip_local,is->ip_remote)==0) 
       && (all_sockets[i].port_local==is->port_remote))
      return all_sockets[i].pid;
    i++;
  }
  return -1;
}

void close_sockfd(pid_t pid, int fd) {
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid ) {
      all_sockets[i].closed=1;
      break;
    }
    i++;
  }
}



int get_protocol_socket(pid_t pid, int fd) {
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid )
      return all_sockets[i].protocol;
    i++;
  }
  return -1;
}

int get_domain_socket(pid_t pid, int fd) {
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid ) 
      return all_sockets[i].domain;
    i++;
  }
  return -1;
}

int socket_incomplete(pid_t pid, int fd){
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid)
      return all_sockets[i].incomplete;
    i++;
  }
  return -1;
}

int socket_closed(pid_t pid, int fd) { 
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid )
      return all_sockets[i].closed;
    i++;
  }
  return -1;
}

int socket_netlink(pid_t pid, int fd) {
  int i=0;
  while (i<nb_sockets) {
    if (all_sockets[i].sockfd == fd && all_sockets[i].pid == pid )
      return (all_sockets[i].protocol==16);
    i++;
  }
  return -1;
}


struct infos_socket* getSocketInfoFromContext(char* ip_remote, int port_remote, char* ip_local, int port_local)
{
  int i=0;
  while (i<nb_sockets) {
    if ((all_sockets[i].port_remote == port_remote) && (all_sockets[i].port_local == port_local) && !strcmp(all_sockets[i].ip_remote, ip_remote) && !strcmp(all_sockets[i].ip_local, ip_local))
      return  &(all_sockets[i]);
    i++;
  }
  return NULL;
}

void add_new_transmission(struct infos_socket* is, int length, char* ip_remote, int port_remote)
{
  recv_information* recv = malloc(sizeof(recv_information));
  recv->ip_remote = strdup(ip_remote);
  recv->port_remote = port_remote;
  recv->length = length;
  
  xbt_dynar_insert_at(is->recv_arr, xbt_dynar_length(is->recv_arr), recv);
  
}

