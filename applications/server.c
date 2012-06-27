#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>

#define SERV_PORT 2227

#define BUFFER_SIZE 100000

int main(){

  int serverSocket;
  u_short port;
  int res;
  char *buff=malloc(BUFFER_SIZE);
  int client_socket;

  if((serverSocket = socket(AF_INET,SOCK_STREAM,0)) < 0){
    perror("error socket");
    exit(1);
  }else{
    
    struct sockaddr_in *serv_addr=(struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    memset((char *)serv_addr,(char)0,sizeof(struct sockaddr_in));

    port=SERV_PORT;
    serv_addr->sin_family=AF_INET;
    serv_addr->sin_port=htons(port);
    serv_addr->sin_addr.s_addr=htonl(INADDR_ANY);


    int on = 1;
    if(setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0){
      perror("error setsockopt");
      exit(1);
    }

   
    if(getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0){
      perror("error getsockopt");
      exit(1);
    }

    if(bind(serverSocket, (struct sockaddr *)serv_addr, sizeof(struct sockaddr_in)) < 0){
      perror("error bind");
      exit(1);
    }else{
      if(listen(serverSocket,SOMAXCONN) < 0){
	perror("error listen");
	exit(1);
      }else{
	printf("Attente demande de connexion\n");
	int clilen=sizeof(struct sockaddr_in);
	struct sockaddr_in *cli_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        
//         struct pollfd ld = {serverSocket, POLLIN, 0};
//         int temp;
//         while((temp = poll(&ld, 1, 100)) != 1);
//         
//         printf("End of pool : %d\n", temp);
	if((client_socket=accept(serverSocket, (struct sockaddr *)cli_addr,(socklen_t *)&clilen)) < 0){
	  perror("error accept");
	  exit(1);
	}else{
	  printf("Connexion acceptée\n");
	  int length = BUFFER_SIZE;
	  while(length !=0)
	  {
	    res = recv(client_socket,buff,length,0);
	    if(res==-1){
	      perror("erreur réception server");
	      exit(1);
	    }
	    length -= res;
	    printf("Server : recv %d (left %d)\n", res, length);
	  }
	    //printf("Message reçu : %s",buff);
	  strcpy(buff,"envoi serveur\n");
	  printf("Server envoie au client\n");
	  int i=0;
	  int j;
	  for(i=0; i<2000000 ; ++i)
	  {
	    j=i*(i%14);
	    --j;
	  }
	  res=send(client_socket,buff,BUFFER_SIZE,0);
	  if(res==-1){
	    perror("erreur envoi server");
	    exit(1);
	  }
	  shutdown(client_socket,2);
	  close(client_socket);
	}
      }
    }
  }
}
