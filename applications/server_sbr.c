#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <poll.h>
#include <pthread.h>

#define SERV_PORT 2227

#define BUFFER_SIZE 1024


int main(){
  int serverSocket;
  char *buff=malloc(BUFFER_SIZE);
  u_short port;
  int res;
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
        
        
        if((client_socket=accept(serverSocket, (struct sockaddr *)cli_addr,(socklen_t *)&clilen)) < 0){
          perror("error accept");
          exit(1);
        }else{
          char *message = "Hello\n";
          send(client_socket, message , sizeof("Hello\n"), 0);
          
          res = recv(client_socket,buff,BUFFER_SIZE,0);
          if(res==-1){
            perror("erreur réception server");
            exit(1);
          }
          printf("Message reçu du client %s\n", buff);
          
          res = recv(client_socket,buff,BUFFER_SIZE,0);
          if(res==-1){
            perror("erreur réception server");
            exit(1);
          }
          printf("Message reçu du client %s\n", buff);
        }
      }
    }
  }
  
  return 0;
}