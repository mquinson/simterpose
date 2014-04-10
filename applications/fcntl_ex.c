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
#include <fcntl.h>
#include <errno.h>

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
    fcntl(serverSocket, F_GETFL, 0);
    fcntl(serverSocket, F_SETFL, O_RDWR|O_NONBLOCK);

    
    
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
        
        int c;
        if((c = socket(AF_INET,SOCK_STREAM,0)) < 0){
          perror("error socket");
          exit(1);
        }else{
          
          fcntl(c, F_SETFL, O_RDWR|O_NONBLOCK);
          serv_addr->sin_addr.s_addr=inet_addr("127.0.0.1");
          
          if(connect(c,(struct sockaddr *)serv_addr, sizeof(struct sockaddr_in)) < 0){
            if(errno =! EINPROGRESS)
            {
              printf(" %s echec demande de connexionn", strerror(errno));
              exit(0);
            }
          }
          struct sockaddr_in lala;
          socklen_t len = sizeof(struct sockaddr_in);
          getpeername(c, (struct sockaddr *)&lala, &len);
        }

        int clilen=sizeof(struct sockaddr_in);
        struct sockaddr_in *cli_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        
        if((client_socket=accept(serverSocket, (struct sockaddr *)cli_addr,(socklen_t *)&clilen)) < 0){
          perror("error accept");
          exit(1);
        }
      }
    }
  }
  
  return 0;
}