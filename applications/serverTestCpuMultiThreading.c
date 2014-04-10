#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERV_PORT 2222

int main(int argc, char *argv[]){

  int serverSocket;
  u_short port;
  int res;
  char *buff=malloc(512);
  int client_socket;
  int nb_exe=0;

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
    }
    if(listen(serverSocket,SOMAXCONN) < 0){
      perror("error listen");
      exit(1);
    }
    printf("Attente demande de connexion\n");
    int clilen=sizeof(struct sockaddr_in);
    struct sockaddr_in *cli_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
    if((client_socket=accept(serverSocket, (struct sockaddr *)cli_addr,(socklen_t *)&clilen)) < 0){
      perror("error accept");
      exit(1);
    }
    printf("Connexion acceptée\n");

    int size_ret=atoi(argv[1]); // taille mess retour
    char *mess_ret=malloc(size_ret*sizeof(char));
    res=recv(client_socket,mess_ret,size_ret,0); // dernier mess fin
    if(res==-1){
      perror("erreur réception server");
      exit(1);
    }else{
      printf("%s\n",mess_ret);
    }
  }

  shutdown(client_socket,2);
  close(client_socket);

}
