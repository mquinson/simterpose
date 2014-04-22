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
//#define IP "162.32.43.1"

//#define BUFFER_SIZE 1000


int main(int argc, char** argv){

  if (argc < 3) {
    fprintf(stderr, "usage: %s number_of_loops buffer_size \n", argv[0]);
    return EXIT_FAILURE;
  }

  int number_of_loops = atoi(argv[1]);
  int buffer_size = atoi(argv[2]);
  
  int serverSocket;
  char *buff=malloc(buffer_size);
  u_short port;
  int res;
  int client_socket;

  if((serverSocket = socket(AF_INET,SOCK_STREAM,0)) < 0){
    perror("Server: error socket");
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
      perror("Server: error setsockopt");
      exit(1);
    }

   
    if(getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0){
      perror("Server: error getsockopt");
      exit(1);
    }

    if(bind(serverSocket, (struct sockaddr *)serv_addr, sizeof(struct sockaddr_in)) < 0){
      perror("Server: error bind");
      exit(1);
    }else{
      if(listen(serverSocket,SOMAXCONN) < 0){
	perror("Server: error listen");
	exit(1);
      }else{
	printf("Server: Attente demande de connexion\n");
	int clilen=sizeof(struct sockaddr_in);
	struct sockaddr_in *cli_addr = (struct sockaddr_in *)malloc(sizeof(struct sockaddr_in));
        
//         struct pollfd ld = {serverSocket, POLLIN, 0};
//         int temp;
//         while((temp = poll(&ld, 1, 100)) != 1);
//         
//         printf("End of pool : %d\n", temp);
        
	if((client_socket=accept(serverSocket, (struct sockaddr *)cli_addr,(socklen_t *)&clilen)) < 0){
	  perror("Server: error accept");
	  exit(1);
	}else{
          printf("Server: Connexion acceptée\n");
          int length = buffer_size;
          while(length !=0)
          {
            res = recv(client_socket,buff,length,0);
            if(res==-1){
              perror("Server: erreur réception");
          exit(1);
            }
            length -= res;
        //    printf("Server : recv %d (left %d)\n", res, length);
          }
          //printf("Message reçu : %s",buff);
//          strcpy(buff,"Server: envoi \n");
 //         printf("Server: envoi au client\n");
          int i=0;
          int j;
          for(i=0; i<2000000 ; ++i)
          {
            j=i*(i%14);
            --j;
          }
          res=send(client_socket,buff,buffer_size,0);
          if(res==-1){
            perror("Server erreur envoi");
            exit(1);
          }
           shutdown(client_socket,2);
           close(client_socket);
	}
	
	if((client_socket=accept(serverSocket, (struct sockaddr *)cli_addr,(socklen_t *)&clilen)) < 0){
          perror("Server: error accept");
          exit(1);
        }else{
       //   printf("Server: Connexion acceptée\n");
          
          int ia=0;
          for(ia=0; ia<number_of_loops; ++ia)
          {
            int length = buffer_size;
            while(length >0)
            {
              res = recv(client_socket,buff,length,0);
              if(res==-1){
                perror("Server: erreur réception");
                exit(1);
              }
              length -= res;
          //    printf("Server : recv %d (left %d)\n", res, length);
            }
          //  printf("Server: Message reçu : %s",buff);
         //   strcpy(buff,"envoi serveur\n");
        //  printf("Server: envoi au client\n");
            res=send(client_socket,buff,buffer_size,0);
            if(res==-1){
              perror("Server: erreur envoi");
              exit(1);
            }
       //     printf("Server: envoyé\n");
          }
           shutdown(client_socket,2);
           close(client_socket);
        }
      }
    }
  }
  
  return 0;
}
