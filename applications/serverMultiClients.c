#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <sys/timeb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#define SERV_PORT 2226

#define BUFSIZE 1500
int str_echo(int sockfd)
{
  int nrcv, nsnd;
  char msg[BUFSIZE];

  /*    * Attendre  le message envoye par le client 
   */
  memset((char *) msg, 0, sizeof(msg));
  if ((nrcv = read(sockfd, msg, sizeof(msg) - 1)) < 0) {
    perror("servmulti : : readn error on socket");
    exit(1);
  }
  msg[nrcv] = '\0';
  printf("servmulti :message recu=%s du processus %d nrcv = %d \n", msg, getpid(), nrcv);

  if ((nsnd = write(sockfd, msg, nrcv)) < 0) {
    printf("servmulti : writen error on socket");
    exit(1);
  }
  printf("nsnd = %d \n", nsnd);
  return (nsnd);
}                               /* end of function */




int main()
{

  int serverSocket;
  u_short port;
  int res;
  char *buff = malloc(512);
  int client_socket;

  if ((serverSocket = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
    perror("error socket");
    exit(1);
  } else {

    struct sockaddr_in *serv_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));
    memset((char *) serv_addr, (char) 0, sizeof(struct sockaddr_in));

    port = SERV_PORT;
    serv_addr->sin_family = AF_INET;
    serv_addr->sin_port = htons(port);
    serv_addr->sin_addr.s_addr = htonl(INADDR_ANY);

    int on = 1;
    if (setsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, sizeof(on)) < 0) {
      perror("error setsockopt");
      exit(1);
    }

    if (bind(serverSocket, (struct sockaddr *) serv_addr, sizeof(struct sockaddr_in)) < 0) {
      perror("error bind");
      exit(1);
    } else {
      if (listen(serverSocket, SOMAXCONN) < 0) {
        perror("error listen");
        exit(1);
      } else {


        int maxfdp1 = serverSocket + 1;
        fd_set allset, rset;
        FD_ZERO(&allset);
        FD_ZERO(&rset);
        FD_SET(serverSocket, &rset);
        int i;
        int tab_clients[FD_SETSIZE];
        for (i = 0; i < FD_SETSIZE; i++) {
          tab_clients[i] = -1;
        }
        int nbfd;
        i = 0;


        printf("Attente demande de connexion\n");
        int clilen = sizeof(struct sockaddr_in);
        struct sockaddr_in *cli_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));



        while (1) {
          i = 0;

          allset = rset;
          nbfd = select(maxfdp1, &allset, NULL, NULL, NULL);
          if (FD_ISSET(serverSocket, &allset))  // Demande de connexion
          {
            client_socket = accept(serverSocket, (struct sockaddr *) cli_addr, (socklen_t *) & clilen);

            // Recherche d'une place libre
            while ((i < FD_SETSIZE) && (tab_clients[i] >= 0)) {
              i++;
            }
            if (i == FD_SETSIZE) {
              exit(1);
            }

            tab_clients[i] = client_socket;
            FD_SET(client_socket, &rset);
            maxfdp1 = client_socket + 1;


            nbfd--;             // On a traité une demande d'action

          }

          i = 0;
          while ((nbfd > 0) && (i < FD_SETSIZE)) {
            if (tab_clients[i] != -1) {
              if (FD_ISSET(tab_clients[i], &allset)) {
                memset((char *) buff, (char) 0, 512);   // raz buffer
                res = recv(tab_clients[i], buff, 512, 0);
                if (res == -1) {
                  perror("erreur réception server");
                  exit(1);
                } else {
                  printf("Message reçu : %s", buff);
                  if (strcmp(buff, "exit") == 0)
                    exit(0);

                  res = send(client_socket, "reçu \n", 512, 0);
                  if (res == -1) {
                    perror("erreur envoi server");
                    exit(1);
                  }
                }

                nbfd--;
              }
            }
            i++;

          }

        }
        shutdown(serverSocket, 2);
        close(serverSocket);
      }
    }
  }
}
