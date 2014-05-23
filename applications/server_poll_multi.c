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
#include <sys/select.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>


#define SERV_PORT 2227

#define BUFFER_SIZE 100000


int main()
{

  int serverSocket;
  char *buff = malloc(BUFFER_SIZE);
  u_short port;
  int res;
  int client_socket;
  int nbfd;
  int conn = 2;

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


    if (getsockopt(serverSocket, SOL_SOCKET, SO_REUSEADDR, &on, &on) < 0) {
      perror("error getsockopt");
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
        printf("Attente demande de connexion\n");
        int clilen = sizeof(struct sockaddr_in);
        struct sockaddr_in *cli_addr = (struct sockaddr_in *) malloc(sizeof(struct sockaddr_in));

        struct pollfd ld = { serverSocket, POLLIN, 0 };

        struct pollfd *arr_fd = malloc(sizeof(struct pollfd));
        arr_fd[0] = ld;

        int nbfd = 1;

        while (conn) {
          int fd_match = poll(arr_fd, nbfd, 1000);
          if (fd_match == 0) {
            printf("Time out poll\n");
            continue;
          } else {
            printf("Starting looking poll result\n");
            int i;
            for (i = 1; i < nbfd; ++i) {
              if (arr_fd[i].revents & POLLIN) {
                res = recv(arr_fd[1].fd, buff, BUFFER_SIZE, 0);
                if (res == -1) {
                  perror("erreur réception server");
                  exit(1);
                }
                if (res == 0) {
                  printf("Socket is closed %d\n", conn);
                  if (i != nbfd - 1)
                    memmove(&arr_fd[i], &arr_fd[i + 1], (nbfd - i - 1) * sizeof(struct pollfd));
                  --nbfd;
                  arr_fd = realloc(arr_fd, sizeof(struct pollfd) * nbfd);
                  --conn;
                }

                arr_fd[i].revents = 0;
              }
            }
            if (arr_fd[0].revents & POLLIN) {
              printf("Connexion acceptée %d\n", POLLIN);
              client_socket = accept(serverSocket, (struct sockaddr *) cli_addr, (socklen_t *) & clilen);
              ++nbfd;
              arr_fd = realloc(arr_fd, sizeof(struct pollfd) * nbfd);
              arr_fd[nbfd - 1].fd = client_socket;
              arr_fd[nbfd - 1].events = POLLIN;
              arr_fd[nbfd - 1].revents = 0;
              arr_fd[0].revents = 0;
            }
          }
        }

      }
    }
  }

  return 0;
}
