#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>

int main(int argc, char *argv[]){

  if(argc<3){
    fprintf(stderr, "Usage: %s <port> <file-to-exec> [args...]\n", argv[0]);
    exit(EXIT_FAILURE);
  }


  int sockfd = socket(AF_INET, SOCK_DGRAM, 0);
  uint16_t port = atoi(argv[1]);

  struct sockaddr_in localhost = {
      .sin_family = AF_INET,
      .sin_port = htons(port),
      .sin_addr = { .s_addr = 0x0100007f },
  };

  bind(sockfd, &localhost, sizeof(localhost));

  char **newargv = &argv[2];

  // close
  close(0);
  close(1);
  //close(2);

  // dup to socket
  dup2(sockfd, 0);
  dup2(sockfd, 1);
  //dup2(sockfd, 2);

  execv(argv[2], newargv);
  exit(EXIT_FAILURE);
}
