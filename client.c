#include <sys/select.h>
#include <sys/socket.h>
#include <stdio.h>
#include <string.h>
#include <netinet/in.h>
#include <unistd.h>
#include <netdb.h>   // gethostbyname()
#include <arpa/inet.h>

#define SERVER_PORT     3005
#define BUFFER_LENGTH    250
#define FALSE              0
#define SERVER_NAME     "localhost"
#define MAX_HOST_NAME_LENGTH 20


int main(int argc, char *argv[]) {
   int    sd=-1, rc, bytesReceived;
   char   buffer[BUFFER_LENGTH];
   char   server[MAX_HOST_NAME_LENGTH];
   struct sockaddr_in serveraddr;
   struct hostent *hostp;

   do   {
      sd = socket(AF_INET, SOCK_STREAM, 0);
      //test error sd < 0

      if (argc > 1)  strcpy(server, argv[1]);
      else  strcpy(server, SERVER_NAME);

      memset(&serveraddr, 0, sizeof(serveraddr));
      serveraddr.sin_family      = AF_INET;
      serveraddr.sin_port        = htons(SERVER_PORT);
      serveraddr.sin_addr.s_addr = inet_addr(server);

      if (serveraddr.sin_addr.s_addr == (unsigned long)INADDR_NONE)      {
         hostp = gethostbyname(server);
         if (hostp == (struct hostent *)NULL) {
            printf("Host not found --> ");
            break;
         }

         memcpy(&serveraddr.sin_addr,
                hostp->h_addr,
                sizeof(serveraddr.sin_addr));
      }

      rc = connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
      // test error rc < 0

      printf("Connect returned %d\n", rc);

      memset(buffer, 'a', sizeof(buffer));
      rc = send(sd, buffer, sizeof(buffer), 0);
      // test error rc < 0

      printf("send returned %d\n", rc);
     
       bytesReceived = 0;
       while (bytesReceived < BUFFER_LENGTH) {
             rc = recv(sd, & buffer[bytesReceived],
                    BUFFER_LENGTH - bytesReceived, 0);
             // test error rc < 0 or rc == 0
             printf("bytes received %d\n", rc);

              bytesReceived += rc;
        }

   } while (FALSE);

//    shutdown(sd, SHUT_RDWR);

    if (sd != -1)
      close(sd);
}



