#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>    
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>


#define SERVER_PORT     3005
#define BUFFER_LENGTH    250
#define FALSE              0

int  main() {
    int    sd=-1, sd2=-1;
    int    rc, length, on=1;
    char   buffer[BUFFER_LENGTH];
    fd_set read_fd;
    struct timeval timeout;
    struct sockaddr_in serveraddr;

    //create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);
    // test error: sd < 0)
    if (sd < 0) {
        perror("Socket creation failed");
        return -1;
    }      

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family      = AF_INET;
    serveraddr.sin_port        = htons(SERVER_PORT);
    serveraddr.sin_addr.s_addr = htonl(INADDR_ANY);

    //bind socket
    rc = bind(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    // test error rc < 0
    if (rc < 0) {
        perror("Bind failed");
        close(sd);
        return -1;
    }

    //tell socket to listen
    rc = listen(sd, 10);
    // test error rc< 0
    if (rc < 0) {
        perror("Listen failed");
        close(sd);
        return -1;
    }

    printf("Ready for client connect().\n");

    do {

        sd2 = accept(sd, NULL, NULL);
        // test error sd2 < 0
        if (sd2 < 0) {
            perror("Accept failed");
            continue;
        }

        timeout.tv_sec  = 0;
        timeout.tv_usec = 0;

        FD_ZERO(&read_fd);
        FD_SET(sd2, &read_fd);

        rc = select(1, &read_fd, NULL, NULL, &timeout);
        // test error rc < 0
        if (rc < 0) {
            perror("Select failed");
            continue;
        }

        length = BUFFER_LENGTH;


        rc = recv(sd2, buffer, sizeof(buffer), 0);
        // test error rc < 0 or rc == 0 or   rc < sizeof(buffer)
        if (rc < 0 || rc == 0 || rc < sizeof(buffer)) {
            perror("Receive Failed");
            continue;
        }
        printf("server received %d bytes\n", rc);
        printf("Hash Received: %s\n", buffer);

        //implement sha1
        //check arguements
        SHA_CTX* shactx;
        unsigned char digest[SHA_DIGEST_LENGTH];
        char digest_str[BUFFER_LENGTH];
        char num[50];
        int res = 0;
        
        for (int i = 0; i <= 9999; i++) {
            shactx = malloc(sizeof(SHA_CTX));
            if (shactx == NULL) {
                free(shactx);
                res = -1;
                break;
            }

            //initialize sha1 components
            SHA1_Init(shactx);

            //call update based on digits in pin
            sprintf(num, "%d", i);
            if(i >= 0 && i < 10) {
                SHA1_Update(shactx, num, 1);
            } else if(i >=10 && i < 100) {
                SHA1_Update(shactx, num, 2);
            } else if(i >=100 && i < 1000) {
                SHA1_Update(shactx, num, 3);
            } else if(i >=1000 && i < 10000) {
                SHA1_Update(shactx, num, 4);
            } else { 
                printf("Error: i(%d) out of bounds of program\n", i);
                free(shactx);
                continue;
            }

            SHA1_Final(digest, shactx);

            //convert digest into a hexadecimal string to be compared to the buffer passed
            memset(digest_str, 0, sizeof(digest_str));
            for (int j = 0; j < SHA_DIGEST_LENGTH; j++) {
                sprintf(&digest_str[j * 2],"%02x", digest[j] );
            }
            digest_str[2 * SHA_DIGEST_LENGTH] = '\0';

            if (strcmp(digest_str, buffer) == 0) {
                free(shactx);
                res = 1;
                break;
            } 

            free(shactx);
        }
        memset(buffer, 0, sizeof(buffer));
        if (res == 1) {
            //digest_str is used for a temporary string- an alternate to its original purpose
            memset(digest_str, 0, BUFFER_LENGTH);
            sprintf(digest_str, "PIN found: %s\n", num);
            strcpy(buffer, digest_str);
        } else if (res ==0 ) {
            strcpy(buffer, "PIN could not be found\n");
        } else if (res == -1) {
            strcpy(buffer, "Server Encountered Error. Try again.\n");
        } else {
            strcpy(buffer, "Server Encountered VERY ODD Error. Try again.\n");
        }
        
        rc = send(sd2, buffer, sizeof(buffer), 0);
        // test error rc < 0
        printf("server returned %d bytes\n", rc);

    } while (1);

    if (sd != -1)
        close(sd);
    if (sd2 != -1)
        close(sd2);
}


