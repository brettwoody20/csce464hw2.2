#include <sys/select.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>    
#include <netinet/in.h>
#include <unistd.h>
#include <openssl/sha.h>
#include <errno.h>
#include <malloc.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <resolv.h>
#include "openssl/ssl.h"
#include "openssl/err.h"


#define SERVER_PORT     3005
#define BUFFER_LENGTH    250
#define FALSE              0
#define FAIL              -1

int OpenListener(int port)
{
    int sd;
    struct sockaddr_in addr;
    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = INADDR_ANY;
    if (bind(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 )
    {
        perror("can't bind port");
        abort();
    }
    if ( listen(sd, 10) != 0 )
    {
        perror("Can't configure listening port");
        abort();
    }
    return sd;
}
int isRoot()
{
    if (getuid() != 0)
    {
        return 0;
    }
    else
    {
        return 1;
    }
}
SSL_CTX* InitServerCTX(void)
{
    const SSL_METHOD *method;
    SSL_CTX *ctx;
    OpenSSL_add_all_algorithms();  /* load & register all cryptos, etc. */
    SSL_load_error_strings();   /* load all error messages */
    method = TLS_server_method();  /* create new server-method instance */
    ctx = SSL_CTX_new(method);   /* create new context from method */
    if ( ctx == NULL )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    return ctx;
}
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile)
{
    /* set the local certificate from CertFile */
    if ( SSL_CTX_use_certificate_file(ctx, CertFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* set the private key from KeyFile (may be the same as CertFile) */
    if ( SSL_CTX_use_PrivateKey_file(ctx, KeyFile, SSL_FILETYPE_PEM) <= 0 )
    {
        ERR_print_errors_fp(stderr);
        abort();
    }
    /* verify private key */
    if ( !SSL_CTX_check_private_key(ctx) )
    {
        fprintf(stderr, "Private key does not match the public certificate\n");
        abort();
    }
}
void ShowCerts(SSL* ssl)
{
    X509 *cert;
    char *line;
    cert = SSL_get_peer_certificate(ssl); /* Get certificates (if available) */
    if ( cert != NULL )
    {
        printf("Server certificates:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);
        free(line);
        X509_free(cert);
    }
    else
        printf("No certificates.\n");
}
void Servlet(SSL* ssl) /* Serve the connection -- threadable */
{
    char buffer[BUFFER_LENGTH] = {0};
    int sd, bytes;
    
    if ( SSL_accept(ssl) == FAIL )     /* do SSL-protocol accept */
        ERR_print_errors_fp(stderr);
    else
    {
        ShowCerts(ssl);        /* get any certificates */
        bytes = SSL_read(ssl, buffer, sizeof(buffer)); /* get request */
        buffer[bytes] = '\0';
        printf("Client msg: \"%s\"\n", buffer);
        if ( bytes > 0 )
        {
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
            
            SSL_write(ssl, buffer, sizeof(buffer)/sizeof(buffer[0]));
        }
        else
        {
            ERR_print_errors_fp(stderr);
        }
    }
    sd = SSL_get_fd(ssl);       /* get socket connection */
    SSL_free(ssl);         /* release SSL state */
    close(sd);          /* close connection */
}

int main() {
    SSL_CTX *ctx;
    int server;
    //Only root user have the permsion to run the server
    if(!isRoot())
    {
        printf("This program must be run as root/sudo user!!");
        exit(0);
    }

    // Initialize the SSL library
    SSL_library_init();
    ctx = InitServerCTX();        /* initialize SSL */
    LoadCertificates(ctx, "cert.pem", "key.pem"); /* load certs */
    server = OpenListener(SERVER_PORT);    /* create server socket */
    while (1)
    {
        struct sockaddr_in addr;
        socklen_t len = sizeof(addr);
        SSL *ssl;
        int client = accept(server, (struct sockaddr*)&addr, &len);  /* accept connection as usual */
        printf("Connection: %s:%d\n",inet_ntoa(addr.sin_addr), ntohs(addr.sin_port));
        ssl = SSL_new(ctx);              /* get new SSL state with context */
        SSL_set_fd(ssl, client);      /* set connection socket to SSL state */
        Servlet(ssl);         /* service connection */
    }
    close(server);          /* close server socket */
    SSL_CTX_free(ctx);         /* release context */
}


int  old_main() {
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


