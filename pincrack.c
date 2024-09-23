#include <sys/select.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>    
#include <netinet/in.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <netdb.h>   // gethostbyname()
#include <errno.h>
#include <malloc.h>
#include <string.h>
#include <resolv.h>
#include <openssl/ssl.h>
#include <openssl/err.h>

#define SERVER_PORT     3005
#define BUFFER_LENGTH    250
#define FALSE              0
#define SERVER_NAME "localhost"
#define NETDB_MAX_HOST_NAME_LENGTH 20
#define FAIL -1

//helper functions
void LoadCertificates(SSL_CTX* ctx, char* CertFile, char* KeyFile);
int OpenConnection(const char *hostname, int port);
void ShowCerts(SSL* ssl);
SSL_CTX* InitCTX(void);


int pincrack(char *hash, int hashLength) {
    char hostname[NETDB_MAX_HOST_NAME_LENGTH];
    char buf[BUFFER_LENGTH];
    SSL_CTX *ctx;
    SSL *ssl;
    int server;
    int bytes;

    // Init. the SSL lib
    SSL_library_init();
    ctx = InitCTX();

    printf("Client SSL lib init complete\n");

    // Open the connection as normal
    strcpy(hostname, SERVER_NAME);
    server = OpenConnection(hostname, SERVER_PORT);

    // Create new SSL connection state
    ssl = SSL_new(ctx);


    // Attach the socket descriptor
    SSL_set_fd(ssl, server);

    // Perform the connection
    if ( SSL_connect(ssl) != FAIL ) {

        printf("Connected with %s encryption\n", SSL_get_cipher(ssl));

        // Print any certs
        ShowCerts(ssl);


        // Encrypt & send message */
        SSL_write(ssl, hash, hashLength);


        // Get reply & decrypt
        bytes = SSL_read(ssl, buf, sizeof(buf));


        buf[bytes] = 0;
        printf("\nReceived: %s\n\n", buf);


        // Release connection state
        SSL_free(ssl);


    } // if

    else ERR_print_errors_fp(stderr);


    // Close socket
    close(server);


    // Release context
    SSL_CTX_free(ctx);
    return 0;
}

int pincrack_old(char *hash, int hashLength) {

/* Here you will implement all logic: 
socket creation, communication with the server and returning 
the value to the caller of this function. 
*/
    int sd= -1, rc, bytesrReceived;
    char buffer[BUFFER_LENGTH];
    char server[NETDB_MAX_HOST_NAME_LENGTH];
    struct sockaddr_in serveraddr;
    struct hostent *hostp;

    
    //Create socket
    sd = socket(AF_INET, SOCK_STREAM, 0);
    if (sd < 0) {
        perror("Socket creation failed");
        return -1;
    }

    strcpy(server, SERVER_NAME);

    memset(&serveraddr, 0, sizeof(serveraddr));
    serveraddr.sin_family  = AF_INET;
    serveraddr.sin_port    = htons(SERVER_PORT);
    serveraddr.sin_addr.s_addr = inet_addr(server);

    if (serveraddr.sin_addr.s_addr == (unsigned long)INADDR_NONE) {
        hostp = gethostbyname(server);
        if (hostp == (struct hostent *)NULL) {
            perror("Host not found -->");
            close(sd);
            return -1;
        }
        memcpy(&serveraddr.sin_addr, hostp->h_addr, sizeof(serveraddr.sin_addr));
    }

    //connect to server
    rc = connect(sd, (struct sockaddr *)&serveraddr, sizeof(serveraddr));
    if (rc < 0) {
        perror("Error: Connection failed");
        close(sd);
        return -1;
    }

    //send message to server
    memset(buffer, 0, sizeof(buffer));
    strcpy(buffer, hash);
    rc = send(sd, buffer, sizeof(buffer), 0);
    if (rc < 0) {
        perror("Send failed");
        close(sd);
        return -1;
    }

    memset(buffer, 0, sizeof(buffer));
    rc = recv(sd, buffer, sizeof(buffer) - 1, 0);  // -1 to leave space for null-terminator
    if (rc < 0) {
        perror("Receive failed");
        close(sd);
        return -1;
    }

    printf("%s", buffer);
    

    shutdown(sd, SHUT_RDWR);



    return -1; //if failed
}

SSL_CTX* InitCTX(void) {


    SSL_METHOD const *method;
    SSL_CTX *ctx;


    // Load cryptos, et.al.
    OpenSSL_add_all_algorithms();


    // Bring in and register error messages
    SSL_load_error_strings();


    // Create new client-method instance
    method = SSLv23_client_method();


    // Create new context
    ctx = SSL_CTX_new(method);


    if ( ctx == NULL ) {


        ERR_print_errors_fp(stderr);
        abort();


    } // if


    return ctx;


} //InitCTX


int OpenConnection(const char *hostname, int port) {


    int sd;
    struct hostent *host;
    struct sockaddr_in addr;


    if ( (host = gethostbyname(hostname)) == NULL ) {


        perror(hostname);
        abort();


    } // if


    sd = socket(PF_INET, SOCK_STREAM, 0);
    bzero(&addr, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    addr.sin_addr.s_addr = *(long*)(host->h_addr);


    if ( connect(sd, (struct sockaddr*)&addr, sizeof(addr)) != 0 ) {


        close(sd);
        perror(hostname);
        abort();


    } // if


    return sd;


} // OpenConnection


void ShowCerts(SSL* ssl) {


    X509 *cert;
    char *line;


    cert = SSL_get_peer_certificate(ssl); /* get the server's certificate */


    if ( cert != NULL ) {


        printf("\nServer certificate:\n");
        line = X509_NAME_oneline(X509_get_subject_name(cert), 0, 0);
        printf("Subject: %s\n", line);


        // Free the malloc'ed string
        free(line);
        line = X509_NAME_oneline(X509_get_issuer_name(cert), 0, 0);
        printf("Issuer: %s\n", line);


        // Free the malloc'ed string
        free(line);


        // Free the malloc'ed certificate copy
        X509_free(cert);


    } // if


    else printf("No certificates.\n");


} // ShowCerts
