#include <stdio.h>
#include <stdlib.h>
#include <openssl/sha.h>

typedef unsigned char byte;

int main(int argc, char *argv[]) {

   //get and check arguement
    SHA_CTX shactx;
    byte digest[SHA_DIGEST_LENGTH];
    int i;

    if(argc != 2) {
        printf("Usage: sha1test <up to 4 character string>\n");
        exit(-1);
    }
   
   //initialize some sha1 thing
    SHA1_Init(&shactx);
    int pin  = atoi(argv[1]);
    printf("PIN is %d\n", pin);

   //cal SHA1_update based on number of digits in pin
   if(pin >= 0 && pin < 10) {
       SHA1_Update(&shactx, argv[1], 1);
    } else if(pin >=10 && pin < 100) {
       SHA1_Update(&shactx, argv[1], 2);
    } else if(pin >=100 && pin < 1000) {
       SHA1_Update(&shactx, argv[1], 3);
    } else if(pin >=1000 && pin < 10000) {
       SHA1_Update(&shactx, argv[1], 4);
    } else { 
       printf("PIN out of range\n");
       exit(0);
    }

    SHA1_Final(digest, &shactx);

    for (i=0; i<SHA_DIGEST_LENGTH; i++)
	printf("%02x", digest[i]);
    putchar('\n');

    return 0;
}


