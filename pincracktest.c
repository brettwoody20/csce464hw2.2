#include "pincrack.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>


int main(int argc, char *argv[]) {
    
    int pin = 0;

    if(argc != 2) {
     printf("Usage: pincracktest <SHA-1 hash of 4 digit PIN>\n");
     exit(-1);
    }

    pin = pincrack(argv[1], strlen(argv[1]));
     
    // if (pin != -1)
    //     printf("PIN found: %d\n", pin);
    // else
    //     printf("PIN could not be found\n");

}
