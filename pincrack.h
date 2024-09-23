
/* This function takes as arguments a SHA-1 hash and the length of it.
This function returns a 4 digit PIN code that has a SHA-1 hash equal to that provided
This function returns -1 if no 4 digit PIN code is found.
*/
 
int pincrack(char *hash, int hashLength);

