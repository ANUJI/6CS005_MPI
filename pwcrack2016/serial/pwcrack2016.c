//pwcrack2016
//accesing linux extention functions
#define _GNU_SOURCE
#include <assert.h>
#include <crypt.h>
#include <math.h>
#include <malloc.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/* A salt is a two character string which adds some randomness to passwords. */
const char* SALT = "$6$HP$";

/* The characters which are allowed to be used in passwords. */
const char* ALPHABET = "_.abcdefghijklmnopqrstuvwxyz";

/* How many characters are valid in the password? */
const int ALPHABET_SIZE = 28;

/* Number of characters in an encrypted password. */
const int ENCRYPTED_SIZE = 94;
//define an error message
#define ERROR -1
//function for decrypt password
void decrypt_password(int, char*, char**);

//decrypting the password
void decrypt_password(const int password_length, char* password, char** plain) {
  //Looking for possible password combinations
    int possibilties = pow(ALPHABET_SIZE, password_length);
    //Looking for candidate passwords
    char candidates[possibilties][password_length + 1];
    long i = 0, val = 0;
    int j = 0;
    char letter = '_';
    //Allocating memory for password combinations
    char* word = malloc(password_length + 1);
    //checking encription has a null characters
    char *encrypted = NULL;
    //checking the encrypted password is matches with ALPHABETS
    for (i = 0; i < possibilties; i++) {
        val = i;
        for (j = 0; j < password_length; j++) {
            letter = ALPHABET[val % ALPHABET_SIZE];
            word[j] = letter;
            val = val / ALPHABET_SIZE;
        }
        strcpy(candidates[i], word);
    }
    //checking Plaintext matches as possible chandidates
     for (i = 0; i < possibilties; i++) {
         encrypted = crypt(candidates[i], SALT);
         if (strcmp(encrypted, password) == 0) {
             strcpy(*plain, candidates[i]);
             break;
         }
     }
     //freeing the memory
    free(word);

    return;
}
//argv and argc command line arguments are passed to main()
int main(int argc, char **argv) {
  //checking for argc is smaller than 3
    if (argc < 3) {
      //if the condition is false, printing the error Message
        fprintf(stderr, "Usage: pwcrack n ciphertext\nn should be the number of characters in the password.\nRemember to escape $ characters in your shell\n");
        return ERROR;
    }
    //convert argv array to int
    int password_length = atoi(argv[1]);
    //exit if password length is negative
    assert(password_length > 0);
    char *password = argv[2];
    //Allocating memory
    char* plain = malloc(sizeof(char) * (password_length + 1));
    //checking the decryption password matches
    decrypt_password(password_length, password, &plain);
    if (plain) {
      //if the plain text matches, print the Message
        printf("%s decrypts to: %s\n", password, plain);
    }
    //freeing allocated memory
    free(plain);
    //Exiting from the program
    return 0;
}
