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

#define ERROR -1

void decrypt_password(int, char*, char**);


void decrypt_password(const int password_length, char* password, char** plain) {
    int possibilties = pow(ALPHABET_SIZE, password_length);
    char candidates[possibilties][password_length + 1];
    long i = 0, val = 0;
    int j = 0;
    char letter = '_';
    char* word = malloc(password_length + 1);
    char *encrypted = NULL;

    for (i = 0; i < possibilties; i++) {
        val = i;
        for (j = 0; j < password_length; j++) {
            letter = ALPHABET[val % ALPHABET_SIZE];
            word[j] = letter;
            val = val / ALPHABET_SIZE;
        }
        strcpy(candidates[i], word);
    }

     for (i = 0; i < possibilties; i++) {
         encrypted = crypt(candidates[i], SALT);
         if (strcmp(encrypted, password) == 0) {
             strcpy(*plain, candidates[i]);
             break;
         }
     }

    free(word);

    return;
}

int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: pwcrack n ciphertext\nn should be the number of characters in the password.\nRemember to escape $ characters in your shell\n");
        return ERROR;
    }
    int password_length = atoi(argv[1]);
    assert(password_length > 0);
    char *password = argv[2];
    char* plain = malloc(sizeof(char) * (password_length + 1));

    decrypt_password(password_length, password, &plain);
    if (plain) {
        printf("%s decrypts to: %s\n", password, plain);
    }

    free(plain);

    return 0;
}
