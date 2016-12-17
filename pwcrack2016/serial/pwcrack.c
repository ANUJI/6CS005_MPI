//Accesing linux extension functions
#define _GNU_SOURCE
//adding library files
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
//define error message
#define ERROR -1
//funtion for decrypt password
void decrypt_password(int, char*, char**);
//read the file line by line
void read_line_in_file(FILE*, char**);

//read the file line by line till end of the characters
void read_line_in_file(FILE* fp, char** line) {
    size_t len = 0;
    ssize_t read = 0;
//reading the file
    if ((read = getline(line, &len, fp)) != -1) {
        if ((*line)[read - 1] == '\n') {
            (*line)[read - 1] = '\0';
            --read;
        }
    }
}

//decrypt the password
void decrypt_password(const int password_length, char* password, char** plain) {
  //Looking for combinations
    int possibilties = pow(ALPHABET_SIZE, password_length);
    //Looking for candidate passwords
    char candidates[possibilties][password_length + 1];
    long i = 0, val = 0;
    int j = 0;
    char letter = '_';
    //Allocating memory for password combinations
    char* word = malloc(password_length + 1);
    //checking for null characters
    char *encrypted = NULL;
    //checking the possibilities of the encrypted password matches with ALPHABETS
    for (i = 0; i < possibilties; i++) {
        val = i;
        for (j = 0; j < password_length; j++) {
            letter = ALPHABET[val % ALPHABET_SIZE];
            word[j] = letter;
            val = val / ALPHABET_SIZE;
        }
        strcpy(candidates[i], word);
    }
    //checking if Plaintext matches as possible chandidates
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
//argv and argc,command line arguments are passed to main()
int main(int argc, char **argv) {
    if (argc < 3) {
        fprintf(stderr, "Usage: pwcrack n filename\nn should be the number of characters in the password.\n");
        return ERROR;
    }
    int password_length = atoi(argv[1]);
    assert(password_length > 0);
    char *filename = argv[2];
    char *line = malloc(password_length + 1);
    FILE* fp = NULL;
    char* plain = malloc(sizeof(char) * (password_length + 1));

    fp = fopen(filename, "rb");
    if (fp == NULL) {
        fprintf(stderr, "Could not find file: %s.\n", filename);
        return ERROR;
    }

    do {
        read_line_in_file(fp, &line);
        decrypt_password(password_length, line, &plain);
        if (plain) {
            printf("%s decrypts to: %s\n", line, plain);
        }
    } while (*line != '\0');

    (void)fclose(fp);

    free(line);
    free(plain);

    return 0;
}
