#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#include "md5.h"

//provided string lengths
const int PASS_LEN = 20;        // Maximum any password will be
const int HASH_LEN = 33;        // Length of MD5 hash strings

//provided function outline
// Given a target plaintext word, use it to try to find
// a matching hash in the hashFile.
char * tryWord(char * plaintext, char * hashFilename)
{
    //store hash of provided plaintext password
    char *password = md5(plaintext, strlen(plaintext));

    // Open the hash file
    FILE *hashFile = fopen(hashFilename, "r");
    if(!hashFile) 
    {
        printf("Unable to open file %s!\n", hashFilename);
        exit(1);
    }

    //init var to store hash value from file
    char hash[HASH_LEN];

    // Loop through the hash file, one line at a time.
    while(fgets(hash, HASH_LEN, hashFile))
    {
        //trim newline if needed
        if(hash[strlen(hash) - 1] == '\n') hash[strlen(hash) - 1] = '\0';

        //compare password hash to hash list
        //if match, return hash
        if(!strcmp(hash, password))
        {
            //free memory and close file
            free(password);
            fclose(hashFile);

            return hash;
        }
    }

    //free memory and close file
    free(password);
    fclose(hashFile);

    //return NULL if no match found
    return NULL;
}

//main function
//takes 2 arguments from the command line
int main(int argc, char *argv[])
{   
    //if too few arguments, exit
    if (argc < 3) 
    {
        fprintf(stderr, "Usage: %s hash_file dict_file\n", argv[0]);
        exit(1);
    }

    //open dictionary file
    FILE *dict = fopen(argv[2], "r");
    //check that it opened correctly
    if(!dict)
    {
        printf("Unable to open file %s!\n", argv[2]); //if not, error and exit
        exit(1);
    }

    //init string to hold dictionary words
    char dictWord[PASS_LEN];
    //init var to hold number of successful matches
    int hacked = 0;

    //for the length of the dictionary file
    while(fgets(dictWord, PASS_LEN, dict))
    {  
        //trim newline if needed
        if(dictWord[strlen(dictWord) - 1] == '\n') dictWord[strlen(dictWord) - 1] = '\0';
        
        //store result of tryWord
        char *match = tryWord(dictWord, argv[1]);
        
        //if tryWord returned non-NULL value
        //print the hash and matching dictionary word
        //increment hacked
        if(match)
        {
            printf("%s %s\n", match, dictWord); 
            hacked++;
        }
    }

    //close file 
    fclose(dict);

    //print total number of successful matches
    printf("%d hashes were cracked.\n", hacked);
}

