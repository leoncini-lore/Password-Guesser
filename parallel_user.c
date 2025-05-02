// Description: This program is a parallel password cracker that uses multiple threads to guess passwords from a shadow file using a dictionary. It utilizes the crypt library for hashing and compares the hashed passwords with the stored hashes in the shadow file.
#include <stdio.h>
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>

int NUM_THREADS;

int NUM_THREADS;

char** dictionary;
size_t dictionary_size = 0;

char** shadow_array;
size_t shadow_size = 0;


typedef struct {
    int thread_id;
} thread_args;


// Macros for checking password match
#define CHECK_PASSWORD_MATCH(pwdandsalt, hashedword, username, word, fptrd) \
    if (!strcmp(pwdandsalt, hashedword)) { \
        printf("Thread %d -> La password di %s è: %s\n", thread_id, username, word); \
        stop_flag = true; \
    } \

//modificata
char * gettoken(char * str, char * delim, int pos) {
    char *strtmp = strdup(str);
    char *ch = strtok(strtmp, delim);
    while (ch != NULL && pos > 1) {
        ch = strtok(NULL, delim);
        pos--;
    }
    char *result = ch ? strdup(ch) : NULL;
    free(strtmp);
    return result;
}


// Function to replace letters with numbers
char * with_number (char * word) {
    char * str = strdup(word);
    char * start = str;
    while (*str) {
        switch (*str){
           case 'o':
              *str = '0';
              break;
           case 'i':
              *str = '1';
              break;
           case 'e':
              *str = '3';
              break;
           case 's':
              *str = '5';
              break;              
        }
        str++;
    }
    return start;
}

// Function to capitalize the first letter of a word
char * capitalize (char * word) {
   char * str = strdup(word);
   if (*str >= 'a' && *str <= 'z') {
      *str -= ('a'-'A');
   }
   return str;
}

// Function to get the interval for each thread
void get_interval(int* start, int* stop, int id) {
    // First compute quotient and remainder of 100/NUM_THREADS
    int quotient = shadow_size / NUM_THREADS;
    int remainder = shadow_size % NUM_THREADS;
    // Compute start and stop for this thread
    *start = id * quotient + (id < remainder ? id : remainder);
    *stop = *start + quotient + (id < remainder ? 1 : 0);
    //printf("Thread %d: start = %d, stop = %d\n", id, *start, *stop);     
}

// Function to guess the password
char * guess(const char * password, const char * salt, struct crypt_data *cdata) {
    char *hashed = crypt_r(password, salt, cdata);
    if (hashed == NULL) {
        perror("crypt");
        return "Error";
    }
    return hashed;
}


char **load_dictionary(const char *file_name, size_t *word_count) {
    FILE *fptrd = fopen(file_name, "r");
    if (fptrd == NULL) {
        perror("Error opening dictionary file");
        return NULL;
    }

    char **file = NULL;
    char *word = NULL;
    size_t len = 0;
    size_t count = 0;

    while (getline(&word, &len, fptrd) != -1) {
        char *newline = strrchr(word, '\n');
        if (newline) *newline = '\0'; // Remove newline character

        file = realloc(file, (count + 1) * sizeof(char *));
        if (!file) {
            perror("Memory allocation failed");
            fclose(fptrd);
            free(word);
            return NULL;
        }

        file[count] = strdup(word); // Allocate memory for the word
        if (!file[count]) {
            perror("Memory allocation failed");
            fclose(fptrd);
            free(word);
            return NULL;
        }

        count++;
    }

    free(word);
    fclose(fptrd);

    *word_count = count;
    return file;
}

char **load_shadow(const char *file_name, size_t *word_count) {
    FILE *fptrd = fopen(file_name, "r");
    if (fptrd == NULL) {
        perror("Error opening dictionary file");
        return NULL;
    }

    char **file = NULL;
    char *word = NULL;
    size_t len = 0;
    size_t count = 0;

    while (getline(&word, &len, fptrd) != -1) {
        char *newline = strrchr(word, '\n');
        if (newline) *newline = '\0'; // Remove newline character
        char *method = gettoken(word, "$", 2);
        if (method == NULL || !(*method == '1' || *method == '5' || *method == '6' || *method == 'y')) {
            continue;
        }
        file = realloc(file, (count + 1) * sizeof(char *));
        if (!file) {
            perror("Memory allocation failed");
            fclose(fptrd);
            free(word);
            return NULL;
        }

        file[count] = strdup(word); // Allocate memory for the word
        if (!file[count]) {
            perror("Memory allocation failed");
            fclose(fptrd);
            free(word);
            return NULL;
        }

        count++;
    }

    free(word);
    fclose(fptrd);

    *word_count = count;
    return file;
}
// Function to be executed by each thread
void* password_guess(void* arg) {
    thread_args *args = (thread_args*)arg;
    int thread_id = args->thread_id;

    struct crypt_data cdata;
    cdata.initialized = 0;

    char (*array)[100] = malloc(4 * (100));
    if (!array) {
        perror("Memory allocation failed");
        return NULL;
    }
    int startI, endI;
    get_interval(&startI, &endI, thread_id);
    for (int i = startI; i < endI; i++) {
        bool stop_flag = false;
        char* user = shadow_array[i];
        char *method = gettoken(user, "$", 2);
        char *username = gettoken(user, ":", 1);
        char *pwdandsalt = gettoken(user, ":", 2);
        char *hashedpasswd = gettoken(pwdandsalt, "$", 4);
        const char *fullsalt = strdup(pwdandsalt);
        char *last_occurrence = strrchr(fullsalt, '$');
        if (!last_occurrence) return NULL;
        *last_occurrence = '\0';

        for (size_t w = 0; !stop_flag && w < dictionary_size; w++) {
            char *word = dictionary[w];

            char *word_capitalized = capitalize(word);
            char *inputs[4] = {word, with_number(word), word_capitalized, with_number(word_capitalized)};
            size_t len = strlen(word);

            for (int i = 0; i < 4; i++) {
                strcpy(array[i], inputs[i]);
            }

            free(word_capitalized);
            free(inputs[1]);
            free(inputs[3]);

            char *hashedword;
            
            for (int x = 0; !stop_flag && x < 4 ; x++) {
                hashedword = guess(array[x], fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(pwdandsalt, hashedword, username, array[x], NULL);
            }
            

            for (int x = 0; !stop_flag && x < 4; x++) {
                array[x][len + 2] = '\0';
            }

            for (int i = 0;!stop_flag && i < 100; i++) {
                for (int x = 0; x < 4; x++) {
                    array[x][len] = (i / 10) + '0';
                    array[x][len + 1] = (i % 10) + '0';
                    hashedword = guess(array[x], fullsalt, &cdata);
                    CHECK_PASSWORD_MATCH(pwdandsalt, hashedword, username, array[x], NULL);
                }
            }
        }
        if (!stop_flag) {
            printf("Password non trovata per %s\n", username);
        }
        free(method);
        free(username);
        free(pwdandsalt);
        free(hashedpasswd);
        free(fullsalt);
    }

    free(array);
    return NULL;
}


int main(int argc, char *argv[]) {
    if (argc < 4) {
        fprintf(stderr, "Usage: %s <shadow_file> <dictionary_file> <num_threads>\n", argv[0]);
        return 1;
    }

    const char *shadow_file = argv[1];
    const char *dictionary_file = argv[2];
    NUM_THREADS = atoi(argv[3]); // Convert the number of threads to an integer

    if (NUM_THREADS <= 0) {
        fprintf(stderr, "Error: Number of threads must be greater than 0.\n");
        return 1;
    }
    
    // Load the dictionary into memory
    dictionary = load_dictionary(dictionary_file, &dictionary_size);
    if (!dictionary) {
        return 1;
    }
    
    // Load the shadow file into memory
    shadow_array = load_shadow(shadow_file, &shadow_size);
    if (!shadow_array) {
        return 1;
    }
    pthread_t threads[NUM_THREADS];
    thread_args args[NUM_THREADS];

    struct timespec start, end;
    #ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &start);
    #endif
    printf("Starting password cracking with %d threads...\n", NUM_THREADS);
    for (int i = 0; i < NUM_THREADS; i++) {
        args[i].thread_id = i;
        pthread_create(&threads[i], NULL, password_guess, &args[i]);
    }

    for (int i = 0; i < NUM_THREADS; i++) {
        pthread_join(threads[i], NULL);
    }

    #ifdef CLOCK_MONOTONIC
    clock_gettime(CLOCK_MONOTONIC, &end);
    #endif
    
    double elapsed_time = (end.tv_sec - start.tv_sec) + (end.tv_nsec - start.tv_nsec) / 1e9;
    printf("Elapsed time: %.6f seconds\n", elapsed_time);

    
    // Free the dictionary
    for (size_t i = 0; i < dictionary_size; i++) {
        free(dictionary[i]);
    }
    free(dictionary);

    // Free the shadow array
    for (size_t i = 0; i < shadow_size; i++) {
        free(shadow_array[i]);
    }
    free(shadow_array);

    return 0;
}