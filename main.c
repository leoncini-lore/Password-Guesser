#include <stdio.h>
#include <crypt.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <time.h>
#include <pthread.h>
#include <stdatomic.h>

int NUM_THREADS;

int NUM_THREADS;
atomic_int stop_flag;

typedef struct {
    char * username; 
    char * pwdandsalt;
    char * hashedpasswd;
    const char * fullsalt;
} user_struct;

typedef struct {
    int thread_id;
    const char *dictionary_file;
} thread_args;

user_struct user_instance;

// Macros for checking password match
#define CHECK_PASSWORD_MATCH(pwdandsalt, hashedword, username, word, fptrd) \
    if (!strcmp(pwdandsalt, hashedword)) { \
        printf("Thread %d -> La password di %s è: %s\n \n", thread_id, username, word); \
        atomic_store(&stop_flag, 1); \
        if (fptrd != NULL) { \
            fclose(fptrd); \
            fptrd = NULL; \
        } \
        return NULL; \
    } \

// Macro for checking if the stop flag is set
#define CHECK_DONE \
    if (atomic_load(&stop_flag)) { \
        fclose(fptrd); \
        return NULL; \
    } \

char * gettoken(char * str, char * delim, int pos) {
  char * strtmp = strdup(str);
  char *ch = strtok(strtmp, delim);
  while (ch != NULL && pos>1) {
    ch = strtok(NULL, delim);
    pos--;
  }
  return ch;
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
    int quotient = 100 / NUM_THREADS;
    int remainder = 100 % NUM_THREADS;
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

// Function to be executed by each thread
void* password_guess(void* arg) {
    thread_args *args = (thread_args*)arg;
    int thread_id = args->thread_id;
    const char *dictionary_file = args->dictionary_file;

    struct crypt_data cdata;
    cdata.initialized = 0;

    FILE *fptrd = fopen(dictionary_file, "r");
    if (fptrd == NULL) {
        perror("Error opening dictionary file");
        return NULL;
    }

    char *word = NULL;
    size_t wlen = 0;
    size_t wread;
    while ((wread = getline(&word, &wlen, fptrd)) != -1) {
        if (wread == -1) {
            perror("getline");
            break;
        }

        // Process the word (existing logic)
        char *newline = strrchr(word, '\n');
        if (newline) *newline = '\0';

        char *word_capitalized = capitalize(word);
        char *inputs[4] = {word, with_number(word), word_capitalized, with_number(word_capitalized)};
        size_t len = strlen(word);
        char (*array)[len + 3] = malloc(4 * (len + 3));

        for (int i = 0; i < 4; i++) {
            strcpy(array[i], inputs[i]);
        }

        char *hashedword;
        if (NUM_THREADS > 3) {
            if (thread_id < 4) {
                hashedword = guess(array[thread_id], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[thread_id], fptrd);
            }
        } else if (NUM_THREADS > 1) {
            if (thread_id == 0) {
                hashedword = guess(array[thread_id], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[thread_id], fptrd);
                hashedword = guess(array[thread_id + 1], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[thread_id + 1], fptrd);
            } else if (thread_id == 1) {
                hashedword = guess(array[thread_id + 1], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[thread_id + 1], fptrd);
                hashedword = guess(array[thread_id + 2], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[thread_id + 2], fptrd);
            }
        } else {
            for (int x = 0; x < 4; x++) {
                hashedword = guess(array[x], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[x], fptrd);
            }
        }
        CHECK_DONE;

        for (int x = 0; x < 4; x++) {
            array[x][len + 2] = '\0';
        }

        int startI, endI;
        get_interval(&startI, &endI, thread_id);
        for (int i = startI; i < endI; i++) {
            for (int x = 0; x < 4; x++) {
                array[x][len] = (i / 10) + '0';
                array[x][len + 1] = (i % 10) + '0';
                hashedword = guess(array[x], user_instance.fullsalt, &cdata);
                CHECK_PASSWORD_MATCH(user_instance.pwdandsalt, hashedword, user_instance.username, array[x], fptrd);
                CHECK_DONE;
            }
        }
        free(array);
    }

    fclose(fptrd);
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

    pthread_t threads[NUM_THREADS];
    thread_args args[NUM_THREADS];

    FILE *fptrs = fopen(shadow_file, "r");
    if (fptrs == NULL) {
        perror("Error opening shadow file");
        return 1;
    }

    char *user = NULL;
    size_t len = 0;
    size_t read;
    time_t start, end;
    start = time(NULL);

    while ((read = getline(&user, &len, fptrs)) != -1) {
        if (strchr(user, '*') != NULL) {
            //printf("The user string contains an asterisk (*): %s\n", user);
            continue;
        }
        char *method = gettoken(user, "$", 2);
        switch (method[0]) {
        case '1':
            printf("Method: MD5\n");
            break;
        case '5':
            printf("Method: SHA-256\n");
            break;
        case '6':
            printf("Method: SHA-512\n");
            break;
        case 'y':
            printf("Method: Yescript\n");
            break;
        default:
            break;
        }
        char *username = gettoken(user, ":", 1);
        char *pwdandsalt = gettoken(user, ":", 2);
        char *hashedpasswd = gettoken(pwdandsalt, "$", 4);
        const char *fullsalt = strdup(pwdandsalt);
        char *last_occurrence = strrchr(fullsalt, '$');
        if (!last_occurrence) return 1;
        *last_occurrence = '\0';

        user_instance.username = username;
        user_instance.pwdandsalt = pwdandsalt;
        user_instance.hashedpasswd = hashedpasswd;
        user_instance.fullsalt = fullsalt;
        stop_flag = 0;

        for (int i = 0; i < NUM_THREADS; i++) {
            args[i].thread_id = i;
            args[i].dictionary_file = dictionary_file;
            pthread_create(&threads[i], NULL, password_guess, &args[i]);
        }

        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        if (!stop_flag) {
            printf("Password not found for %s\n", username);
        }
    }

    end = time(NULL);
    printf("Elapsed time: %.2f seconds\n", difftime(end, start));

    fclose(fptrs);
    free(user);
    return 0;
}
