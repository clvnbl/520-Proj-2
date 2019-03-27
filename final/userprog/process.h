#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"


/*new code
#define LOAD_FAIL 2
#define LOAD_SUCCESS 1
#define ERROR -1
#define CLOSE_ALL -1
#define NOT_LOADED 0 */






tid_t process_execute (const char *file_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (void);

#endif /* userprog/process.h */
