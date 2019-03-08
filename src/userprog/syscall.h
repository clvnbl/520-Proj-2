#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);




/*new code*/
#include "threads/synch.h"


/*new code*/
#define LOAD_FAIL 2
#define LOAD_SUCCESS 1
#define ERROR -1
#define CLOSE_ALL -1
#define NOT_LOADED 0




struct child_process {
	int pid;
	int load;
	bool wait;
	bool exit;
	int status;
	struct lock wait_lock;
	struct list_elem elem;
};

struct child_process* get_child_process (int pid);
void remove_child_process (struct child_process *cp);
void remove_child_processes (void);
void process_close_file (int fd);
struct child_process* add_child_process (int pid);
void syscall_init (void);




#endif /* userprog/syscall.h */
