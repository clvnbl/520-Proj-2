#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

void syscall_init (void);




/*new code*/
//needing the locks from synch.h
#include "threads/synch.h"


/*new code*/
//defining constants used in syscall.c and process.c
#define LOAD_FAIL 2
#define LOAD_SUCCESS 1
#define ERROR -1




//creating a lock for the file system
struct lock filesys_lock;

//creating a struct for processing files. 
struct process_file {
	
	//holds the file
    struct file *file;
    
	//holds the file descriptor
	int fd;
	
	//holds a list of elements
    struct list_elem elem;
};

//creating a struct for the child process
struct child_process {
	
	//holds the process id of the process
	int pid;
	
	//holds if was able to load or not.
	int load;
	
	//bool for for if the process is waiting or not
	bool wait;
	
	//bool if the process is ready to exit
	bool exit;
	
	//holds the status of the process
	int status;
	
	//holds a lock for if the thread is waiting on a lock
	struct lock wait_lock;
	
	//holds a list of elements
	struct list_elem elem;
};

struct child_process* get_child_process (int pid);
void remove_child_process (struct child_process *cp);
void remove_child_processes (void);
void process_close_file (int fd);
struct child_process* initilize_child_process (int pid);
void syscall_init (void);




#endif /* userprog/syscall.h */
