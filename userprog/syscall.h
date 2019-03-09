#ifndef USERPROG_SYSCALL_H
#define USERPROG_SYSCALL_H

#include "threads/synch.h"

#define CLOSE_ALL -1
#define ERROR -1

	//assigns load status from an integer
#define NOT_LOADED 0
#define LOAD_SUCCESS 1
#define LOAD_FAIL 2


	//structure for a child process
struct child_process {
  int pid;	//parent ID
  int load;
  bool wait;
  bool exit;
  int status;
  struct lock wait_lock;
  struct list_elem elem;
};

	//function to add a child process
struct child_process* add_child_process (int pid);
	//function to retrieve child process
struct child_process* get_child_process (int pid);
	//remove child process and return it
void remove_child_process (struct child_process *cp);
	//completely remove child process
void remove_child_processes (void);

void process_close_file (int fd);

void syscall_init (void);

#endif /* userprog/syscall.h */