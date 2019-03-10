/*
 * All modified code was inspired from ryantimwilson's git repo, which can be found here:
 * https://github.com/ryantimwilson/Pintos-Project-2/blob/master/src/userprog/syscall.c
 *
 */


#include "userprog/syscall.h"
#include <stdio.h>
#include <syscall-nr.h>
#include <user/syscall.h>
#include "devices/input.h"
#include "devices/shutdown.h"
#include "filesys/file.h"
#include "filesys/filesys.h"
#include "threads/interrupt.h"
#include "threads/malloc.h"
#include "threads/synch.h"
#include "threads/thread.h"
#include "threads/vaddr.h"
#include "userprog/pagedir.h"
#include "userprog/process.h"

//defining constants 
#define CLOSE_ALL -1
#define NOT_LOADED 0

int process_add_file (struct file *f);
struct file* process_get_file (int fd);

static void syscall_handler (struct intr_frame *);
int user_to_kernel_ptr(const void *vaddr);
void get_arguments (struct intr_frame *f, int *arg, int n);
void check_valid_ptr (const void *vaddr);
void check_valid_buffer (void* buffer, unsigned size);

void
syscall_init (void) 
{
	
	
	/*new code*/
	//locks the filesystem so that nothing else can touch it until the procee is done
	lock_init(&filesys_lock);
	
	
	
	
  intr_register_int (0x30, 3, INTR_ON, syscall_handler, "syscall");
}

static void
syscall_handler (struct intr_frame *f UNUSED) 
{
	/*the function is all new code*/
	
	
	//checks to see if the pointer is valid. If not, error out
	check_valid_ptr((const void*) f->esp);
	
	//int array that holds arguments that comes from the stack.
	int arguments[3];
	
	//switch case for the user program functions
	switch (* (int *) f->esp)
	{
		//case to halt the system
		case SYS_HALT:
		{
			//calls the halt function
			halt();
			break;
		}
		//case to exit the system
		case SYS_EXIT:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//calls exit on the first argument on the stack
			exit(arguments[0]);
			break;
		}
		// case to wait for the child process 
		case SYS_WAIT:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//sets the frame eax to wait
			f->eax = wait(arguments[0]);
			break;
		}
		//case to execute commands from the console
		case SYS_EXEC:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//sets location 0 of the arguments array to the pointer of the stack
			arguments[0] = user_to_kernel_ptr((const void *) arguments[0]);
			
			//sets the eax of the frame to the pid
			f->eax = exec((const char *) arguments[0]);
			break;
		}
		//case to create a new file
		case SYS_CREATE:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 2
			get_arguments(f, &arguments[0], 2);
			
			//sets location 0 of the arguments array to the pointer of the stack
			arguments[0] = user_to_kernel_ptr((const void *) arguments[0]);
			
			//sets the eax of the frame to a true or false depending on if the file was created or not
			f->eax = create((const char *)arguments[0], (unsigned) arguments[1]);
			break;
		}
		//case to remove a file
		case SYS_REMOVE:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//sets location 0 of the arguments array to the pointer of the stack
			arguments[0] = user_to_kernel_ptr((const void *) arguments[0]);
			
			//sets the eax of the frame to true or false depending on if the file could be removed
			f->eax = remove((const char *) arguments[0]);
			break;
		}
		//case to open a file
		case SYS_OPEN:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//sets location 0 of the arguments array to the pointer of the stack
			arguments[0] = user_to_kernel_ptr((const void *) arguments[0]);
			
			//sets the eax of the frame to positive file descriptor, or -1 if the operation failed
			f->eax = open((const char *) arguments[0]);
			break;
		}
		//case to get the size of a file
		case SYS_FILESIZE:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//sets the eax of the frame to size of the file
			f->eax = filesize(arguments[0]);
			break;
		}
		//case to read a file
		case SYS_READ:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 3
			get_arguments(f, &arguments[0], 3);
			
			//makes sure that the buffer is valid
			check_valid_buffer((void *) arguments[1], (unsigned) arguments[2]);
			
			//sets location 1 to the pointer of the stack
			arguments[1] = user_to_kernel_ptr((const void *) arguments[1]);
			
			//sets the eax to the number of bytes read that were able to be read
			f->eax = read(arguments[0], (void *) arguments[1], (unsigned) arguments[2]);
			break;
		}
		//call to write to an open file
		case SYS_WRITE:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 2
			get_arguments(f, &arguments[0], 3);
			
			//makes sure that the buffer is valid
			check_valid_buffer((void *) arguments[1], (unsigned) arguments[2]);
			
			//sets location 1 to the pointer of the stack
			arguments[1] = user_to_kernel_ptr((const void *) arguments[1]);
			
			//set eax to the number of bytes that were able to be written
			f->eax = write(arguments[0], (const void *) arguments[1], (unsigned) arguments[2]);
			break;
		}
		//case to change the next byte to be read or written
		case SYS_SEEK:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 2
			get_arguments(f, &arguments[0], 2);
			
			//changes the byte to read or write
			seek(arguments[0], (unsigned) arguments[1]);
			break;
		}
		//case to get the next byte to be read or written
		case SYS_TELL:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//sets the eax to the position of the next byte to be read or written
			f->eax = tell (arguments[0]);
			break;
		}
		//case to close all a processes files that are open
		case SYS_CLOSE:
		{
			//calls the get_arguments function and passes in the frame, location 0 of the arguments array, and 1
			get_arguments(f, &arguments[0], 1);
			
			//closes the files that are open
			close(arguments[0]);
			break;
		}
	}
}

//function to halt pintos
void halt (void)
{
	//turns of pintos
   shutdown_power_off();
}

//function to exit a program
void exit (int status)
{
	//create a new thread that is set equal to the current thread
    struct thread *current_thread = thread_current();
	
	//checks to see if the current thread parent process is alive. If it is, then status of the child process of the current thread is set equal to the status
    if (thread_alive(current_thread->parent))
    {
        current_thread->cp->status = status;
    }
	
	//print that the current thread is exiting
    printf ("%s: exit(%d)\n", current_thread->name, status);
  
    //exit the thread
    thread_exit();
}

//function to return the pid of a thread
pid_t exec (const char *cmd_line)
{
	//executes the process that was brought in, and returns the pid
	pid_t pid = process_execute(cmd_line);
	
	//creates a new child process and grabs the process with the pid returned pid from above.
	struct child_process* user_file = get_child_process(pid);
	
	//makes sure that the child process is a thing
	ASSERT(user_file);
	
	//traps the child process if the load is not set/does not have a load
	while (user_file->load == NOT_LOADED)
	{
	    barrier();
	}
	
	//checks if the load is not loaded, and throws an error if that is the case
	if (user_file->load == LOAD_FAIL)
	{
	    return ERROR;
	}
	
	//returns the pid of the child process
	return pid;
}

//function to make the thread wait
int wait (pid_t pid)
{
	//calls the process_wait function and returns the value
    return process_wait(pid);
}

//function to create a user file 
bool create (const char *file, unsigned initial_size)
{
	//grabs the file system lock
	lock_acquire(&filesys_lock);
	
	//will try and create the file, and will return the true if it could, or false if not
	bool success = filesys_create(file, initial_size);
	
	//releases the file system lock
	lock_release(&filesys_lock);
	
	//returns the success bool
	return success;
}

//function to remove a user created file
bool remove (const char *file)
{
	//grabs the lock for the file system
	lock_acquire(&filesys_lock);
	
	//will try and remove the file, will return a bool with a success or failure
	bool success = filesys_remove(file);
	
	//releases the lock for the file system
	lock_release(&filesys_lock);
	
	//returns the bool
	return success;
}

//function to open a user file
int open (const char *file)
{
	//grabs the file system lock
	lock_acquire(&filesys_lock);
	
	//opens the file and puts it into a new file struct
	struct file *user_file = filesys_open(file);
	
	//if the file is NULL, then release the file system lock and throw an error
	if (!user_file)
	{
		lock_release(&filesys_lock);
		return ERROR;
	}
	
	//adds the file to the file list of the thread and returns the file descriptor
	int fd = process_add_file(user_file);
	
	//release the file system lock
	lock_release(&filesys_lock);
	
	//return the file descriptor of the file
	return fd;
}

//function to get a user file size
int filesize (int fd)
{
	//grabs the file system lock
	lock_acquire(&filesys_lock);
	
	//tries to get the user file and puts it into a new file struct
	struct file *user_file = process_get_file(fd);
	
	//if the file is NULL, release the system lock and throw an error
	if (!user_file)
	{
		lock_release(&filesys_lock);
		return ERROR;
	}
	
	//get the size of the file and puts it into an int
	int size = file_length(user_file);
	
	//release the file system lock
	lock_release(&filesys_lock);
	
	//return the size of the file
	return size;
}

//function to read the user file
int read (int fd, void *buffer, unsigned size)
{
	//checks the file descriptor to see if it is equal to 0?
	if (fd == STDIN_FILENO)
	{
		//creates a temp buffer with the size of the one brought in
		uint8_t* temp_buffer = (uint8_t *) buffer;
		
		//loops through the and adds each character into the temp buffer
		for (unsigned count = 0; count < size; count++)
		{
			temp_buffer[count] = input_getc();
		}
		
		//returns the size
		return size;
	}
	//grabs the system file lock
	lock_acquire(&filesys_lock);
	
	//gets the file from the process
	struct file *user_file = process_get_file(fd);
	
	//if the file is equal to NULL, the lock is release and an error is thrown
	if (!user_file)
	{
		lock_release(&filesys_lock);
		return ERROR;
	}
	
	//read the file and return the number of bytes
	int bytes = file_read(user_file, buffer, size);
	
	//release the lock
	lock_release(&filesys_lock);
	
	//return the number of locks
	return bytes;
}

//function for the user to write to a file
int write (int fd, const void *buffer, unsigned size)
{
	//checks the file descriptor to see if it is equal to 0?
	if (fd == STDOUT_FILENO)
	{
		//does something then returns the size
		putbuf(buffer, size);
		return size;
	}
	
	//grabs the system file lock 
	lock_acquire(&filesys_lock);
	
	//gets the file and shoves it into a new file struct
	struct file *user_file = process_get_file(fd);
	
	//checks if the file is NULL, if it is then release the lock and throw an error
	if (!user_file)
	{
		lock_release(&filesys_lock);
		return ERROR;
	}
	
	//write to the file and return the number of bytes
	int bytes = file_write(user_file, buffer, size);
	
	//release the lock
	lock_release(&filesys_lock);
	
	//return the bytes
	return bytes;
}

//function to change the next byte to read or write
void seek (int fd, unsigned position)
{
	//grabs the system file lock
	lock_acquire(&filesys_lock);
	
	//gets the file and shoves it into a new file struct
	struct file *user_file = process_get_file(fd);
	
	//checks if the file is NULL, if it is then release the lock and throw an error
	if (!user_file)
	{
		lock_release(&filesys_lock);
		return;
	}
	
	//change the byte
	file_seek(user_file, position);
	
	//release the lock
	lock_release(&filesys_lock);
}

//function to get if the next byte is read or write
unsigned tell (int fd)
{
	//get the lock
	lock_acquire(&filesys_lock);

	//gets the file and shoves it into a new file struct
	struct file *user_file = process_get_file(fd);
	
	//checks if the file is NULL, if it is then release the lock and throw an error
	if (!user_file)
	{
		lock_release(&filesys_lock);
		return ERROR;
	}
	
	//get the next byte
	off_t offset = file_tell(user_file);
	
	//release the lock
	lock_release(&filesys_lock);
	
	//return the offest
	return offset;
}

//function to close the user file
void close (int fd)
{
	//grabs the lock
	lock_acquire(&filesys_lock);

	//closes the file
	process_close_file(fd);
	
	//releases the lock
	lock_release(&filesys_lock);
}

//function to check if the pointer is in a valid position
void check_valid_ptr (const void *vaddr)
{
	//if the user pointer is below 0 or less then PHYS_BASE + 0x1234, throw and error and close the process
	if (!is_user_vaddr(vaddr) || vaddr < ((void *)0x08048000))
	{
		exit(ERROR);
	}
}

//function to get the pointer to the stack
int user_to_kernel_ptr(const void *vaddr)
{
	//checks to see if the pointer is valid
	//check_valid_ptr(vaddr);
	
	//gets the pointer that the user is wanting
	void *ptr = pagedir_get_page(thread_current()->pagedir, vaddr);
	
	//if the pointer is NULL, then an error is thrown and the process is stopped
	if (!ptr)
	{
		exit(ERROR);
	}
	
	//returns the pointer as an int
	return (int) ptr;
}

//function to add a user's file
int process_add_file (struct file *f)
{
	//creating a new process file 
	struct process_file *user_file = malloc(sizeof(struct process_file));
	
	//puts the file in the process file 
	user_file->file = f;
	
	//puts the file descriptor in the process file
	user_file->fd = thread_current()->fd;
	
	//increments the file descriptor in the current thread
	thread_current()->fd++;
	
	//puts the process file into the current thread file list
	list_push_back(&thread_current()->file_list, &user_file->elem);
	
	//returns the file descriptor of the process file
	return user_file->fd;
}

//function to get a file
struct file* process_get_file (int fd)
{
	//gets the current thread
	struct thread *thread = thread_current();
	
	//creates a new list of elements

	//loops through the file list in the current thread
	for (struct list_elem *e = list_begin (&thread->file_list); e != list_end (&thread->file_list);e = list_next (e))
	{
		//creates a new process file and sets it equal to the current process file in the list
		struct process_file *pf = list_entry (e, struct process_file, elem);
		
		//checks to see if that process file is equal to the file descriptor that was brought in. If it is, return the file
		if (pf->fd == fd)
		{
			return pf->file;
		}
	}
	
	//return NULL since the file is not found
	return NULL;
}

//function to close the user file
void process_close_file (int fd)
{
	//gets the current thread
    struct thread *thread = thread_current();
    
	struct list_elem *next;
	struct list_elem *e = list_begin(&thread->file_list);
	
	
	//loops through the thread file list
    while (e != list_end (&thread->file_list))
    {
		//sets the next entry in the list to next
		next = list_next(e);
		
		//grabs the file in that list entry
		struct process_file *user_file = list_entry (e, struct process_file, elem);
		
		//checks if the file descriptor of the file is equal to the file descriptor that was brought in, or that the file descriptor is set to close all.
		if (fd == user_file->fd || fd == CLOSE_ALL)
		{
			//the file is closed
			file_close(user_file->file);
			
			//the file is removed from the list
			list_remove(&user_file->elem);
			
			//the memory of the process file is freed
			free(user_file);
			
			//checks if the file descriptor is not equal to close all. if that is true, then it kicks out
			if (fd != CLOSE_ALL)
			{
				return;
			}
		}
		e = next;
    } 
}

//function to add a child process to a thread
struct child_process* initilize_child_process (int pid)
{
	//creating a new child processes
	struct child_process* cp = malloc(sizeof(struct child_process));
	
	//setting the pid equal to the pid that was brought in
	cp->pid = pid;
	
	//setting the load to not loaded
	cp->load = NOT_LOADED;
	
	//setting the wait to false
	cp->wait = false;
	
	//setting the exit to false
	cp->exit = false;
	
	//initializing the lock on the child process
	lock_init(&cp->wait_lock);
	
	//putting the child process into the current thread child list
	list_push_back(&thread_current()->child_list, &cp->elem);
	
	//returns the child process
	return cp;
}

//function to get the child process
struct child_process* get_child_process (int pid)
{
	//gets the current thread
    struct thread *thread = thread_current();
    
	//creates a new list of elements
	//struct list_elem *e;

	//loops through the child list of the current thread
	for (struct list_elem *e = list_begin (&thread->child_list); e != list_end (&thread->child_list);e = list_next (e))
    {
		//creates a new child process that is set to the child process in the list
        struct child_process *cp = list_entry (e, struct child_process, elem);
		
		//checks if the pid of the child process is equal to the pid that was brought in. if it is, return the child process 
        if (pid == cp->pid)
	    {
	        return cp;
	    }
    }
	//returns NULL if the child process is not found
    return NULL;
}

//function to remove the child process
void remove_child_process (struct child_process *cp)
{
	//removes the child process from the list of elements (this also means any threads it is associated with
    list_remove(&cp->elem);
    
	//frees the child process
    free(cp);
}

//function to remove multiple child processes
void remove_child_processes (void)
{
	//gets the current thread
	struct thread *thread = thread_current();
	
	//creates a new list of elements
	struct list_elem *next_e;
	struct list_elem *e = list_begin(&thread->child_list);
	
	//loops through the list of child processes in the current thread
	while (e != list_end (&thread->child_list))
    {
		//sets the next list item to next
        next_e = list_next(e);
		
		//creates a new child process that is set to the current list entry
        struct child_process *cp = list_entry (e, struct child_process, elem);
		
		//removes the child process from the list of elements
        list_remove(&cp->elem);
		
		//frees the child process
        free(cp);
		
		//sets e to the next list entry
        e = next_e;
    }	
}

//function to get arguments
void get_arguments(struct intr_frame *f, int *arguments, int n)
{
	//creating a pointer
	int *ptr;
	
	//loops though the n times 
	for (int count = 0; count < n; count++)
    {
		//sets the pointer to the esp + counter + 1
		ptr = (int *) f->esp + count + 1;
		
		//checks to see if this a valid pointer
		check_valid_ptr((const void *) ptr);
		
		//sets the argument to the pointer
		arguments[count] = *ptr;
    }
}

//function to check if the buffer is valid
void check_valid_buffer (void* buffer, unsigned size)
{
	//creates a new buffer
	char* temp_buffer = (char *) buffer;
	
	//loops though the size that was brought in 
	for (unsigned count = 0; count < size; count++)
    {
		//checks to see if the buffer is valid
		check_valid_ptr((const void*) temp_buffer);
		
		//increments the buffer
		temp_buffer++;
    }
}
