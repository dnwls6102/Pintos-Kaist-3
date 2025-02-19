#ifndef USERPROG_PROCESS_H
#define USERPROG_PROCESS_H

#include "threads/thread.h"
#include "filesys/file.h"

tid_t process_create_initd (const char *file_name);
tid_t process_fork (const char *name, struct intr_frame *if_);
int process_exec (void *f_name);
int process_wait (tid_t);
void process_exit (void);
void process_activate (struct thread *next);

int process_add_file(struct file *t);
struct file* process_get_file(int fd);
void process_close_file(int fd);

#define STDIN 0x1
#define STDOUT 0x2
#define STDERR 0x3

#endif /* userprog/process.h */
