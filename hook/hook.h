#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*Hunter_hook)(pid_t tracee);

void tracerwork(pid_t tracee);
void checkArg(int argc, char* argv[], char* envp[]);
int Hunter_write(pid_t tracee);
int Hunter_read(pid_t tracee);

//define a function for syscall
void Hunter(long syscall, Hunter_hook bf_hook);