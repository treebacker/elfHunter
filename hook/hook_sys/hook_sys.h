#include <sys/wait.h>
#include <unistd.h>
#include <sys/ptrace.h>
#include <sys/wait.h>
#include <sys/reg.h>
#include <sys/user.h>
#include <sys/syscall.h>
#include <stdio.h>
#include <stdlib.h>

typedef int (*Hunter_sys_hook)(pid_t tracee);

//check args 
void checkArg(int argc, char* argv[], char* envp[]);

//one trace loop work funtion for trace the tracee target
void tracerwork(pid_t tracee);

//demo hook_sys function
int Hunter_sys_write(pid_t tracee);
int Hunter_sys_read(pid_t tracee);

//define two functions for syscall callback function reg | unreg
void Hunter_sys_reg(long syscall, Hunter_sys_hook callback);
void Hunter_sys_unreg(long syscall);

//define some pre_hook
void pre_sys_hook();


//define check
void check_stack(tracee);


