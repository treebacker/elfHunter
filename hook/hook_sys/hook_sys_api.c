#include "hook_sys.h"

// global mark for syscall state 
// enter | exita
int incalling = 0;

//global sys_hook_table
Hunter_sys_hook Sys_hook[0x300];
int main(int argc, char* argv[], char* envp[])
{
	checkArg(argc, argv, envp);
	pid_t childPid;
	char** childArgv;			//tracee's argv

	childArgv = (char**)&argv[1];
	childPid = fork();
	if(childPid == 0){
		ptrace(PTRACE_TRACEME, 0, NULL, NULL);
		execve(argv[1], childArgv, envp);
	}
	else{
		pre_sys_hook();
		tracerwork(childPid);
	}
}